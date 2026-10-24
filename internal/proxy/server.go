package proxy

import (
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/spawnzao/dpipot-ng/internal/flow"
	"github.com/spawnzao/dpipot-ng/internal/httpclassifier"
	"github.com/spawnzao/dpipot-ng/internal/kafka"
	"github.com/spawnzao/dpipot-ng/internal/mitm"
	"github.com/spawnzao/dpipot-ng/internal/router"
	"go.uber.org/zap"
)

// NDPITimingStats carries one heartbeat interval's Phase 2 timing histograms.
// All nanosecond values are 0 when no samples were collected in the interval.
type NDPITimingStats struct {
	QueueWaitP50   int64
	QueueWaitP95   int64
	QueueWaitP99   int64
	QueueWaitP999  int64
	QueueWaitCount int64
	ProcessP50     int64
	ProcessP95     int64
	ProcessP99     int64
	ProcessP999    int64
	ProcessCount   int64
	QueueDepthMax     int64
	QueueDepthAvg     int64
	ShardDrops        int64 // packets dropped because a shard channel was full (0 when NDPI_WORKERS=1)
	PacketsDispatched int64 // packets that entered a shard channel or were processed synchronously
	ShardQueueMax     int64 // max shard channel occupancy at snapshot time
	ShardQueueAvg     int64 // avg shard channel occupancy at snapshot time
}

// ClassifierTelemetry abstrai as métricas do AF_PACKET e do nDPI handler para
// o heartbeat do proxy, sem criar dependência direta dos pacotes capture/ndpi.
// Implementada em main.go como glue entre os dois componentes.
type ClassifierTelemetry interface {
	AFPacketKernelDropsAndReset() int64
	AFPacketChanDropsAndReset() int64
	NDPIPacketsProcessedAndReset() int64
	NDPIFlowsActive() int
	NDPICleanupEvictedAndReset() int64
	NDPITimingStatsAndReset() NDPITimingStats
	NDPIShardQueueDepths() []int
}

// Server aceita conexões TCP e cria um Handler por conexão.
// Cada Handler roda em goroutine separada — o server nunca bloqueia.
type Server struct {
	listenAddr          string
	router              *router.Router
	producer            *kafka.Producer
	maxPayloadBytes     int64
	sshInputBufSize     int
	sshOutputBufSize    int
	sshBannerPool       []string
	sshBannerMap        map[uint16]string
	rdpIdentityPool     []mitm.RDPIdentity
	log                 *zap.Logger
	flowTable           *flow.Table
	certMgr             *mitm.CertManager
	serverFirstPorts    map[uint16]string
	serverFirstPortsTLS map[uint16]string
	httpAuthPorts       map[uint16]bool
	httpAuthPortsTLS    map[uint16]bool
	httpClassifier      *httpclassifier.Classifier
	proxyTimeout        time.Duration
	listener            net.Listener
	sem                 chan struct{}
	perIPConns          sync.Map // map[string]*atomic.Int64 — contador por IP de origem
	maxPerIPConns       int
	nodeName            string // spec.nodeName injetado via Downward API (NODE_NAME)
	podName             string // metadata.name injetado via Downward API (POD_NAME)
	version             string // binary version set via SetVersion (injected at build time)

	// contadores de qualidade de link — acumulados por connection e zerados a cada heartbeat
	retransmitsClient   atomic.Int64 // soma de retransmissões atacante→proxy
	retransmitsHoneypot atomic.Int64 // soma de retransmissões proxy→honeypot
	flowsClient         atomic.Int64 // conexões de atacante concluídas
	flowsHoneypot       atomic.Int64 // conexões com honeypot estabelecidas

	// diagnóstico da flow table — acumulados por connection e zerados a cada heartbeat
	flowTableNotFound atomic.Int64 // lookup sem entrada (nDPI ainda não classificou)
	flowTableUnknown  atomic.Int64 // entrada existe mas protocolo é Unknown

	classifier          ClassifierTelemetry // opcional — nil se não configurado
	fastpathEnabled     bool               // FASTPATH_ENABLED: structural payload detection for Unknown flows
	classifyWaitTimeout time.Duration      // CLASSIFY_WAIT_TIMEOUT: max wait for nDPI (0 = disabled)
}

// SetClassifier registra a implementação de ClassifierTelemetry para que o heartbeat
// inclua métricas de AF_PACKET e nDPI sem importar os pacotes capture/ndpi diretamente.
func (s *Server) SetClassifier(c ClassifierTelemetry) {
	s.classifier = c
}

// SetFastpathEnabled controls structural payload detection for Unknown flows (FASTPATH_ENABLED).
func (s *Server) SetVersion(v string)        { s.version = v }
func (s *Server) SetFastpathEnabled(v bool) { s.fastpathEnabled = v }

// SetClassifyWaitTimeout sets the max duration to wait for nDPI to classify Unknown flows (CLASSIFY_WAIT_TIMEOUT).
func (s *Server) SetClassifyWaitTimeout(d time.Duration) { s.classifyWaitTimeout = d }

func NewServer(
	listenAddr string,
	r *router.Router,
	producer *kafka.Producer,
	maxPayloadBytes int64,
	sshInputBufSize int,
	sshOutputBufSize int,
	sshBannerPool []string,
	sshBannerMap map[uint16]string,
	maxConnections int,
	maxPerIPConns int,
	log *zap.Logger,
	flowTable *flow.Table,
	certMgr *mitm.CertManager,
	serverFirstPorts map[uint16]string,
	serverFirstPortsTLS map[uint16]string,
	httpAuthPorts map[uint16]bool,
	httpAuthPortsTLS map[uint16]bool,
	httpClassifier *httpclassifier.Classifier,
	proxyTimeout time.Duration,
	rdpIdentityPool []mitm.RDPIdentity,
) *Server {
	if maxConnections <= 0 {
		maxConnections = 10000
	}
	if maxPerIPConns <= 0 {
		maxPerIPConns = 50
	}
	return &Server{
		listenAddr:          listenAddr,
		router:              r,
		producer:            producer,
		maxPayloadBytes:     maxPayloadBytes,
		sshInputBufSize:     sshInputBufSize,
		sshOutputBufSize:    sshOutputBufSize,
		sshBannerPool:       sshBannerPool,
		sshBannerMap:        sshBannerMap,
		rdpIdentityPool:     rdpIdentityPool,
		log:                 log,
		flowTable:           flowTable,
		certMgr:             certMgr,
		serverFirstPorts:    serverFirstPorts,
		serverFirstPortsTLS: serverFirstPortsTLS,
		httpAuthPorts:       httpAuthPorts,
		httpAuthPortsTLS:    httpAuthPortsTLS,
		httpClassifier:      httpClassifier,
		proxyTimeout:        proxyTimeout,
		sem:                 make(chan struct{}, maxConnections),
		maxPerIPConns:       maxPerIPConns,
		nodeName:            os.Getenv("NODE_NAME"),
		podName:             os.Getenv("POD_NAME"),
	}
}

// listenTransparent cria um listener TCP com IP_TRANSPARENT habilitado.
// Necessário para TPROXY - permite bind em IPs não-locais.
func listenTransparent(addr string) (net.Listener, error) {
	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("resolve addr: %w", err)
	}

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		return nil, fmt.Errorf("socket: %w", err)
	}

	if err := syscall.SetsockoptInt(fd, syscall.SOL_IP, syscall.IP_TRANSPARENT, 1); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("setsockopt IP_TRANSPARENT: %w", err)
	}

	sa := &syscall.SockaddrInet4{Port: tcpAddr.Port, Addr: [4]byte{0, 0, 0, 0}}

	if err := syscall.Bind(fd, sa); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("bind 0.0.0.0:%d: %w", tcpAddr.Port, err)
	}

	if err := syscall.Listen(fd, 128); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("listen: %w", err)
	}

	f := os.NewFile(uintptr(fd), "tproxy-listener")
	ln, err := net.FileListener(f)
	f.Close()
	return ln, err
}

// Stop fecha o listener, fazendo ListenAndServe retornar.
func (s *Server) Stop() {
	if s.listener != nil {
		s.listener.Close()
	}
}

// ListenAndServe abre o listener TCP e aceita conexões indefinidamente.
func (s *Server) ListenAndServe() error {
	ln, err := listenTransparent(s.listenAddr)
	if err != nil {
		return fmt.Errorf("listen transparent %s: %w", s.listenAddr, err)
	}
	s.listener = ln
	defer ln.Close()

	s.log.Info("proxy escutando", zap.String("addr", s.listenAddr))

	hbQuit := make(chan struct{})
	go s.startHeartbeat(time.Now(), hbQuit)
	defer close(hbQuit)

	for {
		conn, err := ln.Accept()
		if err != nil {
			s.log.Warn("accept error", zap.Error(err))
			if strings.Contains(err.Error(), "use of closed network connection") {
				return nil
			}
			continue
		}

		srcTCPAddr := conn.RemoteAddr().(*net.TCPAddr)
		srcIP := srcTCPAddr.IP.String()

		val, _ := s.perIPConns.LoadOrStore(srcIP, new(atomic.Int64))
		ipCounter := val.(*atomic.Int64)
		if ipCounter.Add(1) > int64(s.maxPerIPConns) {
			if ipCounter.Add(-1) <= 0 {
				s.perIPConns.Delete(srcIP)
			}
			s.log.Warn("conexão rejeitada: limite por IP atingido",
				zap.String("src_ip", srcIP),
				zap.Int("max_per_ip", s.maxPerIPConns),
			)
			s.producer.Publish(&kafka.Event{
				Timestamp:   time.Now(),
				EventType:   "rejected",
				SrcIP:       srcIP,
				SrcPort:     srcTCPAddr.Port,
				AttackType:  "conn_limit_per_ip",
				PerIPActive: int(ipCounter.Load()),
				SlotsUsed:   kafka.IntPtr(len(s.sem)),
				SlotsMax:    cap(s.sem),
				Instance:    "proxy",
				NodeName:    s.nodeName,
				PodName:     s.podName,
			})
			conn.Close()
			continue
		}

		select {
		case s.sem <- struct{}{}:
			slotsUsed := len(s.sem)
			slotsMax := cap(s.sem)
			perIPActive := int(ipCounter.Load())
			s.log.Info("🎯 Conexão aceita",
				zap.String("local_addr", conn.LocalAddr().String()),
				zap.String("remote_addr", conn.RemoteAddr().String()),
				zap.Int("slots_used", slotsUsed),
				zap.Int("slots_max", slotsMax),
			)
			go func() {
				defer func() {
					<-s.sem
					if ipCounter.Add(-1) <= 0 {
						s.perIPConns.Delete(srcIP)
					}
				}()
				s.handle(conn, slotsUsed, slotsMax, perIPActive)
			}()
		default:
			if ipCounter.Add(-1) <= 0 {
				s.perIPConns.Delete(srcIP)
			}
			s.log.Warn("conexão rejeitada: limite máximo de conexões simultâneas atingido",
				zap.String("remote_addr", conn.RemoteAddr().String()),
				zap.Int("max_connections", cap(s.sem)),
			)
			s.producer.Publish(&kafka.Event{
				Timestamp:  time.Now(),
				EventType:  "rejected",
				SrcIP:      srcIP,
				SrcPort:    srcTCPAddr.Port,
				AttackType: "conn_limit_global",
				SlotsUsed:  kafka.IntPtr(cap(s.sem)),
				SlotsMax:   cap(s.sem),
				Instance:   "proxy",
				NodeName:   s.nodeName,
				PodName:    s.podName,
			})
			conn.Close()
		}
	}
}

// startHeartbeat publica um evento de telemetria a cada 60s enquanto o proxy está ativo.
func (s *Server) startHeartbeat(startTime time.Time, quit <-chan struct{}) {
	if s.producer == nil {
		return
	}
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	// Baseline GC counters so the first heartbeat reports the interval delta, not cumulative total.
	var baseMS runtime.MemStats
	runtime.ReadMemStats(&baseMS)
	lastGCNum := baseMS.NumGC
	lastGCPauseNs := baseMS.PauseTotalNs

	for {
		select {
		case <-quit:
			return
		case <-ticker.C:
			drops := s.producer.DroppedAndReset()
			deliveryErrors := s.producer.DeliveryErrorsAndReset()
			deliveryDropped := s.producer.DeliveryDroppedAndReset()
			marshalErrors := s.producer.MarshalErrorsAndReset()
			produceErrors := s.producer.ProduceErrorsAndReset()
			kafkaStatus := "ok"
			if !s.producer.IsHealthy() {
				kafkaStatus = "error"
			}

			flowTableSize := 0
			if s.flowTable != nil {
				flowTableSize = s.flowTable.Size()
			}

			var ms runtime.MemStats
			runtime.ReadMemStats(&ms)
			gcCycles := int64(ms.NumGC - lastGCNum)
			gcPauseNs := int64(ms.PauseTotalNs - lastGCPauseNs)
			lastGCNum = ms.NumGC
			lastGCPauseNs = ms.PauseTotalNs

			var afKernelDrops, afChanDrops, ndpiPackets, ndpiEvicted int64
			var ndpiFlowsActive int
			var timing NDPITimingStats
			if s.classifier != nil {
				afKernelDrops = s.classifier.AFPacketKernelDropsAndReset()
				afChanDrops = s.classifier.AFPacketChanDropsAndReset()
				ndpiPackets = s.classifier.NDPIPacketsProcessedAndReset()
				ndpiFlowsActive = s.classifier.NDPIFlowsActive()
				ndpiEvicted = s.classifier.NDPICleanupEvictedAndReset()
				timing = s.classifier.NDPITimingStatsAndReset()

				depths := s.classifier.NDPIShardQueueDepths()
				var qMax, qSum int64
				for _, d := range depths {
					if int64(d) > qMax {
						qMax = int64(d)
					}
					qSum += int64(d)
				}
				if len(depths) > 0 {
					timing.ShardQueueMax = qMax
					timing.ShardQueueAvg = qSum / int64(len(depths))
				}
			}

			ev := &kafka.Event{
				Timestamp:                   time.Now(),
				EventType:                   "heartbeat",
				AppVersion:                  s.version,
				SlotsUsed:                   kafka.IntPtr(len(s.sem)),
				SlotsMax:                    cap(s.sem),
				KafkaDrops:                  kafka.Int64Ptr(drops),
				KafkaDeliveryErrors:         kafka.Int64Ptr(deliveryErrors),
				KafkaDeliveryDropped:        kafka.Int64Ptr(deliveryDropped),
				KafkaMarshalErrors:          kafka.Int64Ptr(marshalErrors),
				KafkaProduceErrors:          kafka.Int64Ptr(produceErrors),
				KafkaStatus:                 kafkaStatus,
				UptimeSec:                   time.Since(startTime).Seconds(),
				KafkaChanLen:                kafka.IntPtr(s.producer.ChanLen()),
				KafkaQueueLen:               kafka.IntPtr(s.producer.QueueLen()),
				Instance:                    "proxy",
				NodeName:                    s.nodeName,
				PodName:                     s.podName,
				FlowTableSize:               kafka.IntPtr(flowTableSize),
				FlowTableNotFound:           kafka.Int64Ptr(s.flowTableNotFound.Swap(0)),
				FlowTableUnknown:            kafka.Int64Ptr(s.flowTableUnknown.Swap(0)),
				TCPRetransmitsClientTotal:   kafka.Int64Ptr(s.retransmitsClient.Swap(0)),
				TCPRetransmitsHoneypotTotal: kafka.Int64Ptr(s.retransmitsHoneypot.Swap(0)),
				FlowsClientTotal:            kafka.Int64Ptr(s.flowsClient.Swap(0)),
				FlowsHoneypotTotal:          kafka.Int64Ptr(s.flowsHoneypot.Swap(0)),
				AFPacketKernelDrops:         kafka.Int64Ptr(afKernelDrops),
				AFPacketChanDrops:           kafka.Int64Ptr(afChanDrops),
				NDPIPackets:                 kafka.Int64Ptr(ndpiPackets),
				NDPIFlowsActive:             kafka.IntPtr(ndpiFlowsActive),
				NDPICleanupEvicted:          kafka.Int64Ptr(ndpiEvicted),
				NDPIShardDrops:              kafka.Int64Ptr(timing.ShardDrops),
				NDPIPacketsDispatched:       kafka.Int64Ptr(timing.PacketsDispatched),
				NDPIShardQueueMax:           kafka.Int64Ptr(timing.ShardQueueMax),
				NDPIShardQueueAvg:           kafka.Int64Ptr(timing.ShardQueueAvg),
				GoGCCycles:                  kafka.Int64Ptr(gcCycles),
				GoGCPauseNs:                 kafka.Int64Ptr(gcPauseNs),
				GoHeapAllocBytes:            kafka.Int64Ptr(int64(ms.HeapAlloc)),
				GoGoroutines:                kafka.Int64Ptr(int64(runtime.NumGoroutine())),
			}
			if timing.QueueWaitCount > 0 {
				ev.NDPIQueueWaitP50 = kafka.Int64Ptr(timing.QueueWaitP50)
				ev.NDPIQueueWaitP95 = kafka.Int64Ptr(timing.QueueWaitP95)
				ev.NDPIQueueWaitP99 = kafka.Int64Ptr(timing.QueueWaitP99)
				ev.NDPIQueueWaitP999 = kafka.Int64Ptr(timing.QueueWaitP999)
				ev.NDPIQueueWaitCount = kafka.Int64Ptr(timing.QueueWaitCount)
			}
			if timing.ProcessCount > 0 {
				ev.NDPIProcessP50 = kafka.Int64Ptr(timing.ProcessP50)
				ev.NDPIProcessP95 = kafka.Int64Ptr(timing.ProcessP95)
				ev.NDPIProcessP99 = kafka.Int64Ptr(timing.ProcessP99)
				ev.NDPIProcessP999 = kafka.Int64Ptr(timing.ProcessP999)
				ev.NDPIProcessCount = kafka.Int64Ptr(timing.ProcessCount)
			}
			if timing.QueueDepthMax > 0 {
				ev.NDPIQueueDepthMax = kafka.Int64Ptr(timing.QueueDepthMax)
				ev.NDPIQueueDepthAvg = kafka.Int64Ptr(timing.QueueDepthAvg)
			}
			s.producer.Publish(ev)
		}
	}
}

func (s *Server) handle(conn net.Conn, slotsUsed, slotsMax, perIPActive int) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("handler recovered from panic", zap.Any("panic", r))
		}
		conn.Close()
	}()

	log := s.log

	log.Debug("🔌 Handler started!",
		zap.String("local_addr", conn.LocalAddr().String()),
		zap.String("remote_addr", conn.RemoteAddr().String()),
	)

	h := NewHandler(
		conn,
		s.router,
		s.producer,
		s.maxPayloadBytes,
		s.sshInputBufSize,
		s.sshOutputBufSize,
		log,
		s.flowTable,
		s.certMgr,
		s.serverFirstPorts,
		s.serverFirstPortsTLS,
		s.httpAuthPorts,
		s.httpAuthPortsTLS,
		s.httpClassifier,
		s.proxyTimeout,
		s.rdpIdentityPool,
	)
	h.slotsUsed = slotsUsed
	h.slotsMax = slotsMax
	h.perIPActive = perIPActive
	h.nodeName = s.nodeName
	h.podName = s.podName
	h.sshBannerPool = s.sshBannerPool
	h.sshBannerMap = s.sshBannerMap
	h.retransmitsClient = &s.retransmitsClient
	h.retransmitsHoneypot = &s.retransmitsHoneypot
	h.flowsClient = &s.flowsClient
	h.flowsHoneypot = &s.flowsHoneypot
	h.flowTableNotFound = &s.flowTableNotFound
	h.flowTableUnknown = &s.flowTableUnknown
	h.fastpathEnabled = s.fastpathEnabled
	h.classifyWaitTimeout = s.classifyWaitTimeout
	h.Handle()

	log.Info("handler finished")
}
