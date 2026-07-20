package proxy

import (
	"fmt"
	"net"
	"os"
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

// Server aceita conexões TCP e cria um Handler por conexão.
// Cada Handler roda em goroutine separada — o server nunca bloqueia.
type Server struct {
	listenAddr          string
	router              *router.Router
	producer            *kafka.Producer
	maxPayloadBytes     int64
	sshInputBufSize     int
	sshOutputBufSize    int
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

	// contadores de qualidade de link — acumulados por connection e zerados a cada heartbeat
	retransmitsClient   atomic.Int64 // soma de retransmissões atacante→proxy
	retransmitsHoneypot atomic.Int64 // soma de retransmissões proxy→honeypot
	flowsClient         atomic.Int64 // conexões de atacante concluídas
	flowsHoneypot       atomic.Int64 // conexões com honeypot estabelecidas
}

func NewServer(
	listenAddr string,
	r *router.Router,
	producer *kafka.Producer,
	maxPayloadBytes int64,
	sshInputBufSize int,
	sshOutputBufSize int,
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
	for {
		select {
		case <-quit:
			return
		case <-ticker.C:
			drops := s.producer.DroppedAndReset()
			kafkaStatus := "ok"
			if !s.producer.IsHealthy() {
				kafkaStatus = "error"
			}

			flowTableSize := 0
			if s.flowTable != nil {
				flowTableSize = s.flowTable.Size()
			}

			s.producer.Publish(&kafka.Event{
				Timestamp:                   time.Now(),
				EventType:                   "heartbeat",
				SlotsUsed:                   kafka.IntPtr(len(s.sem)),
				SlotsMax:                    cap(s.sem),
				KafkaDrops:                  kafka.Int64Ptr(drops),
				KafkaStatus:                 kafkaStatus,
				UptimeSec:                   time.Since(startTime).Seconds(),
				KafkaChanLen:                kafka.IntPtr(s.producer.ChanLen()),
				KafkaQueueLen:               kafka.IntPtr(s.producer.QueueLen()),
				Instance:                    "proxy",
				NodeName:                    s.nodeName,
				PodName:                     s.podName,
				FlowTableSize:               kafka.IntPtr(flowTableSize),
				TCPRetransmitsClientTotal:   kafka.Int64Ptr(s.retransmitsClient.Swap(0)),
				TCPRetransmitsHoneypotTotal: kafka.Int64Ptr(s.retransmitsHoneypot.Swap(0)),
				FlowsClientTotal:            kafka.Int64Ptr(s.flowsClient.Swap(0)),
				FlowsHoneypotTotal:          kafka.Int64Ptr(s.flowsHoneypot.Swap(0)),
			})
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
	)
	h.slotsUsed = slotsUsed
	h.slotsMax = slotsMax
	h.perIPActive = perIPActive
	h.nodeName = s.nodeName
	h.podName = s.podName
	h.retransmitsClient = &s.retransmitsClient
	h.retransmitsHoneypot = &s.retransmitsHoneypot
	h.flowsClient = &s.flowsClient
	h.flowsHoneypot = &s.flowsHoneypot
	h.Handle()

	log.Info("handler finished")
}
