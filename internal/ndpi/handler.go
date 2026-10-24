package ndpi

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/spawnzao/dpipot-ng/internal/flow"
	"github.com/spawnzao/dpipot-ng/internal/kafka"
	"github.com/spawnzao/dpipot-ng/internal/metrics"
	"github.com/spawnzao/dpipot-ng/internal/ndpi/gondpi"
)

const (
	EthernetHeaderSize = 14
)

// ndpiShard holds per-worker nDPI state. Each shard owns its detection module
// and flow map so the hot path needs no inter-goroutine locking on C resources.
type ndpiShard struct {
	ndpiDM      *gondpi.NdpiDetectionModule
	ndpiFlows   sync.Map           // tupleID → *gondpi.NdpiFlow; accessed only by this shard
	pendingFree []*gondpi.NdpiFlow // queued for deferred Close on the next cleanup cycle
	ch          chan []byte         // dispatch channel; nil when numShards == 1 (synchronous)
}

type Handler struct {
	shards    []*ndpiShard
	numShards int

	flowTable *flow.Table
	flowUUIDs sync.Map // tupleID → UUID; shared, LoadOrStore is thread-safe
	logger    *zap.Logger
	wg        sync.WaitGroup
	ctx       context.Context
	cancel    context.CancelFunc

	serverFirstPorts  []uint16
	portProtocolMap   map[uint16]string
	producer          *kafka.Producer
	ndpiEventsEnabled bool
	nodeName          string
	podName           string
	localIP           net.IP

	// telemetry counters — read by heartbeat via ClassifierTelemetry
	packetsProcessed  atomic.Int64
	packetsDispatched atomic.Int64 // packets that entered a shard channel (N>1) or were processed synchronously (N=1)
	activeFlows       atomic.Int64
	cleanupEvicted    atomic.Int64
	shardDrops        atomic.Int64 // packets dropped because a shard's dispatch channel was full

	// Phase 2 timing histograms
	queueWait  metrics.Histogram
	processing metrics.Histogram
	queueDepth metrics.GaugeSampler
}

type HandlerConfig struct {
	FlowTable         *flow.Table
	Logger            *zap.Logger
	ServerFirstPorts  []uint16
	PortProtocolMap   map[uint16]string
	Producer          *kafka.Producer
	NdpiEventsEnabled bool
	NodeName          string
	PodName           string
	LocalIP           net.IP
	NumWorkers        int // NDPI_WORKERS; 0 or 1 = synchronous single-goroutine (default)
}

func NewHandler(cfg HandlerConfig) (*Handler, error) {
	n := cfg.NumWorkers
	if n <= 0 {
		n = 1
	}

	shards := make([]*ndpiShard, n)
	for i := range shards {
		bitmask := gondpi.NewNdpiProtocolBitmask()
		bitmask = gondpi.NdpiProtocolBitmaskSetAll(bitmask)
		dm, err := gondpi.NdpiDetectionModuleInitialize(0, bitmask)
		if err != nil {
			return nil, fmt.Errorf("nDPI shard %d init failed: %w", i, err)
		}
		s := &ndpiShard{ndpiDM: dm}
		if n > 1 {
			s.ch = make(chan []byte, 16384)
		}
		shards[i] = s
	}

	ctx, cancel := context.WithCancel(context.Background())

	h := &Handler{
		shards:            shards,
		numShards:         n,
		flowTable:         cfg.FlowTable,
		logger:            cfg.Logger,
		ctx:               ctx,
		cancel:            cancel,
		serverFirstPorts:  cfg.ServerFirstPorts,
		portProtocolMap:   cfg.PortProtocolMap,
		producer:          cfg.Producer,
		ndpiEventsEnabled: cfg.NdpiEventsEnabled,
		nodeName:          cfg.NodeName,
		podName:           cfg.PodName,
		localIP:           cfg.LocalIP,
	}

	// Worker goroutines — only needed in sharded (N>1) mode.
	if n > 1 {
		for i, s := range shards {
			h.wg.Add(1)
			go h.runShard(i, s)
		}
	}

	// One cleanup goroutine per shard.
	for _, s := range shards {
		h.startShardCleanup(s, 30*time.Second)
	}

	if h.logger != nil {
		h.logger.Info("nDPI handler initialized", zap.Int("shards", n))
	}

	return h, nil
}

// ProcessPacket routes an Ethernet frame to the appropriate nDPI shard.
// For N=1 (synchronous), processing runs in the calling goroutine and the
// T3−T2 interval is recorded internally. For N>1, frames fan out to worker
// goroutines which record their own processing time.
func (h *Handler) ProcessPacket(data []byte) {
	h.packetsProcessed.Add(1)
	if len(data) < EthernetHeaderSize+20 {
		return
	}

	if h.numShards == 1 {
		t := time.Now()
		h.dispatchToShard(h.shards[0], data)
		h.processing.Observe(time.Since(t).Nanoseconds())
		h.packetsDispatched.Add(1)
		return
	}

	// Sharded path: all packets of a flow must reach the same shard.
	// shardKey hashes directly on the binary 5-tuple — zero allocations.
	idx := int(shardKey(data) % uint32(h.numShards))
	select {
	case h.shards[idx].ch <- data:
		h.packetsDispatched.Add(1)
	default:
		// Channel full; drop to avoid blocking the AF_PACKET reader.
		h.shardDrops.Add(1)
	}
}

func (h *Handler) runShard(idx int, s *ndpiShard) {
	defer h.wg.Done()
	for {
		select {
		case data, ok := <-s.ch:
			if !ok {
				return
			}
			t := time.Now()
			h.dispatchToShard(s, data)
			h.processing.Observe(time.Since(t).Nanoseconds())
		case <-h.ctx.Done():
			return
		}
	}
}

func (h *Handler) dispatchToShard(s *ndpiShard, data []byte) {
	ethertype := uint16(data[12])<<8 | uint16(data[13])
	switch ethertype {
	case 0x0800:
		h.processIPv4Shard(s, data)
	case 0x86DD:
		h.processIPv6Shard(s, data)
	}
}

// shardKey computes a FNV-1a 32-bit hash directly over the binary 5-tuple bytes
// of an Ethernet frame without allocating any strings, making it safe to call on
// every packet at 100k+ pps. Returns 0 for IPv6 or unrecognized frames (caller
// routes them to shard 0, which quickly discards them in classifyAndUpdateFlowShard).
func shardKey(data []byte) uint32 {
	if len(data) < EthernetHeaderSize+20 {
		return 0
	}
	if uint16(data[12])<<8|uint16(data[13]) != 0x0800 {
		return 0 // IPv6 and non-IP frames go to shard 0
	}
	ip := data[EthernetHeaderSize:]
	if len(ip) < 20 {
		return 0
	}
	proto := ip[9]
	if proto != 6 && proto != 17 {
		return 0
	}
	ihl := int(ip[0]&0x0F) * 4
	if ihl < 20 {
		return 0
	}
	tcpStart := EthernetHeaderSize + ihl
	if len(data) < tcpStart+4 {
		return 0
	}

	var src, dst [4]byte
	copy(src[:], ip[12:16])
	copy(dst[:], ip[16:20])
	sp := [2]byte{data[tcpStart], data[tcpStart+1]}
	dp := [2]byte{data[tcpStart+2], data[tcpStart+3]}

	// Canonicalize direction: smaller IP first (tie-break by port), matching
	// NormalizeFlowID so both directions of a flow hash to the same shard.
	flip := false
	for i := range src {
		if src[i] > dst[i] {
			flip = true
			break
		} else if src[i] < dst[i] {
			break
		}
	}
	if !flip && src == dst {
		if uint16(sp[0])<<8|uint16(sp[1]) > uint16(dp[0])<<8|uint16(dp[1]) {
			flip = true
		}
	}
	if flip {
		src, dst = dst, src
		sp, dp = dp, sp
	}

	// FNV-1a over 13 bytes: 4+4+2+2+1 — zero heap allocations.
	h := uint32(2166136261)
	for _, b := range src { h ^= uint32(b); h *= 16777619 }
	for _, b := range dst { h ^= uint32(b); h *= 16777619 }
	h ^= uint32(sp[0]); h *= 16777619
	h ^= uint32(sp[1]); h *= 16777619
	h ^= uint32(dp[0]); h *= 16777619
	h ^= uint32(dp[1]); h *= 16777619
	h ^= uint32(proto); h *= 16777619
	// Wang's finalizer: ensures all bits influence the low bits used by modulo.
	h ^= h >> 16
	h *= 0x45d9f3b
	h ^= h >> 16
	return h
}

func (h *Handler) processIPv4Shard(s *ndpiShard, data []byte) {
	ipOffset := EthernetHeaderSize
	ipHeader := data[ipOffset:]

	if len(ipHeader) < 20 {
		return
	}

	ihl := int(ipHeader[0]&0x0F) * 4
	if ihl < 20 || len(ipHeader) < ihl {
		return
	}

	protocol := ipHeader[9]
	if protocol != 6 && protocol != 17 {
		return
	}

	srcIP := net.IP(ipHeader[12:16])
	dstIP := net.IP(ipHeader[16:20])

	tcpOffset := ipOffset + ihl
	if len(data) < tcpOffset+20 {
		return
	}

	tcpHeader := data[tcpOffset:]
	srcPort := uint16(tcpHeader[0])<<8 | uint16(tcpHeader[1])
	dstPort := uint16(tcpHeader[2])<<8 | uint16(tcpHeader[3])

	ttl := ipHeader[8]
	tos := ipHeader[1]

	var tcpWindow uint16
	if protocol == 6 && len(tcpHeader) >= 16 {
		tcpWindow = uint16(tcpHeader[14])<<8 | uint16(tcpHeader[15])
	}

	h.classifyAndUpdateFlowShard(s, srcIP, dstIP, srcPort, dstPort, protocol, data[ipOffset:], ttl, tos, tcpWindow, 4)
}

func (h *Handler) processIPv6Shard(s *ndpiShard, data []byte) {
	ipOffset := EthernetHeaderSize
	ipHeader := data[ipOffset:]

	if len(ipHeader) < 40 {
		return
	}

	nextHeader := ipHeader[6]
	if nextHeader != 6 && nextHeader != 17 {
		return
	}

	srcIP := net.IP(ipHeader[8:24])
	dstIP := net.IP(ipHeader[24:40])

	tcpOffset := ipOffset + 40
	if len(data) < tcpOffset+20 {
		return
	}

	tcpHeader := data[tcpOffset:]
	srcPort := uint16(tcpHeader[0])<<8 | uint16(tcpHeader[1])
	dstPort := uint16(tcpHeader[2])<<8 | uint16(tcpHeader[3])

	hopLimit := ipHeader[7]
	trafficClass := ipHeader[1]

	var tcpWindowIPv6 uint16
	if nextHeader == 6 && len(tcpHeader) >= 16 {
		tcpWindowIPv6 = uint16(tcpHeader[14])<<8 | uint16(tcpHeader[15])
	}

	h.classifyAndUpdateFlowShard(s, srcIP, dstIP, srcPort, dstPort, nextHeader, data[ipOffset:], hopLimit, trafficClass, tcpWindowIPv6, 6)
}

func (h *Handler) classifyAndUpdateFlowShard(s *ndpiShard, srcIP, dstIP net.IP, srcPort, dstPort uint16, protocol uint8, payload []byte, ttl, tos uint8, tcpWindow uint16, ipVersion uint8) {
	tupleID := flow.NormalizeFlowID(srcIP, dstIP, srcPort, dstPort, protocol)

	uuidVal, _ := h.flowUUIDs.LoadOrStore(tupleID, uuid.New().String())
	flowUUID := uuidVal.(string)

	if h.isServerFirstPort(dstPort) {
		proto := h.portToProtocol(dstPort)
		if h.logger != nil {
			h.logger.Info("server-first classified by port",
				zap.String("tuple_id", tupleID),
				zap.String("flow_id", flowUUID),
				zap.String("src", fmt.Sprintf("%s:%d", srcIP, srcPort)),
				zap.String("dst", fmt.Sprintf("%s:%d", dstIP, dstPort)),
				zap.String("protocol", proto),
				zap.Uint16("port", dstPort),
			)
		}

		h.flowTable.Update(tupleID, &flow.Entry{
			Protocol:       proto,
			MasterProtocol: "Unknown",
			Category:       0,
			LastSeen:       time.Now(),
			FlowUUID:       flowUUID,
			TTL:            ttl,
			TOS:            tos,
			TCPWindow:      tcpWindow,
			IPVersion:      ipVersion,
		})

		if h.ndpiEventsEnabled && h.producer != nil {
			h.publishNdpiEvent(flowUUID, tupleID, srcIP, dstIP, srcPort, dstPort, proto, proto, 0, ttl, tos, tcpWindow, ipVersion, protocol, payload)
		}
		return
	}

	// nDPI suporta apenas IPv4 para setup de flow
	if srcIP.To4() == nil {
		return
	}

	ndpiFlowI, loaded := s.ndpiFlows.Load(tupleID)
	if !loaded {
		newFlow, err := gondpi.NewNdpiFlow()
		if err != nil {
			return
		}
		newFlow.SetupFlow(srcIP, dstIP, protocol, srcPort, dstPort)
		actual, existedAlready := s.ndpiFlows.LoadOrStore(tupleID, newFlow)
		if !existedAlready {
			h.activeFlows.Add(1)
		}
		ndpiFlowI = actual
	}

	ndpiFlow, ok := ndpiFlowI.(*gondpi.NdpiFlow)
	if !ok {
		return
	}

	proto := s.ndpiDM.PacketProcessing(ndpiFlow, payload, uint16(len(payload)), time.Now().UnixMilli())

	if h.logger != nil {
		h.logger.Debug("nDPI result",
			zap.String("flow_id", flowUUID),
			zap.String("tuple_id", tupleID),
			zap.String("src", fmt.Sprintf("%s:%d", srcIP, srcPort)),
			zap.String("dst", fmt.Sprintf("%s:%d", dstIP, dstPort)),
			zap.String("master_proto", proto.MasterProtocolId.ToName()),
			zap.String("app_proto", proto.AppProtocolId.ToName()),
		)
	}

	masterProto := proto.MasterProtocolId.ToName()
	appProto := proto.AppProtocolId.ToName()
	category := uint32(proto.CategoryId)

	if strings.ToUpper(masterProto) == "UNKNOWN" {
		masterProto = appProto
	}

	h.flowTable.Update(tupleID, &flow.Entry{
		Protocol:       appProto,
		MasterProtocol: masterProto,
		Category:       category,
		LastSeen:       time.Now(),
		FlowUUID:       flowUUID,
		TTL:            ttl,
		TOS:            tos,
		TCPWindow:      tcpWindow,
		IPVersion:      ipVersion,
	})

	if h.ndpiEventsEnabled && h.producer != nil {
		h.publishNdpiEvent(flowUUID, tupleID, srcIP, dstIP, srcPort, dstPort, masterProto, appProto, category, ttl, tos, tcpWindow, ipVersion, protocol, payload)
	}
}

func (h *Handler) publishNdpiEvent(flowUUID, tupleID string, srcIP, dstIP net.IP, srcPort, dstPort uint16, masterProto, appProto string, category uint32, ttl, tos uint8, tcpWindow uint16, ipVersion uint8, protocol uint8, ipPacket []byte) {
	// Normaliza direção: dst_ip deve ser sempre o IP do servidor (honeypot).
	// Para pacotes de retorno (srcIP == IP local), inverte src/dst.
	if h.localIP != nil && srcIP.Equal(h.localIP) {
		srcIP, dstIP = dstIP, srcIP
		srcPort, dstPort = dstPort, srcPort
	}

	transport := "tcp"
	if protocol == 17 {
		transport = "udp"
	}

	ethertype := "0x0800"
	if ipVersion == 6 {
		ethertype = "0x86DD"
	}

	var tcpFlagsStr string
	var payloadLen int
	if len(ipPacket) > 0 {
		var transportOffset int
		if ipVersion == 4 {
			transportOffset = int(ipPacket[0]&0x0F) * 4
		} else {
			transportOffset = 40
		}
		switch {
		case protocol == 6 && len(ipPacket) > transportOffset+13:
			tcpFlagsStr = decodeTCPFlags(ipPacket[transportOffset+13])
			if len(ipPacket) > transportOffset+12 {
				dataOff := int((ipPacket[transportOffset+12]>>4)&0xF) * 4
				if appStart := transportOffset + dataOff; appStart <= len(ipPacket) {
					payloadLen = len(ipPacket) - appStart
				}
			}
		case protocol == 17 && len(ipPacket) > transportOffset+8:
			payloadLen = len(ipPacket) - (transportOffset + 8)
		}
	}

	var tcpWindowPtr *uint16
	if protocol == 6 {
		tcpWindowPtr = kafka.Uint16Ptr(tcpWindow)
	}

	h.producer.Publish(&kafka.Event{
		Instance:   "classifier",
		EventType:  "ndpi",
		FlowID:     flowUUID,
		TupleID:    tupleID,
		Timestamp:  time.Now(),
		SrcIP:      srcIP.String(),
		SrcPort:    int(srcPort),
		DstIP:      dstIP.String(),
		DstPort:    int(dstPort),
		NDPIProto:  masterProto,
		NDPIApp:    appProto,
		Category:   category,
		TTL:        ttl,
		TOS:        kafka.Uint8Ptr(tos),
		TCPWindow:  tcpWindowPtr,
		IPVersion:  ipVersion,
		Transport:  transport,
		TCPFlags:   tcpFlagsStr,
		PayloadLen: kafka.IntPtr(payloadLen),
		Ethertype:  ethertype,
		IPProto:    int(protocol),
		NodeName:   h.nodeName,
		PodName:    h.podName,
	})
}

func decodeTCPFlags(flags uint8) string {
	var s string
	if flags&0x02 != 0 {
		s += "SYN "
	}
	if flags&0x10 != 0 {
		s += "ACK "
	}
	if flags&0x08 != 0 {
		s += "PSH "
	}
	if flags&0x01 != 0 {
		s += "FIN "
	}
	if flags&0x04 != 0 {
		s += "RST "
	}
	if flags&0x20 != 0 {
		s += "URG "
	}
	return s
}

// PacketsProcessedAndReset retorna pacotes recebidos pelo ProcessPacket desde o último reset
// e zera o contador. Inclui pacotes que foram descartados antes de entrar em um shard.
func (h *Handler) PacketsProcessedAndReset() int64 {
	return h.packetsProcessed.Swap(0)
}

// PacketsDispatchedAndReset retorna pacotes que entraram efetivamente em um canal de shard
// (N>1) ou foram processados de forma síncrona (N=1) desde o último reset, e zera o contador.
// A diferença entre PacketsProcessedAndReset e este valor é igual a ShardDropsAndReset.
func (h *Handler) PacketsDispatchedAndReset() int64 {
	return h.packetsDispatched.Swap(0)
}

// ShardQueueDepths retorna o número atual de pacotes pendentes em cada canal de shard.
// Retorna slice vazio quando NDPI_WORKERS=1 (modo síncrono, sem canal).
func (h *Handler) ShardQueueDepths() []int {
	if h.numShards <= 1 {
		return nil
	}
	depths := make([]int, len(h.shards))
	for i, s := range h.shards {
		if s.ch != nil {
			depths[i] = len(s.ch)
		}
	}
	return depths
}

// ActiveFlows retorna o número atual de flows ativos no nDPI (somados de todos os shards).
func (h *Handler) ActiveFlows() int {
	return int(h.activeFlows.Load())
}

// CleanupEvictedAndReset retorna flows removidos pelo cleanup desde o último reset
// e zera o contador.
func (h *Handler) CleanupEvictedAndReset() int64 {
	return h.cleanupEvicted.Swap(0)
}

// ShardDropsAndReset retorna packets descartados por shard channel cheio desde o
// último reset e zera o contador. Sempre 0 quando NDPI_WORKERS=1.
func (h *Handler) ShardDropsAndReset() int64 {
	return h.shardDrops.Swap(0)
}

// ObserveQueueWait records T2−T1: how long a packet waited in the AF_PACKET channel.
func (h *Handler) ObserveQueueWait(d time.Duration) {
	h.queueWait.Observe(d.Nanoseconds())
}

// ObserveProcessing records T3−T2: the wall-clock cost of one ProcessPacket call.
// For N=1 this is called internally by ProcessPacket; the public method is kept for
// external callers that need to override measurement (e.g. tests).
func (h *Handler) ObserveProcessing(d time.Duration) {
	h.processing.Observe(d.Nanoseconds())
}

// ObserveQueueDepth records a point-in-time sample of the AF_PACKET channel depth.
func (h *Handler) ObserveQueueDepth(n int) {
	h.queueDepth.Observe(int64(n))
}

// TimingSnapshot holds one interval's worth of Phase 2 timing data.
type TimingSnapshot struct {
	QueueWait  metrics.HistogramSnapshot
	Processing metrics.HistogramSnapshot
	QueueDepth metrics.GaugeSnapshot
}

// TimingSnapshotAndReset drains the Phase 2 histograms and returns a snapshot.
func (h *Handler) TimingSnapshotAndReset() TimingSnapshot {
	return TimingSnapshot{
		QueueWait:  h.queueWait.SnapshotAndReset(),
		Processing: h.processing.SnapshotAndReset(),
		QueueDepth: h.queueDepth.SnapshotAndReset(),
	}
}

// SetProducer injects the Kafka producer after construction.
// Used to avoid a circular dependency when NdpiEventsEnabled=true.
func (h *Handler) SetProducer(p *kafka.Producer) {
	h.producer = p
}

func (h *Handler) Close() {
	h.cancel()
	h.wg.Wait()
	// Não chamamos ndpi_exit_detection_module: tráfego de honeypot pode corromper
	// o estado interno do nDPI causando double-free no shutdown. O OS recupera o
	// heap C ao terminar o processo. Flows pendentes são seguros de liberar pois
	// os goroutines de processamento já pararam (wg.Wait acima).
	for _, s := range h.shards {
		for _, f := range s.pendingFree {
			f.Close()
		}
		s.pendingFree = nil
	}
}

func (h *Handler) startShardCleanup(s *ndpiShard, interval time.Duration) {
	h.wg.Add(1)
	go func() {
		defer h.wg.Done()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-h.ctx.Done():
				return
			case <-ticker.C:
				h.cleanupShard(s)
			}
		}
	}()
}

func (h *Handler) cleanupShard(s *ndpiShard) {
	// Free flows deferred from the previous cleanup cycle. They were removed from
	// s.ndpiFlows then, so no PacketProcessing call can still reference them.
	freed := len(s.pendingFree)
	for _, f := range s.pendingFree {
		f.Close()
	}
	s.pendingFree = s.pendingFree[:0]

	evicted := 0
	s.ndpiFlows.Range(func(key, value any) bool {
		tupleID := key.(string)
		if _, found := h.flowTable.Get(tupleID); !found {
			s.ndpiFlows.Delete(tupleID)
			h.flowUUIDs.Delete(tupleID)
			s.pendingFree = append(s.pendingFree, value.(*gondpi.NdpiFlow))
			evicted++
			h.activeFlows.Add(-1)
			h.cleanupEvicted.Add(1)
		}
		return true
	})

	if h.logger != nil && (evicted > 0 || freed > 0) {
		h.logger.Info("nDPI shard cleanup",
			zap.Int("evicted", evicted),
			zap.Int("freed", freed),
		)
	}
}

func (h *Handler) isServerFirstPort(port uint16) bool {
	for _, p := range h.serverFirstPorts {
		if p == port {
			return true
		}
	}
	return false
}

func (h *Handler) portToProtocol(port uint16) string {
	if proto, ok := h.portProtocolMap[port]; ok {
		return proto
	}
	return "Unknown"
}
