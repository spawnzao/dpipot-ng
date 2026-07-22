package ndpi

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/spawnzao/dpipot-ng/internal/flow"
	"github.com/spawnzao/dpipot-ng/internal/kafka"
	"github.com/spawnzao/dpipot-ng/internal/ndpi/gondpi"
)

const (
	EthernetHeaderSize = 14
)

type Handler struct {
	ndpiDM           *gondpi.NdpiDetectionModule
	flowTable        *flow.Table
	ndpiFlows        *sync.Map
	flowUUIDs        sync.Map // tuple_id → UUID; um UUID por conexão TCP
	logger           *zap.Logger
	wg               sync.WaitGroup
	ctx              context.Context
	cancel           context.CancelFunc
	serverFirstPorts []uint16
	portProtocolMap  map[uint16]string
	producer         *kafka.Producer
	ndpiEventsEnabled bool
	nodeName         string
	podName          string
	// pendingFree armazena flows removidos do ndpiFlows no ciclo anterior de
	// cleanup. São liberados no próximo ciclo (2 min depois), garantindo que
	// nenhum PacketProcessing em curso ainda segure o ponteiro C.
	pendingFree []*gondpi.NdpiFlow
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
}

func NewHandler(cfg HandlerConfig) (*Handler, error) {
	detectionBitmask := gondpi.NewNdpiProtocolBitmask()
	detectionBitmask = gondpi.NdpiProtocolBitmaskSetAll(detectionBitmask)

	ndpiDM, err := gondpi.NdpiDetectionModuleInitialize(0, detectionBitmask)
	if err != nil {
		return nil, fmt.Errorf("nDPI init failed: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	h := &Handler{
		ndpiDM:            ndpiDM,
		flowTable:         cfg.FlowTable,
		ndpiFlows:         &sync.Map{},
		logger:            cfg.Logger,
		ctx:               ctx,
		cancel:            cancel,
		serverFirstPorts:  cfg.ServerFirstPorts,
		portProtocolMap:   cfg.PortProtocolMap,
		producer:          cfg.Producer,
		ndpiEventsEnabled: cfg.NdpiEventsEnabled,
		nodeName:          cfg.NodeName,
		podName:           cfg.PodName,
	}

	h.startNdpiFlowsCleanup(30 * time.Second)

	if h.logger != nil {
		h.logger.Info("nDPI handler initialized")
	}

	return h, nil
}

func (h *Handler) ProcessPacket(data []byte) {
	if len(data) < EthernetHeaderSize+20 {
		return
	}

	ethertype := uint16(data[12])<<8 | uint16(data[13])

	switch ethertype {
	case 0x0800:
		h.processIPv4(data)
	case 0x86DD:
		h.processIPv6(data)
	}
}

func (h *Handler) processIPv4(data []byte) {
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

	ipPacket := data[ipOffset:]
	h.classifyAndUpdateFlow(srcIP, dstIP, srcPort, dstPort, protocol, ipPacket, ttl, tos, tcpWindow, 4)
}

func (h *Handler) processIPv6(data []byte) {
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

	ipPacket := data[ipOffset:]
	h.classifyAndUpdateFlow(srcIP, dstIP, srcPort, dstPort, nextHeader, ipPacket, hopLimit, trafficClass, tcpWindowIPv6, 6)
}

func (h *Handler) classifyAndUpdateFlow(srcIP, dstIP net.IP, srcPort, dstPort uint16, protocol uint8, payload []byte, ttl, tos uint8, tcpWindow uint16, ipVersion uint8) {
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
			h.publishNdpiEvent(flowUUID, tupleID, srcIP, dstIP, srcPort, dstPort, proto, proto, ttl, tos, tcpWindow, ipVersion)
		}
		return
	}

	// nDPI suporta apenas IPv4 para setup de flow
	if srcIP.To4() == nil {
		return
	}

	ndpiFlowI, loaded := h.ndpiFlows.Load(tupleID)
	if !loaded {
		newFlow, err := gondpi.NewNdpiFlow()
		if err != nil {
			return
		}
		newFlow.SetupFlow(srcIP, dstIP, protocol, srcPort, dstPort)
		ndpiFlowI, _ = h.ndpiFlows.LoadOrStore(tupleID, newFlow)
	}

	ndpiFlow, ok := ndpiFlowI.(*gondpi.NdpiFlow)
	if !ok {
		return
	}

	proto := h.ndpiDM.PacketProcessing(ndpiFlow, payload, uint16(len(payload)), time.Now().UnixMilli())

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
		h.publishNdpiEvent(flowUUID, tupleID, srcIP, dstIP, srcPort, dstPort, masterProto, appProto, ttl, tos, tcpWindow, ipVersion)
	}
}

func (h *Handler) publishNdpiEvent(flowUUID, tupleID string, srcIP, dstIP net.IP, srcPort, dstPort uint16, masterProto, appProto string, ttl, tos uint8, tcpWindow uint16, ipVersion uint8) {
	h.producer.Publish(&kafka.Event{
		Instance:  "classifier",
		EventType: "ndpi",
		FlowID:    flowUUID,
		TupleID:   tupleID,
		Timestamp: time.Now(),
		SrcIP:     srcIP.String(),
		SrcPort:   int(srcPort),
		DstIP:     dstIP.String(),
		DstPort:   int(dstPort),
		NDPIProto: masterProto,
		NDPIApp:   appProto,
		TTL:       ttl,
		TOS:       tos,
		TCPWindow: tcpWindow,
		IPVersion: ipVersion,
		NodeName:  h.nodeName,
		PodName:   h.podName,
	})
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
	// o goroutine de processamento já parou (wg.Wait acima).
	for _, f := range h.pendingFree {
		f.Close()
	}
	h.pendingFree = nil
}

func (h *Handler) startNdpiFlowsCleanup(interval time.Duration) {
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
				h.cleanupNdpiFlows()
			}
		}
	}()
}

func (h *Handler) cleanupNdpiFlows() {
	freed := len(h.pendingFree)
	for _, f := range h.pendingFree {
		f.Close()
	}
	h.pendingFree = h.pendingFree[:0]

	evicted := 0
	h.ndpiFlows.Range(func(key, value any) bool {
		tupleID := key.(string)
		if _, found := h.flowTable.Get(tupleID); !found {
			h.ndpiFlows.Delete(tupleID)
			h.flowUUIDs.Delete(tupleID)
			h.pendingFree = append(h.pendingFree, value.(*gondpi.NdpiFlow))
			evicted++
		}
		return true
	})

	uuidsCleaned := 0
	h.flowUUIDs.Range(func(key, value any) bool {
		tupleID := key.(string)
		if _, found := h.flowTable.Get(tupleID); !found {
			h.flowUUIDs.Delete(tupleID)
			uuidsCleaned++
		}
		return true
	})

	if h.logger != nil && (evicted > 0 || freed > 0 || uuidsCleaned > 0) {
		h.logger.Info("nDPI flows cleanup",
			zap.Int("evicted", evicted),
			zap.Int("freed", freed),
			zap.Int("uuids_cleaned", uuidsCleaned),
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
