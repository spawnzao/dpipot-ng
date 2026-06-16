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

	"github.com/spawnzao/dpipot-ng/classifier/internal/flow"
	"github.com/spawnzao/dpipot-ng/classifier/internal/kafka"
	"github.com/spawnzao/dpipot-ng/classifier/internal/ndpi/gondpi"
)

const (
	EthernetHeaderSize = 14
)

type Handler struct {
	ndpiDM          *gondpi.NdpiDetectionModule
	flowTable       *flow.Table
	ndpiFlows       *sync.Map
	flowUUIDs       sync.Map // tuple_id → UUID; um UUID por conexão TCP
	logger          *zap.Logger
	producer        *kafka.Producer
	wg              sync.WaitGroup
	ctx             context.Context
	cancel          context.CancelFunc
	serverFirstPorts []uint16
	portProtocolMap  map[uint16]string
	// pendingFree armazena flows removidos do ndpiFlows no ciclo anterior de
	// cleanup. São liberados no próximo ciclo (2 min depois), garantindo que
	// nenhum PacketProcessing em curso ainda segure o ponteiro C.
	pendingFree []*gondpi.NdpiFlow
}

type HandlerConfig struct {
	FlowTable         *flow.Table
	Logger            *zap.Logger
	Producer          *kafka.Producer
	ServerFirstPorts  []uint16
	PortProtocolMap   map[uint16]string
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
		ndpiDM:           ndpiDM,
		flowTable:        cfg.FlowTable,
		ndpiFlows:        &sync.Map{},
		logger:           cfg.Logger,
		producer:         cfg.Producer,
		ctx:              ctx,
		cancel:           cancel,
		serverFirstPorts: cfg.ServerFirstPorts,
		portProtocolMap:  cfg.PortProtocolMap,
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
	default:
		return
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

	// Get TCP flags
	var tcpFlags string
	if len(tcpHeader) >= 14 {
		flags := tcpHeader[13]
		if flags&0x02 != 0 {
			tcpFlags += "SYN "
		}
		if flags&0x10 != 0 {
			tcpFlags += "ACK "
		}
		if flags&0x04 != 0 {
			tcpFlags += "RST "
		}
		if flags&0x08 != 0 {
			tcpFlags += "PSH "
		}
		if flags&0x01 != 0 {
			tcpFlags += "FIN "
		}
		if tcpFlags == "" {
			tcpFlags = "none"
		}
	}

	// Pass the complete IP packet (from IP header to end) to nDPI
	ipPacket := data[ipOffset:]

	h.classifyAndUpdateFlow(srcIP, dstIP, srcPort, dstPort, protocol, ipPacket, 0x0800, tcpFlags)
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

	// Pass the complete IP packet (from IP header to end) to nDPI
	ipPacket := data[ipOffset:]

	h.classifyAndUpdateFlow(srcIP, dstIP, srcPort, dstPort, nextHeader, ipPacket, 0x86dd, "N/A")
}

func (h *Handler) classifyAndUpdateFlow(srcIP, dstIP net.IP, srcPort, dstPort uint16, protocol uint8, payload []byte, ethertype uint16, tcpFlags string) {
	tupleID := flow.NormalizeFlowID(srcIP, dstIP, srcPort, dstPort, protocol)

	// UUID único por conexão: gerado na primeira vez que o tupleID aparece.
	uuidVal, _ := h.flowUUIDs.LoadOrStore(tupleID, uuid.New().String())
	flowUUID := uuidVal.(string)

	// Verifica se é porta server-first - classifica direto sem nDPI
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
			SrcIP:          srcIP.String(),
			SrcPort:        srcPort,
			DstIP:          dstIP.String(),
			DstPort:        dstPort,
			ProtocolNum:    protocol,
			LastSeen:       time.Now(),
			FlowUUID:       flowUUID,
		})
		return
	}

	// Fluxo normal com nDPI
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
			zap.String("ethertype", fmt.Sprintf("0x%04x", ethertype)),
			zap.String("src", fmt.Sprintf("%s:%d", srcIP, srcPort)),
			zap.String("dst", fmt.Sprintf("%s:%d", dstIP, dstPort)),
			zap.Uint8("ip_proto", protocol),
			zap.String("transport", ipProtoName(protocol)),
			zap.String("tcp_flags", tcpFlags),
			zap.String("master_proto", proto.MasterProtocolId.ToName()),
			zap.String("app_proto", proto.AppProtocolId.ToName()),
			zap.Int("payload_len", len(payload)),
		)
	}

	masterProto := proto.MasterProtocolId.ToName()
	appProto := proto.AppProtocolId.ToName()
	category := uint32(proto.CategoryId)

	ndpiProto := masterProto
	ndpiApp := appProto
	if ndpiApp == "Unknown" || ndpiApp == "" {
		ndpiApp = ""
	}
	if strings.ToUpper(ndpiProto) == "UNKNOWN" {
		ndpiProto = appProto
		ndpiApp = ""
	}

	h.flowTable.Update(tupleID, &flow.Entry{
		Protocol:       appProto,
		MasterProtocol: masterProto,
		Category:       category,
		SrcIP:          srcIP.String(),
		SrcPort:        srcPort,
		DstIP:          dstIP.String(),
		DstPort:        dstPort,
		ProtocolNum:    protocol,
		LastSeen:       time.Now(),
		FlowUUID:       flowUUID,
	})

	if h.producer != nil {
		h.producer.Publish(&kafka.Event{
			FlowID:     flowUUID,
			TupleID:    tupleID,
			Timestamp:  time.Now(),
			SrcIP:      srcIP.String(),
			SrcPort:    int(srcPort),
			DstIP:      dstIP.String(),
			DstPort:    int(dstPort),
			NDPIProto:  ndpiProto,
			NDPIApp:    ndpiApp,
			Category:   category,
			TCPFlags:   tcpFlags,
			PayloadLen: len(payload),
			EtherType:  fmt.Sprintf("0x%04x", ethertype),
			IPProto:    protocol,
			Transport:  ipProtoName(protocol),
			Instance:   "classifier",
		})
	}
}

func (h *Handler) Close() {
	h.cancel()
	h.wg.Wait()
	// Não chamamos ndpi_exit_detection_module (NdpiDetectionModule.Close()): o tráfego
	// de honeypot corrompe o estado interno do nDPI e causa "double free detected in
	// tcache 2" no shutdown. O OS recupera o heap C ao matar o container.
	// ndpi_flow_struct_free individual é seguro porque o goroutine de processamento
	// já parou (wg.Wait acima); liberamos os flows pendentes antes de sair.
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
	// Fase 2: libera C heap dos flows removidos no ciclo ANTERIOR (30s atrás).
	// Garantia de segurança: 30s >> tempo de qualquer PacketProcessing em curso (µs).
	freed := len(h.pendingFree)
	for _, f := range h.pendingFree {
		f.Close()
	}
	h.pendingFree = h.pendingFree[:0]

	// Fase 1: evicta flows nDPI cujo tupleID saiu da flowTable.
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

	// Fase 1b: limpa UUIDs de flows server-first (não têm entrada em ndpiFlows,
	// portanto o loop acima nunca os vê — sem isso, flowUUIDs vaza para sempre).
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

func ipProtoName(proto uint8) string {
	switch proto {
	case 1:
		return "icmp"
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 58:
		return "icmpv6"
	default:
		return fmt.Sprintf("%d", proto)
	}
}

func (h *Handler) portToProtocol(port uint16) string {
	if proto, ok := h.portProtocolMap[port]; ok {
		return proto
	}
	return "Unknown"
}
