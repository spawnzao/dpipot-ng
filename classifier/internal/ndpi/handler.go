package ndpi

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/spawnzao/dpipot-ng/classifier/internal/flow"
	"github.com/spawnzao/dpipot-ng/classifier/internal/kafka"
	"github.com/spawnzao/dpipot-ng/classifier/internal/ndpi/gondpi"
)

const (
	EthernetHeaderSize = 14
)

type Handler struct {
	ndpiDM    *gondpi.NdpiDetectionModule
	flowTable *flow.Table
	ndpiFlows *sync.Map
	logger    *zap.Logger
	producer  *kafka.Producer
	wg        sync.WaitGroup
	ctx       context.Context
	cancel    context.CancelFunc
}

type HandlerConfig struct {
	FlowTable *flow.Table
	Logger    *zap.Logger
	Producer  *kafka.Producer
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
		ndpiDM:    ndpiDM,
		flowTable: cfg.FlowTable,
		ndpiFlows: &sync.Map{},
		logger:    cfg.Logger,
		producer:  cfg.Producer,
		ctx:       ctx,
		cancel:    cancel,
	}

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
	flowID := flow.NormalizeFlowID(srcIP, dstIP, srcPort, dstPort, protocol)

	// Try to get existing flow, or create new one
	ndpiFlowI, loaded := h.ndpiFlows.Load(flowID)
	if !loaded {
		newFlow, err := gondpi.NewNdpiFlow()
		if err != nil {
			return
		}
		newFlow.SetupFlow(srcIP, dstIP, protocol, srcPort, dstPort)
		ndpiFlowI, _ = h.ndpiFlows.LoadOrStore(flowID, newFlow)
	}

	ndpiFlow, ok := ndpiFlowI.(*gondpi.NdpiFlow)
	if !ok {
		return
	}

	proto := h.ndpiDM.PacketProcessing(ndpiFlow, payload, uint16(len(payload)), time.Now().UnixMilli())

	if h.logger != nil {
		h.logger.Info("nDPI result",
			zap.String("flow_id", flowID),
			zap.String("ethertype", fmt.Sprintf("0x%04x", ethertype)),
			zap.String("src", fmt.Sprintf("%s:%d", srcIP, srcPort)),
			zap.String("dst", fmt.Sprintf("%s:%d", dstIP, dstPort)),
			zap.Uint8("proto", protocol),
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

	h.flowTable.Update(flowID, &flow.Entry{
		Protocol:       appProto,
		MasterProtocol: masterProto,
		Category:       category,
		SrcIP:          srcIP.String(),
		SrcPort:        srcPort,
		DstIP:          dstIP.String(),
		DstPort:        dstPort,
		ProtocolNum:    protocol,
		LastSeen:       time.Now(),
	})

	if h.producer != nil {
		h.producer.Publish(&kafka.Event{
			FlowID:      flowID,
			Timestamp:   time.Now(),
			SrcIP:       srcIP.String(),
			SrcPort:     int(srcPort),
			DstIP:       dstIP.String(),
			DstPort:     int(dstPort),
			NDPIProto:   ndpiProto,
			NDPIApp:     ndpiApp,
			Category:    category,
			TCPFlags:    tcpFlags,
			PayloadLen:  len(payload),
			EtherType:   fmt.Sprintf("0x%04x", ethertype),
			ProtocolNum: protocol,
			LogType:     "nDPI",
		})
	}
}

func (h *Handler) Close() {
	h.cancel()
	if h.ndpiDM != nil {
		h.ndpiDM.Close()
	}
	h.wg.Wait()
}
