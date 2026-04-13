package ndpi

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/spawnzao/dpipot-ng/classifier/internal/flow"
	"github.com/spawnzao/dpipot-ng/classifier/internal/ndpi/gondpi"
)

const (
	EthernetHeaderSize = 14
)

type Handler struct {
	ndpiDM    *gondpi.NdpiDetectionModule
	flowTable *flow.Table
	logger    *zap.Logger
	wg        sync.WaitGroup
	ctx       context.Context
	cancel    context.CancelFunc
}

type HandlerConfig struct {
	FlowTable *flow.Table
	Logger    *zap.Logger
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
		logger:    cfg.Logger,
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

	// Pass the complete IP packet (from IP header to end) to nDPI
	ipPacket := data[ipOffset:]

	h.classifyAndUpdateFlow(srcIP, dstIP, srcPort, dstPort, protocol, ipPacket)
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

	h.classifyAndUpdateFlow(srcIP, dstIP, srcPort, dstPort, nextHeader, ipPacket)
}

func (h *Handler) classifyAndUpdateFlow(srcIP, dstIP net.IP, srcPort, dstPort uint16, protocol uint8, payload []byte) {
	flowID := flow.NormalizeFlowID(srcIP, dstIP, srcPort, dstPort, protocol)

	ndpiFlow, err := gondpi.NewNdpiFlow()
	if err != nil {
		return
	}
	defer ndpiFlow.Close()

	ts := time.Now().UnixMilli()
	proto := h.ndpiDM.PacketProcessing(ndpiFlow, payload, uint16(len(payload)), ts)

	masterProto := proto.MasterProtocolId.ToName()
	appProto := proto.AppProtocolId.ToName()
	category := uint32(proto.CategoryId)

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
}

func (h *Handler) Close() {
	h.cancel()
	if h.ndpiDM != nil {
		h.ndpiDM.Close()
	}
	h.wg.Wait()
}
