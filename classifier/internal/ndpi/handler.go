package ndpi

import (
	"context"
	"encoding/binary"
	"net"
	"sync"
	"time"

	"github.com/spawnzao/dpipot-ng/classifier/internal/flow"
	"github.com/spawnzao/dpipot-ng/classifier/internal/ndpi/gondpi"
	"go.uber.org/zap"
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

	payloadOffset := tcpOffset + 20
	var payload []byte
	if len(data) > payloadOffset {
		payload = data[payloadOffset:]
	}

	h.classifyAndUpdateFlow(srcIP, dstIP, srcPort, dstPort, protocol, payload)
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

	payloadOffset := tcpOffset + 20
	var payload []byte
	if len(data) > payloadOffset {
		payload = data[payloadOffset:]
	}

	h.classifyAndUpdateFlow(srcIP, dstIP, srcPort, dstPort, nextHeader, payload)
}

func (h *Handler) classifyAndUpdateFlow(srcIP, dstIP net.IP, srcPort, dstPort uint16, protocol uint8, payload []byte) {
	flowID := flow.NormalizeFlowID(srcIP, dstIP, srcPort, dstPort, protocol)

	if h.logger != nil {
		h.logger.Debug("processing packet",
			zap.String("flow_id", flowID),
			zap.String("src", srcIP.String()),
			zap.String("dst", dstIP.String()),
			zap.Uint16("src_port", srcPort),
			zap.Uint16("dst_port", dstPort),
			zap.Uint8("proto", protocol),
			zap.Int("payload_len", len(payload)),
		)
	}

	// Use PacketProcessing directly (like proxy does)
	ndpiFlow, err := gondpi.NewNdpiFlow()
	if err != nil {
		if h.logger != nil {
			h.logger.Debug("nDPI flow creation failed", zap.Error(err))
		}
		return
	}
	defer ndpiFlow.Close()

	srcIP4 := srcIP.To4()
	dstIP4 := dstIP.To4()
	if srcIP4 == nil || dstIP4 == nil {
		return
	}

	// Build complete IP packet for nDPI (same as proxy)
	ipPacket := buildIPv4PacketForNDPI(payload, srcIP4, dstIP4, srcPort, dstPort, protocol)

	if h.logger != nil {
		h.logger.Debug("nDPI classifying packet",
			zap.String("flow_id", flowID),
			zap.Int("ipPacketLen", len(ipPacket)),
			zap.Int("payloadLen", len(payload)),
		)
	}

	ts := time.Now().UnixMilli()
	proto := h.ndpiDM.PacketProcessing(ndpiFlow, ipPacket, uint16(len(ipPacket)), ts)

	masterProto := proto.MasterProtocolId.ToName()
	appProto := proto.AppProtocolId.ToName()
	category := uint32(proto.CategoryId)

	if h.logger != nil {
		h.logger.Debug("classified flow",
			zap.String("flow_id", flowID),
			zap.String("master", masterProto),
			zap.String("app", appProto),
			zap.Uint32("category", category),
		)
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
}

func (h *Handler) Close() {
	h.cancel()
	if h.ndpiDM != nil {
		h.ndpiDM.Close()
	}
	h.wg.Wait()
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func buildIPv4PacketForNDPI(payload []byte, srcIP, dstIP net.IP, srcPort, dstPort uint16, protocol uint8) []byte {
	tcpHeaderLen := 20
	totalLen := 20 + tcpHeaderLen + len(payload)

	packet := make([]byte, totalLen)

	packet[0] = 0x45 // IPv4, IHL=5
	packet[1] = 0x00 // DSCP
	binary.BigEndian.PutUint16(packet[2:], uint16(totalLen))
	binary.BigEndian.PutUint16(packet[4:], uint16(54321))
	binary.BigEndian.PutUint16(packet[6:], 0x4000) // Don't fragment
	packet[8] = 64                                 // TTL
	packet[9] = protocol                           // TCP (6)

	binary.BigEndian.PutUint16(packet[10:], 0)

	copy(packet[12:16], srcIP)
	copy(packet[16:20], dstIP)

	ipChecksum := calculateIPChecksum(packet[:20])
	binary.BigEndian.PutUint16(packet[10:], ipChecksum)

	tcpOffset := 20
	binary.BigEndian.PutUint16(packet[tcpOffset:], srcPort)
	binary.BigEndian.PutUint16(packet[tcpOffset+2:], dstPort)
	binary.BigEndian.PutUint32(packet[tcpOffset+4:], 0)      // Seq
	binary.BigEndian.PutUint32(packet[tcpOffset+8:], 0)      // Ack
	packet[tcpOffset+12] = 0x50                              // Data offset
	packet[tcpOffset+13] = 0x18                              // Flags: SYN + ACK
	binary.BigEndian.PutUint16(packet[tcpOffset+14:], 65535) // Window
	binary.BigEndian.PutUint16(packet[tcpOffset+16:], 0)     // Checksum

	copy(packet[tcpOffset+20:], payload)

	return packet
}

func calculateIPChecksum(header []byte) uint16 {
	var sum uint32
	for i := 0; i < len(header); i += 2 {
		var word uint16
		if i+1 < len(header) {
			word = uint16(header[i])<<8 | uint16(header[i+1])
		} else {
			word = uint16(header[i]) << 8
		}
		sum += uint32(word)
	}
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return uint16(^sum)
}
