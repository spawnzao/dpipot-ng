package ndpi

import (
	"context"
	"encoding/binary"
	"fmt"
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

func (h *Handler) buildIPv4Packet(srcIP, dstIP net.IP, srcPort, dstPort uint16, protocol uint8, payload []byte) []byte {
	// Build a complete IPv4 packet with TCP header
	ipHeaderLen := 20
	tcpHeaderLen := 20
	totalLen := ipHeaderLen + tcpHeaderLen + len(payload)

	packet := make([]byte, totalLen)

	// IPv4 Header
	// Version (4) + IHL (5 = 20 bytes)
	packet[0] = 0x45
	// DSCP + ECN
	packet[1] = 0x00
	// Total Length
	binary.BigEndian.PutUint16(packet[2:4], uint16(totalLen))
	// Identification
	binary.BigEndian.PutUint16(packet[4:6], 0)
	// Flags (0) + Fragment Offset (0)
	binary.BigEndian.PutUint16(packet[6:8], 0)
	// TTL
	packet[8] = 64
	// Protocol
	packet[9] = protocol
	// Header Checksum (will calculate)
	binary.BigEndian.PutUint16(packet[10:12], 0)
	// Source IP
	copy(packet[12:16], srcIP.To4())
	// Destination IP
	copy(packet[16:20], dstIP.To4())

	// Calculate IP header checksum
	ipChecksum := calculateIPChecksum(packet[:ipHeaderLen])
	binary.BigEndian.PutUint16(packet[10:12], ipChecksum)

	// TCP Header
	tcpOffset := ipHeaderLen
	// Source Port
	binary.BigEndian.PutUint16(packet[tcpOffset:tcpOffset+2], srcPort)
	// Destination Port
	binary.BigEndian.PutUint16(packet[tcpOffset+2:tcpOffset+4], dstPort)
	// Sequence Number (random)
	binary.BigEndian.PutUint32(packet[tcpOffset+4:tcpOffset+8], 0x12345678)
	// Acknowledgment Number
	binary.BigEndian.PutUint32(packet[tcpOffset+8:tcpOffset+12], 0)
	// Data Offset (5 = 20 bytes) + Flags (SYN)
	binary.BigEndian.PutUint16(packet[tcpOffset+12:tcpOffset+14], 0x6002) // 5<<12 | 0x0002 (SYN)
	// Window Size
	binary.BigEndian.PutUint16(packet[tcpOffset+14:tcpOffset+16], 65535)
	// Checksum (will calculate)
	binary.BigEndian.PutUint16(packet[tcpOffset+16:tcpOffset+18], 0)
	// Urgent Pointer
	packet[tcpOffset+18] = 0
	packet[tcpOffset+19] = 0

	// Pseudo header for TCP checksum calculation
	psuedo := make([]byte, 12+tcpHeaderLen+len(payload))
	copy(psuedo[0:4], srcIP.To4())
	copy(psuedo[4:8], dstIP.To4())
	psuedo[8] = 0
	psuedo[9] = protocol
	binary.BigEndian.PutUint16(psuedo[10:12], uint16(tcpHeaderLen+len(payload)))
	copy(psuedo[12:], packet[tcpOffset:])

	tcpChecksum := calculateChecksum(psuedo)
	binary.BigEndian.PutUint16(packet[tcpOffset+16:tcpOffset+18], tcpChecksum)

	// Payload
	if len(payload) > 0 {
		copy(packet[tcpOffset+tcpHeaderLen:], payload)
	}

	return packet
}

func calculateIPChecksum(header []byte) uint16 {
	sum := uint32(0)
	for i := 0; i < len(header); i += 2 {
		word := uint16(header[i])<<8 | uint16(header[i+1])
		sum += uint32(word)
	}
	for sum > 0xFFFF {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return uint16(^sum)
}

func calculateChecksum(data []byte) uint16 {
	sum := uint32(0)
	for i := 0; i < len(data); i += 2 {
		var word uint16
		if i+1 < len(data) {
			word = uint16(data[i])<<8 | uint16(data[i+1])
		} else {
			word = uint16(data[i]) << 8
		}
		sum += uint32(word)
	}
	for sum > 0xFFFF {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return uint16(^sum)
}

var _ = math.MinInt

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

	firstBytes := ""
	if len(payload) > 8 {
		firstBytes = fmt.Sprintf("%x", payload[:8])
	}

	if h.logger != nil {
		h.logger.Debug("processing packet",
			zap.String("flow_id", flowID),
			zap.String("src", srcIP.String()),
			zap.String("dst", dstIP.String()),
			zap.Uint16("src_port", srcPort),
			zap.Uint16("dst_port", dstPort),
			zap.Uint8("proto", protocol),
			zap.Int("payload_len", len(payload)),
			zap.String("first_bytes", firstBytes),
		)
	}

	// Build complete IP packet with headers
	ipPacket := h.buildIPv4Packet(srcIP, dstIP, srcPort, dstPort, protocol, payload)
	if h.logger != nil {
		h.logger.Debug("nDPI input",
			zap.String("flow_id", flowID),
			zap.Int("ip_packet_len", len(ipPacket)),
			zap.String("ip_first_bytes", fmt.Sprintf("%x", ipPacket[:min(20, len(ipPacket))])),
		)
	}

	flowInfo, err := h.ndpiDM.ProcessPacketFlow(srcIP, dstIP, srcPort, dstPort, protocol, payload)
	if err != nil {
		if h.logger != nil {
			h.logger.Debug("nDPI classification failed", zap.Error(err), zap.String("flow_id", flowID))
		}
		return
	}

	masterProto := flowInfo.MasterProtocolId.ToName()
	appProto := flowInfo.AppProtocolId.ToName()
	category := uint32(flowInfo.CategoryId)

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
