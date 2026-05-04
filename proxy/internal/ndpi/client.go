package ndpi

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/spawnzao/dpipot-ng/proxy/internal/ndpi/gondpi"
	"go.uber.org/zap"
)

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

type FlowInfo struct {
	SrcIP   net.IP
	SrcPort uint16
	DstIP   net.IP
	DstPort uint16
}

type Client struct {
	useCGO  bool
	timeout time.Duration
	ndpiDM  *gondpi.NdpiDetectionModule
	logger  *zap.Logger
}

func NewClient(timeout time.Duration, logger *zap.Logger) (*Client, error) {
	c := &Client{
		timeout: timeout,
		logger: logger,
	}

	detectionBitmask := gondpi.NewNdpiProtocolBitmask()
	detectionBitmask = gondpi.NdpiProtocolBitmaskSetAll(detectionBitmask)

	ndpiDM, err := gondpi.NdpiDetectionModuleInitialize(0, detectionBitmask)
	if err != nil {
		return nil, fmt.Errorf("nDPI module init failed: %w", err)
	}
	c.ndpiDM = ndpiDM
	c.useCGO = true

	if c.logger != nil {
		c.logger.Info("nDPI detection module initialized via CGO")
	}

	return c, nil
}

func buildIPv4Packet(payload []byte, srcIP, dstIP net.IP, srcPort, dstPort uint16, protocol uint8) []byte {
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

	// Calculate IP checksum (set to 0 for now, should be calculated properly)
	binary.BigEndian.PutUint16(packet[10:], 0)

	copy(packet[12:16], srcIP.To4())
	copy(packet[16:20], dstIP.To4())

	// Recalculate IP checksum
	ipChecksum := calculateIPChecksum(packet[:20])
	binary.BigEndian.PutUint16(packet[10:], ipChecksum)

	// TCP header
	tcpOffset := 20
	binary.BigEndian.PutUint16(packet[tcpOffset:], srcPort)
	binary.BigEndian.PutUint16(packet[tcpOffset+2:], dstPort)
	binary.BigEndian.PutUint32(packet[tcpOffset+4:], 0)      // Seq
	binary.BigEndian.PutUint32(packet[tcpOffset+8:], 0)      // Ack
	packet[tcpOffset+12] = 0x50                              // Data offset (5 * 4 = 20 bytes)
	packet[tcpOffset+13] = 0x18                              // Flags: SYN + ACK (0x12 would be SYN, 0x18 is SYN+ACK)
	binary.BigEndian.PutUint16(packet[tcpOffset+14:], 65535) // Window
	binary.BigEndian.PutUint16(packet[tcpOffset+16:], 0)     // Checksum (should be calculated)
	binary.BigEndian.PutUint16(packet[tcpOffset+18:], 0)     // Urgent

	// TCP checksum (set to 0, simplified)
	// In production, should calculate pseudo-header checksum

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

func (c *Client) Classify(ctx context.Context, flowID string, payload []byte, flowInfo *FlowInfo) (string, error) {
	if len(payload) == 0 {
		return "Unknown", nil
	}

	if err := ctx.Err(); err != nil {
		return "Unknown", err
	}

	if c.useCGO && c.ndpiDM != nil {
		ndpiFlow, err := gondpi.NewNdpiFlow()
		if err != nil {
			return "Unknown", fmt.Errorf("nDPI flow create failed: %w", err)
		}
		defer ndpiFlow.Close()

		srcIP := flowInfo.SrcIP
		dstIP := flowInfo.DstIP

		if srcIP == nil || dstIP == nil {
			return "Unknown", nil
		}

		srcIP4 := srcIP.To4()
		dstIP4 := dstIP.To4()
		if srcIP4 == nil || dstIP4 == nil {
			return "Unknown", nil
		}

		ipPacket := buildIPv4Packet(payload, srcIP4, dstIP4, flowInfo.SrcPort, flowInfo.DstPort, 6)

		if c.logger != nil {
			c.logger.Debug("nDPI classifying packet",
				zap.Int("ipPacketLen", len(ipPacket)),
				zap.Int("payloadLen", len(payload)),
				zap.Uint16("srcPort", flowInfo.SrcPort),
				zap.Uint16("dstPort", flowInfo.DstPort),
				zap.ByteString("firstBytes", payload[:min(10, len(payload))]),
			)
		}

		ts := time.Now().UnixMilli()
		proto := c.ndpiDM.PacketProcessing(ndpiFlow, ipPacket, uint16(len(ipPacket)), ts)

		masterProto := proto.MasterProtocolId.ToName()
		appProto := proto.AppProtocolId.ToName()

		if c.logger != nil {
			c.logger.Debug("nDPI classification result",
				zap.String("masterProto", masterProto),
				zap.String("appProto", appProto),
				zap.Int("category", int(proto.CategoryId)),
			)
		}

		if appProto != "Unknown" {
			return appProto, nil
		}
		if masterProto != "Unknown" {
			return masterProto, nil
		}

		return "Unknown", nil
	}

	return "Unknown", nil
}

func (c *Client) Ping() error {
	if c.useCGO && c.ndpiDM != nil {
		return nil
	}
	return fmt.Errorf("nDPI CGO não disponível")
}

func (c *Client) Close() {
	if c.ndpiDM != nil {
		c.ndpiDM.Close()
	}
}
