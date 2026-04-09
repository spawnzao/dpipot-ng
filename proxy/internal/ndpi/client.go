package ndpi

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/spawnzao/dpipot-ng/proxy/internal/ndpi/gondpi"
	"github.com/spawnzao/dpipot-ng/proxy/internal/ndpi/gondpi/types"
)

type FlowInfo struct {
	SrcIP   net.IP
	SrcPort uint16
	DstIP   net.IP
	DstPort uint16
}

type Client struct {
	useCGO     bool
	socketPath string
	timeout    time.Duration
	ndpiDM     *gondpi.NdpiDetectionModule
}

func NewClient(socketPath string, timeout time.Duration) (*Client, error) {
	c := &Client{
		socketPath: socketPath,
		timeout:    timeout,
	}

	detectionBitmask := gondpi.NewNdpiProtocolBitmask()
	detectionBitmask = gondpi.NdpiProtocolBitmaskSetAll(detectionBitmask)

	ndpiDM, err := gondpi.NdpiDetectionModuleInitialize(types.NDPI_NO_PREFS, detectionBitmask)
	if err != nil {
		return nil, fmt.Errorf("nDPI module init failed: %w", err)
	}
	c.ndpiDM = ndpiDM
	c.useCGO = true

	return c, nil
}

func (c *Client) Classify(ctx context.Context, flowID string, payload []byte, flowInfo *FlowInfo) (string, error) {
	if len(payload) == 0 {
		return "Unknown", nil
	}

	if c.useCGO && c.ndpiDM != nil {
		ndpiFlow, err := gondpi.NewNdpiFlow()
		if err != nil {
			return "Unknown", fmt.Errorf("nDPI flow create failed: %w", err)
		}
		defer ndpiFlow.Close()

		ts := time.Now().UnixMilli()
		proto := c.ndpiDM.PacketProcessing(ndpiFlow, payload, uint16(len(payload)), ts)

		masterProto := proto.MasterProtocolId.ToName()
		appProto := proto.AppProtocolId.ToName()

		if appProto != "Unknown" {
			return appProto, nil
		}
		if masterProto != "Unknown" {
			return masterProto, nil
		}

		return "Unknown", nil
	}

	conn, err := net.DialTimeout("unix", c.socketPath, c.timeout)
	if err != nil {
		return "Unknown", fmt.Errorf("ndpi socket dial: %w", err)
	}
	defer conn.Close()

	deadline := time.Now().Add(c.timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	conn.SetDeadline(deadline)

	header := fmt.Sprintf("%s\n", flowID)
	if _, err := conn.Write([]byte(header)); err != nil {
		return "Unknown", fmt.Errorf("ndpi write header: %w", err)
	}

	size := make([]byte, 4)
	binary.BigEndian.PutUint32(size, uint32(len(payload)))
	if _, err := conn.Write(size); err != nil {
		return "Unknown", fmt.Errorf("ndpi write size: %w", err)
	}

	srcIP := flowInfo.SrcIP.To4()
	if srcIP == nil {
		return "Unknown", fmt.Errorf("src_ip não é IPv4")
	}
	if _, err := conn.Write(srcIP); err != nil {
		return "Unknown", fmt.Errorf("ndpi write src_ip: %w", err)
	}

	dstIP := flowInfo.DstIP.To4()
	if dstIP == nil {
		return "Unknown", fmt.Errorf("dst_ip não é IPv4")
	}
	if _, err := conn.Write(dstIP); err != nil {
		return "Unknown", fmt.Errorf("ndpi write dst_ip: %w", err)
	}

	srcPort := make([]byte, 2)
	binary.BigEndian.PutUint16(srcPort, flowInfo.SrcPort)
	if _, err := conn.Write(srcPort); err != nil {
		return "Unknown", fmt.Errorf("ndpi write src_port: %w", err)
	}

	dstPort := make([]byte, 2)
	binary.BigEndian.PutUint16(dstPort, flowInfo.DstPort)
	if _, err := conn.Write(dstPort); err != nil {
		return "Unknown", fmt.Errorf("ndpi write dst_port: %w", err)
	}

	if _, err := conn.Write(payload); err != nil {
		return "Unknown", fmt.Errorf("ndpi write payload: %w", err)
	}

	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil {
		return "Unknown", fmt.Errorf("ndpi read response: %w", err)
	}

	label := strings.TrimSpace(string(buf[:n]))
	if label == "" {
		return "Unknown", nil
	}
	return label, nil
}

func (c *Client) Ping() error {
	if c.useCGO && c.ndpiDM != nil {
		return nil
	}

	conn, err := net.DialTimeout("unix", c.socketPath, 5*time.Second)
	if err != nil {
		return fmt.Errorf("nDPI sidecar não disponível em %s: %w", c.socketPath, err)
	}
	conn.Close()
	return nil
}

func (c *Client) Close() {
	if c.ndpiDM != nil {
		c.ndpiDM.Close()
	}
}
