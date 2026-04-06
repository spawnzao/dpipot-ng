package ndpi

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"
)

// FlowInfo contém as informações de rede do fluxo TCP.
// Usado para enviar ao nDPI a 5-tupla correta mesmo após TPROXY/redirect.
type FlowInfo struct {
	SrcIP   net.IP
	SrcPort uint16
	DstIP   net.IP
	DstPort uint16
}

// Client fala com o sidecar nDPI via Unix domain socket.
// O sidecar recebe bytes do payload e devolve a label do protocolo.
type Client struct {
	socketPath string
	timeout    time.Duration
}

func NewClient(socketPath string, timeout time.Duration) *Client {
	return &Client{
		socketPath: socketPath,
		timeout:    timeout,
	}
}

// Classify envia os primeiros bytes de um fluxo para o nDPI e recebe a label.
// Retorna "Unknown" se o nDPI não conseguir classificar dentro do timeout.
//
// Protocolo do socket:
//
//	→ proxy manda: flow_id\n [4 bytes len] [4 bytes src_ip] [4 bytes dst_ip]
//	              [2 bytes src_port] [2 bytes dst_port] [payload...]
//	← nDPI devolve: "HTTP\n" ou "MongoDB\n" etc.
func (c *Client) Classify(ctx context.Context, flowID string, payload []byte, flowInfo *FlowInfo) (string, error) {
	if len(payload) == 0 {
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

	// flow_id + newline
	header := fmt.Sprintf("%s\n", flowID)
	if _, err := conn.Write([]byte(header)); err != nil {
		return "Unknown", fmt.Errorf("ndpi write header: %w", err)
	}

	// payload length (4 bytes big-endian)
	size := make([]byte, 4)
	binary.BigEndian.PutUint32(size, uint32(len(payload)))
	if _, err := conn.Write(size); err != nil {
		return "Unknown", fmt.Errorf("ndpi write size: %w", err)
	}

	// src_ip (4 bytes network byte order)
	srcIP := flowInfo.SrcIP.To4()
	if srcIP == nil {
		return "Unknown", fmt.Errorf("src_ip não é IPv4")
	}
	if _, err := conn.Write(srcIP); err != nil {
		return "Unknown", fmt.Errorf("ndpi write src_ip: %w", err)
	}

	// dst_ip (4 bytes network byte order)
	dstIP := flowInfo.DstIP.To4()
	if dstIP == nil {
		return "Unknown", fmt.Errorf("dst_ip não é IPv4")
	}
	if _, err := conn.Write(dstIP); err != nil {
		return "Unknown", fmt.Errorf("ndpi write dst_ip: %w", err)
	}

	// src_port (2 bytes big-endian)
	srcPort := make([]byte, 2)
	binary.BigEndian.PutUint16(srcPort, flowInfo.SrcPort)
	if _, err := conn.Write(srcPort); err != nil {
		return "Unknown", fmt.Errorf("ndpi write src_port: %w", err)
	}

	// dst_port (2 bytes big-endian)
	dstPort := make([]byte, 2)
	binary.BigEndian.PutUint16(dstPort, flowInfo.DstPort)
	if _, err := conn.Write(dstPort); err != nil {
		return "Unknown", fmt.Errorf("ndpi write dst_port: %w", err)
	}

	// payload
	if _, err := conn.Write(payload); err != nil {
		return "Unknown", fmt.Errorf("ndpi write payload: %w", err)
	}

	// lê a resposta: "HTTP\n"
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

// Ping verifica se o sidecar nDPI está disponível.
func (c *Client) Ping() error {
	conn, err := net.DialTimeout("unix", c.socketPath, 5*time.Second)
	if err != nil {
		return fmt.Errorf("nDPI sidecar não disponível em %s: %w", c.socketPath, err)
	}
	conn.Close()
	return nil
}
