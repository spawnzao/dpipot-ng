package ndpi

import (
	"context"
	//"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"
)

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
// Protocolo do socket (simples, sem overhead):
//
//	→ proxy manda: [4 bytes tamanho big-endian][payload bytes]
//	← nDPI devolve: "HTTP\n" ou "MongoDB\n" etc.
func (c *Client) Classify(ctx context.Context, flowID string, payload []byte) (string, error) {
	if len(payload) == 0 {
		return "Unknown", nil
	}

	conn, err := net.DialTimeout("unix", c.socketPath, c.timeout)
	if err != nil {
		return "Unknown", fmt.Errorf("ndpi socket dial: %w", err)
	}
	defer conn.Close()

	// aplica deadline da requisição inteira
	deadline := time.Now().Add(c.timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	conn.SetDeadline(deadline)

	// envia: flow_id (36 bytes UUID) + newline + tamanho (4 bytes) + payload
	header := fmt.Sprintf("%s\n", flowID)
	size := []byte{
		byte(len(payload) >> 24),
		byte(len(payload) >> 16),
		byte(len(payload) >> 8),
		byte(len(payload)),
	}

	if _, err := conn.Write([]byte(header)); err != nil {
		return "Unknown", fmt.Errorf("ndpi write header: %w", err)
	}
	if _, err := conn.Write(size); err != nil {
		return "Unknown", fmt.Errorf("ndpi write size: %w", err)
	}
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
// Útil no healthcheck do Pod antes de aceitar tráfego.
func (c *Client) Ping() error {
	conn, err := net.DialTimeout("unix", c.socketPath, 1*time.Second)
	if err != nil {
		return fmt.Errorf("nDPI sidecar não disponível em %s: %w", c.socketPath, err)
	}
	conn.Close()
	return nil
}
