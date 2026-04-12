package flowtracker

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/spawnzao/dpipot-ng/proxy/internal/config"
	"go.uber.org/zap"
)

type Client struct {
	addr    string
	timeout time.Duration
	logger  *zap.Logger
	enabled bool
}

func NewClient(cfg config.Config, logger *zap.Logger) *Client {
	addr := fmt.Sprintf("%s:%d", cfg.ClassifierHost, cfg.ClassifierPort)
	timeout := 100 * time.Millisecond

	c := &Client{
		addr:    addr,
		timeout: timeout,
		logger:  logger,
		enabled: cfg.ClassifierEnabled,
	}

	if !c.enabled {
		if c.logger != nil {
			c.logger.Info("FlowTracker client disabled")
		}
		return c
	}

	if c.logger != nil {
		c.logger.Info("FlowTracker client initialized", zap.String("addr", addr))
	}

	return c
}

type QueryRequest struct {
	FlowID string `json:"flow_id"`
}

type QueryResponse struct {
	Found          bool   `json:"found"`
	Protocol       string `json:"protocol"`
	MasterProtocol string `json:"master_protocol"`
	Category       uint32 `json:"category"`
}

func (c *Client) QueryFlow(ctx context.Context, flowID string) (proto, masterProto string, category uint32, found bool, err error) {
	if !c.enabled {
		return "", "", 0, false, fmt.Errorf("FlowTracker not available")
	}

	conn, err := net.DialTimeout("tcp", c.addr, 5*time.Second)
	if err != nil {
		return "", "", 0, false, fmt.Errorf("dial failed: %w", err)
	}
	defer conn.Close()

	req := QueryRequest{FlowID: flowID}
	data, err := json.Marshal(req)
	if err != nil {
		return "", "", 0, false, fmt.Errorf("marshal failed: %w", err)
	}

	conn.SetWriteDeadline(time.Now().Add(c.timeout))
	if _, err := conn.Write(data); err != nil {
		return "", "", 0, false, fmt.Errorf("write failed: %w", err)
	}

	conn.SetReadDeadline(time.Now().Add(c.timeout))
	respBuf := make([]byte, 4096)
	n, err := conn.Read(respBuf)
	if err != nil {
		if err == io.EOF {
			return "", "", 0, false, fmt.Errorf("connection closed")
		}
		return "", "", 0, false, fmt.Errorf("read failed: %w", err)
	}

	var resp QueryResponse
	if err := json.Unmarshal(respBuf[:n], &resp); err != nil {
		return "", "", 0, false, fmt.Errorf("unmarshal failed: %w", err)
	}

	return resp.Protocol, resp.MasterProtocol, resp.Category, resp.Found, nil
}

func (c *Client) IsEnabled() bool {
	return c.enabled
}

func (c *Client) Close() error {
	return nil
}
