package flowtracker

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/spawnzao/dpipot-ng/proxy/internal/config"
	"go.uber.org/zap"
)

const connPoolSize = 8

type Client struct {
	addr    string
	timeout time.Duration
	logger  *zap.Logger
	enabled bool
	pool    chan net.Conn

	// contadores de telemetria — lidos e zerados pelo heartbeat via StatsAndReset
	cntTimeouts    atomic.Int64
	cntNotFound    atomic.Int64
	cntUnknown     atomic.Int64
}

// FlowTrackerStats agrupa os contadores do período desde o último reset.
type FlowTrackerStats struct {
	Timeouts    int64
	NotFound    int64
	UnknownProto int64
}

// StatsAndReset retorna os contadores acumulados e os zera atomicamente.
func (c *Client) StatsAndReset() FlowTrackerStats {
	if c == nil {
		return FlowTrackerStats{}
	}
	return FlowTrackerStats{
		Timeouts:    c.cntTimeouts.Swap(0),
		NotFound:    c.cntNotFound.Swap(0),
		UnknownProto: c.cntUnknown.Swap(0),
	}
}

func NewClient(cfg config.Config, logger *zap.Logger) *Client {
	addr := fmt.Sprintf("%s:%d", cfg.ClassifierHost, cfg.ClassifierPort)

	// Usa FLOWTRACKER_TTL como timeout da query (antes era hardcoded em 100ms).
	timeout := cfg.FlowTrackerTTL
	if timeout <= 0 {
		timeout = 100 * time.Millisecond
	}

	c := &Client{
		addr:    addr,
		timeout: timeout,
		logger:  logger,
		enabled: cfg.ClassifierEnabled,
		pool:    make(chan net.Conn, connPoolSize),
	}

	if !c.enabled {
		if c.logger != nil {
			c.logger.Info("FlowTracker client disabled")
		}
		return c
	}

	if c.logger != nil {
		c.logger.Info("FlowTracker client initialized",
			zap.String("addr", addr),
			zap.Duration("query_timeout", timeout),
		)
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
	FlowUUID       string `json:"flow_uuid,omitempty"`
}

func (c *Client) getConn() (net.Conn, error) {
	select {
	case conn := <-c.pool:
		return conn, nil
	default:
		return net.DialTimeout("tcp", c.addr, 5*time.Second)
	}
}

func (c *Client) putConn(conn net.Conn) {
	conn.SetDeadline(time.Time{}) // limpa deadline antes de devolver ao pool
	select {
	case c.pool <- conn:
	default:
		conn.Close() // pool cheio, descarta
	}
}

func (c *Client) doQuery(conn net.Conn, flowID string) (proto, masterProto string, category uint32, flowUUID string, found bool, err error) {
	req := QueryRequest{FlowID: flowID}
	data, err := json.Marshal(req)
	if err != nil {
		return "", "", 0, "", false, fmt.Errorf("marshal failed: %w", err)
	}

	conn.SetWriteDeadline(time.Now().Add(c.timeout))
	if _, err := conn.Write(data); err != nil {
		return "", "", 0, "", false, fmt.Errorf("write failed: %w", err)
	}

	conn.SetReadDeadline(time.Now().Add(c.timeout))
	respBuf := make([]byte, 4096)
	n, err := conn.Read(respBuf)
	if err != nil {
		if err == io.EOF {
			return "", "", 0, "", false, fmt.Errorf("connection closed")
		}
		return "", "", 0, "", false, fmt.Errorf("read failed: %w", err)
	}

	var resp QueryResponse
	if err := json.Unmarshal(respBuf[:n], &resp); err != nil {
		return "", "", 0, "", false, fmt.Errorf("unmarshal failed: %w", err)
	}

	return resp.Protocol, resp.MasterProtocol, resp.Category, resp.FlowUUID, resp.Found, nil
}

func (c *Client) QueryFlow(flowID string) (proto, masterProto string, category uint32, flowUUID string, found bool, err error) {
	if !c.enabled {
		return "", "", 0, "", false, fmt.Errorf("FlowTracker not available")
	}

	start := time.Now()

	// Tenta reusar conexão do pool; se estiver stale, abre uma nova.
	for attempt := 0; attempt < 2; attempt++ {
		conn, dialErr := c.getConn()
		if dialErr != nil {
			return "", "", 0, "", false, fmt.Errorf("dial failed: %w", dialErr)
		}

		proto, masterProto, category, flowUUID, found, err = c.doQuery(conn, flowID)
		if err != nil {
			conn.Close()
			if attempt == 0 {
				// Conexão stale do pool; tenta com uma nova.
				continue
			}
			// Falha definitiva: identifica se foi timeout e incrementa contador.
			elapsed := time.Since(start)
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				c.cntTimeouts.Add(1)
				if c.logger != nil {
					c.logger.Warn("FlowTracker query timeout",
						zap.String("flow_id", flowID),
						zap.Duration("elapsed", elapsed),
						zap.Duration("timeout_cfg", c.timeout),
					)
				}
			}
			return "", "", 0, "", false, err
		}

		elapsed := time.Since(start)

		if !found {
			c.cntNotFound.Add(1)
			if c.logger != nil {
				c.logger.Debug("FlowTracker: fluxo não encontrado (nDPI ainda classificando)",
					zap.String("flow_id", flowID),
					zap.Duration("elapsed", elapsed),
				)
			}
		} else if proto == "" || strings.ToUpper(proto) == "UNKNOWN" {
			c.cntUnknown.Add(1)
			if c.logger != nil {
				c.logger.Debug("FlowTracker: protocolo UNKNOWN (nDPI não conseguiu classificar)",
					zap.String("flow_id", flowID),
					zap.Duration("elapsed", elapsed),
				)
			}
		} else if c.logger != nil && elapsed > c.timeout/2 {
			// Log quando latência > 50% do timeout, mesmo que tenha sucesso
			c.logger.Warn("FlowTracker query lenta",
				zap.String("flow_id", flowID),
				zap.Duration("elapsed", elapsed),
				zap.Duration("timeout_cfg", c.timeout),
			)
		}

		c.putConn(conn)
		return proto, masterProto, category, flowUUID, found, nil
	}

	return "", "", 0, "", false, fmt.Errorf("query failed after retries")
}

func (c *Client) IsEnabled() bool {
	return c.enabled
}

func (c *Client) Close() error {
	for {
		select {
		case conn := <-c.pool:
			conn.Close()
		default:
			return nil
		}
	}
}
