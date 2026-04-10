package flowtracker

import (
	"encoding/binary"
	"encoding/json"
	"net"
	"time"

	"github.com/spawnzao/dpipot-ng/classifier/internal/flow"
	"go.uber.org/zap"
)

type Server struct {
	flowTable *flow.Table
	logger    *zap.Logger
	listener  net.Listener
	stopCh    chan struct{}
}

type ServerConfig struct {
	FlowTable  *flow.Table
	Logger     *zap.Logger
	ListenAddr string
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

func NewServer(cfg ServerConfig) *Server {
	return &Server{
		flowTable: cfg.FlowTable,
		logger:    cfg.Logger,
		stopCh:    make(chan struct{}),
	}
}

func (s *Server) Start(addr string) error {
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	s.listener = lis

	if s.logger != nil {
		s.logger.Info("FlowTracker TCP server started", zap.String("addr", addr))
	}

	for {
		select {
		case <-s.stopCh:
			return nil
		default:
			conn, err := lis.Accept()
			if err != nil {
				select {
				case <-s.stopCh:
					return nil
				default:
					if s.logger != nil {
						s.logger.Error("failed to accept connection", zap.Error(err))
					}
					continue
				}
			}
			go s.handleConnection(conn)
		}
	}
}

func (s *Server) handleConnection(conn net.Conn) {
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(30 * time.Second))

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		if s.logger != nil {
			s.logger.Debug("failed to read request", zap.Error(err))
		}
		return
	}

	var req QueryRequest
	if err := json.Unmarshal(buf[:n], &req); err != nil {
		if s.logger != nil {
			s.logger.Debug("failed to parse request", zap.Error(err))
		}
		return
	}

	entry, ok := s.flowTable.Get(req.FlowID)
	if !ok {
		resp := QueryResponse{Found: false}
		data, _ := json.Marshal(resp)
		conn.Write(data)
		return
	}

	resp := QueryResponse{
		Found:          true,
		Protocol:       entry.Protocol,
		MasterProtocol: entry.MasterProtocol,
		Category:       entry.Category,
	}
	data, _ := json.Marshal(resp)

	length := uint16(len(data))
	binary.Write(conn, binary.BigEndian, length)
	conn.Write(data)
}

func (s *Server) Stop() {
	close(s.stopCh)
	if s.listener != nil {
		s.listener.Close()
	}
}

type Client struct {
	conn   net.Conn
	logger *zap.Logger
}

func NewClient(addr string, logger *zap.Logger) (*Client, error) {
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return nil, err
	}
	return &Client{conn: conn, logger: logger}, nil
}

func (c *Client) QueryFlow(flowID string) (*QueryResponse, error) {
	req := QueryRequest{FlowID: flowID}
	data, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	c.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.conn.Write(data); err != nil {
		return nil, err
	}

	c.conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	var resp QueryResponse
	if err := json.NewDecoder(c.conn).Decode(&resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) Close() error {
	return c.conn.Close()
}
