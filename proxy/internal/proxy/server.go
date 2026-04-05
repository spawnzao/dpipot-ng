package proxy

import (
	"fmt"
	"net"
	"time"

	"github.com/google/uuid"
	"github.com/spawnzao/dpipot-ng/proxy/internal/kafka"
	"github.com/spawnzao/dpipot-ng/proxy/internal/ndpi"
	"github.com/spawnzao/dpipot-ng/proxy/internal/router"
	"go.uber.org/zap"
)

// Server aceita conexões TCP e cria um Handler por conexão.
// Cada Handler roda em goroutine separada — o server nunca bloqueia.
type Server struct {
	listenAddr      string
	ndpiClient      *ndpi.Client
	router          *router.Router
	producer        *kafka.Producer
	maxPayloadBytes int64
	log             *zap.Logger
}

func NewServer(
	listenAddr string,
	ndpiClient *ndpi.Client,
	r *router.Router,
	producer *kafka.Producer,
	maxPayloadBytes int64,
	log *zap.Logger,
) *Server {
	return &Server{
		listenAddr:      listenAddr,
		ndpiClient:      ndpiClient,
		router:          r,
		producer:        producer,
		maxPayloadBytes: maxPayloadBytes,
		log:             log,
	}
}

// ListenAndServe abre o listener TCP e aceita conexões indefinidamente.
// Bloqueia até que o listener seja fechado (graceful shutdown via contexto).
func (s *Server) ListenAndServe() error {
	ln, err := net.Listen("tcp", s.listenAddr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", s.listenAddr, err)
	}
	defer ln.Close()

	s.log.Info("proxy escutando", zap.String("addr", s.listenAddr))

	for {
		conn, err := ln.Accept()
		if err != nil {
			// listener fechado — shutdown gracioso
			return fmt.Errorf("accept: %w", err)
		}

		// cada conexão roda em goroutine própria
		// goroutines Go são leves (~2KB de stack) — suporta milhares simultâneas
		go s.handle(conn)
	}
}

func (s *Server) handle(conn net.Conn) {
	// configura keepalive TCP para detectar conexões mortas
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(30 * time.Second)
	}

	flowID := uuid.New().String()

	h := NewHandler(
		flowID,
		conn,
		s.ndpiClient,
		s.router,
		s.producer,
		s.maxPayloadBytes,
		s.log.With(zap.String("flow_id", flowID)),
	)
	h.Handle()
}
