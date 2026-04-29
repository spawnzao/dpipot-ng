package proxy

import (
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"

	"github.com/google/uuid"
	"github.com/spawnzao/dpipot-ng/proxy/internal/flowtracker"
	"github.com/spawnzao/dpipot-ng/proxy/internal/httpclassifier"
	"github.com/spawnzao/dpipot-ng/proxy/internal/kafka"
	"github.com/spawnzao/dpipot-ng/proxy/internal/mitm"
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
	flowTracker     *flowtracker.Client
	certMgr         *mitm.CertManager
	serverFirstPorts map[uint16]string
	serverFirstPortsTLS map[uint16]string
	httpAuthPorts map[uint16]bool
	httpAuthPortsTLS map[uint16]bool
	httpClassifier *httpclassifier.Classifier
}

func NewServer(
	listenAddr string,
	ndpiClient *ndpi.Client,
	r *router.Router,
	producer *kafka.Producer,
	maxPayloadBytes int64,
	log *zap.Logger,
	flowTracker *flowtracker.Client,
	certMgr *mitm.CertManager,
	serverFirstPorts map[uint16]string,
	serverFirstPortsTLS map[uint16]string,
	httpAuthPorts map[uint16]bool,
	httpAuthPortsTLS map[uint16]bool,
	httpClassifier *httpclassifier.Classifier,
) *Server {
	return &Server{
		listenAddr:      listenAddr,
		ndpiClient:      ndpiClient,
		router:          r,
		producer:        producer,
		maxPayloadBytes: maxPayloadBytes,
		log:             log,
		flowTracker:     flowTracker,
		certMgr:         certMgr,
		serverFirstPorts: serverFirstPorts,
		serverFirstPortsTLS: serverFirstPortsTLS,
		httpAuthPorts:      httpAuthPorts,
		httpAuthPortsTLS:    httpAuthPortsTLS,
		httpClassifier:   httpClassifier,
	}
}

// listenTransparent cria um listener TCP com IP_TRANSPARENT habilitado.
// Necessário para TPROXY - permite bind em IPs não-locais.
func listenTransparent(addr string) (net.Listener, error) {
	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("resolve addr: %w", err)
	}

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		return nil, fmt.Errorf("socket: %w", err)
	}

	if err := syscall.SetsockoptInt(fd, syscall.SOL_IP, syscall.IP_TRANSPARENT, 1); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("setsockopt IP_TRANSPARENT: %w", err)
	}

	// Bind em 0.0.0.0 para capturar conexões locais
	sa := &syscall.SockaddrInet4{Port: tcpAddr.Port, Addr: [4]byte{0, 0, 0, 0}}

	if err := syscall.Bind(fd, sa); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("bind 0.0.0.0:%d: %w", tcpAddr.Port, err)
	}

	if err := syscall.Listen(fd, 128); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("listen: %w", err)
	}

	f := os.NewFile(uintptr(fd), "tproxy-listener")
	return net.FileListener(f)
}

// ListenAndServe abre o listener TCP e aceita conexões indefinidamente.
// Bloqueia até que o listener seja fechado (graceful shutdown via contexto).
func (s *Server) ListenAndServe() error {
	ln, err := listenTransparent(s.listenAddr)
	if err != nil {
		return fmt.Errorf("listen transparent %s: %w", s.listenAddr, err)
	}
	defer ln.Close()

	s.log.Info("proxy escutando", zap.String("addr", s.listenAddr))

	for {
		conn, err := ln.Accept()
		if err != nil {
			s.log.Warn("accept error", zap.Error(err))
			if strings.Contains(err.Error(), "use of closed network connection") {
				return nil
			}
			continue
		}

		remoteAddr := conn.RemoteAddr().String()
		s.log.Info("🎯 Conexão aceita",
			zap.String("local_addr", conn.LocalAddr().String()),
			zap.String("remote_addr", remoteAddr),
		)

		go s.handle(conn)
	}
}

func (s *Server) handle(conn net.Conn) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("handler recovered from panic", zap.Any("panic", r))
		}
		conn.Close()
	}()

	flowID := uuid.New().String()
	log := s.log.With(zap.String("flow_id", flowID))

	log.Debug("🔌Handler started!",
		zap.String("local_addr", conn.LocalAddr().String()),
		zap.String("remote_addr", conn.RemoteAddr().String()),
	)

	h := NewHandler(
		flowID,
		conn,
		s.ndpiClient,
		s.router,
		s.producer,
		s.maxPayloadBytes,
		log,
		s.flowTracker,
		s.certMgr,
		s.serverFirstPorts,
		s.serverFirstPortsTLS,
		s.httpAuthPorts,
		s.httpAuthPortsTLS,
		s.httpClassifier,
	)
	h.Handle()

	log.Info("handler finished")
}
