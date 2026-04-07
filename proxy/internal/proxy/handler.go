package proxy

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/spawnzao/dpipot-ng/proxy/internal/kafka"
	"github.com/spawnzao/dpipot-ng/proxy/internal/ndpi"
	"github.com/spawnzao/dpipot-ng/proxy/internal/router"
	"go.uber.org/zap"
	"golang.org/x/net/ipv4"
)

const (
	classifyBufferSize    = 4096
	honeypotDialTimeout  = 5 * time.Second
	pipeBufferSize       = 32 * 1024
	originalDstTimeout   = 2 * time.Second
)

// Handler processa uma única conexão TCP de um atacante.
// É criado um Handler por conexão, rodando em goroutine separada.
type Handler struct {
	flowID   string
	conn     net.Conn
	ndpi     *ndpi.Client
	router   *router.Router
	producer *kafka.Producer
	log      *zap.Logger

	// captura dos payloads para o Kafka
	maxPayloadBytes int64
}

func NewHandler(
	flowID string,
	conn net.Conn,
	ndpiClient *ndpi.Client,
	r *router.Router,
	producer *kafka.Producer,
	maxPayloadBytes int64,
	log *zap.Logger,
) *Handler {
	return &Handler{
		flowID:          flowID,
		conn:            conn,
		ndpi:            ndpiClient,
		router:          r,
		producer:        producer,
		maxPayloadBytes: maxPayloadBytes,
		log:             log,
	}
}

// getOriginalDst obtém o IP e porta originais de destino usando
// getsockopt(IP_ORIGINAL_DST) no Linux.
// Funciona com REDIRECT.
func getOriginalDst(conn net.Conn) (net.IP, uint16, error) {
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return nil, 0, fmt.Errorf("não é uma conexão TCP")
	}

	file, err := tcpConn.File()
	if err != nil {
		return nil, 0, fmt.Errorf("File(): %w", err)
	}
	defer file.Close()

	fd := int(file.Fd())

	var addr syscall.RawSockaddrInet4
	var addrLen uint32 = syscall.SizeofSockaddrInet4

	// IP_ORIGINAL_DST = 80, SOL_IP = 0
	// syscall.Getsockoptbyte não funciona para structs, usar Syscall6 diretamente
	_, _, errno := syscall.Syscall6(
		syscall.SYS_GETSOCKOPT,
		uintptr(fd),
		uintptr(syscall.SOL_IP),
		uintptr(80), // IP_ORIGINAL_DST
		uintptr(unsafe.Pointer(&addr)),
		uintptr(unsafe.Pointer(&addrLen)),
		0,
	)
	if errno != 0 {
		return nil, 0, fmt.Errorf("getsockopt IP_ORIGINAL_DST: %v", errno)
	}

	ip := net.IP(addr.Addr[:])
	port := binary.BigEndian.Uint16((*[2]byte)(unsafe.Pointer(&addr.Port))[:])

	return ip, port, nil
}

// getTproxyDst obtém o IP e porta originais quando o tráfego vem via TPROXY.
// Usa IP_PKTINFO para obter o endereço de destino original do pacote.
func getTproxyDst(conn net.Conn) (net.IP, uint16, error) {
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return nil, 0, fmt.Errorf("não é uma conexão TCP")
	}

	file, err := tcpConn.File()
	if err != nil {
		return nil, 0, fmt.Errorf("File(): %w", err)
	}
	defer file.Close()

	fd := int(file.Fd())
	pc := ipv4.NewConn(file)

	dstIP, err := pc.DestinationAddress()
	if err != nil {
		return nil, 0, fmt.Errorf("IP_PKTINFO: %w", err)
	}

	localAddr := pc.LocalAddr()
	if localAddr == nil {
		return nil, 0, fmt.Errorf("LocalAddr returned nil")
	}

	port := uint16(localAddr.(*net.TCPAddr).Port)

	return net.IP(dstIP), port, nil
}

// Handle é o ciclo de vida completo de uma conexão:
//
//  1. Lê o primeiro chunk do atacante
//  2. Obtém IP/porta original via getsockopt
//  3. Classifica com nDPI
//  4. Resolve honeypot pelo label
//  5. Tenta conectar ao honeypot (pode falhar)
//  6. Se conectado: pipe bidirecional com captura de payload
//  7. Sempre: publica evento no Kafka (mesmo se honeypot falhar)
func (h *Handler) Handle() {
	defer h.conn.Close()

	srcAddr := h.conn.RemoteAddr().(*net.TCPAddr)
	dstAddr := h.conn.LocalAddr().(*net.TCPAddr)

	log := h.log.With(
		zap.String("flow_id", h.flowID),
		zap.String("src", srcAddr.String()),
	)

	// variáveis para o evento
	var (
		bufSrc       bytes.Buffer
		bufDst       bytes.Buffer
		ndpiLabel    = "Unknown"
		honeypotAddr string
		honeypotError string
		startTime     time.Time
	)
	var origDstIP net.IP
	var origDstPort uint16

	// --- STEP 1: lê primeiro chunk para classificação ---
	firstChunk := make([]byte, classifyBufferSize)
	h.conn.SetReadDeadline(time.Now().Add(originalDstTimeout))
	n, err := h.conn.Read(firstChunk)
	h.conn.SetReadDeadline(time.Time{})
	if err != nil {
		if err != io.EOF {
			log.Debug("erro lendo primeiro chunk", zap.Error(err))
		}
		honeypotError = fmt.Sprintf("read error: %v", err)
		goto publish
	}
	firstChunk = firstChunk[:n]
	bufSrc.Write(firstChunk)

	// --- STEP 2: obtém IP/porta original ---
	// Primeiro tenta TPROXY (IP_PKTINFO), depois REDIRECT (IP_ORIGINAL_DST)
	origDstIP, origDstPort, err = getTproxyDst(h.conn)
	if err != nil {
		log.Debug("TPROXY não disponível, tentando REDIRECT", zap.Error(err))
		origDstIP, origDstPort, err = getOriginalDst(h.conn)
		if err != nil {
			log.Warn("falha obtendo original dst, usando local addr",
				zap.Error(err),
				zap.Stringer("local", dstAddr),
			)
			origDstIP = dstAddr.IP
			origDstPort = uint16(dstAddr.Port)
		}
	}

	flowInfo := &ndpi.FlowInfo{
		SrcIP:   srcAddr.IP,
		SrcPort: uint16(srcAddr.Port),
		DstIP:   origDstIP,
		DstPort: origDstPort,
	}

	log.Debug("informações do fluxo",
		zap.String("src_ip", flowInfo.SrcIP.String()),
		zap.Uint16("src_port", flowInfo.SrcPort),
		zap.String("dst_ip", flowInfo.DstIP.String()),
		zap.Uint16("dst_port", flowInfo.DstPort),
	)

	// --- STEP 3: classifica com nDPI ---
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	ndpiLabel, err = h.ndpi.Classify(ctx, h.flowID, firstChunk, flowInfo)
	if err != nil {
		log.Warn("nDPI classify falhou, usando Unknown", zap.Error(err))
		ndpiLabel = "Unknown"
	}
	log.Info("fluxo classificado", zap.String("proto", ndpiLabel))

	// --- STEP 4: resolve honeypot pelo label nDPI ---
	honeypotAddr, _ = h.router.Resolve(ndpiLabel)

	// --- STEP 5: tenta conectar ao honeypot ---
	honeypotConn, err := net.DialTimeout("tcp", honeypotAddr, honeypotDialTimeout)
	if err != nil {
		log.Error("falha conectando ao honeypot",
			zap.String("honeypot", honeypotAddr),
			zap.Error(err),
		)
		honeypotError = fmt.Sprintf("connection failed: %v", err)
		goto publish
	}
	defer honeypotConn.Close()

	// --- STEP 6: reenvia o primeiro chunk para o honeypot ---
	if _, err := honeypotConn.Write(firstChunk); err != nil {
		log.Error("erro reenviando primeiro chunk", zap.Error(err))
		honeypotError = fmt.Sprintf("write failed: %v", err)
		goto publish
	}

	// --- STEP 7: pipe bidirecional com captura de payload ---
	teeWriterSrc := newLimitedTeeWriter(&bufSrc, h.maxPayloadBytes)
	teeWriterDst := newLimitedTeeWriter(&bufDst, h.maxPayloadBytes)

	startTime = time.Now()
	var wg sync.WaitGroup
	wg.Add(2)

	// goroutine 1: atacante → honeypot
	go func() {
		defer wg.Done()
		if tcpConn, ok := honeypotConn.(*net.TCPConn); ok {
			tcpConn.CloseWrite()
		}
		src := io.TeeReader(h.conn, teeWriterSrc)
		if _, err := io.Copy(honeypotConn, src); err != nil {
			log.Debug("pipe src→dst encerrado", zap.Error(err))
		}
	}()

	// goroutine 2: honeypot → atacante
	go func() {
		defer wg.Done()
		if tcpConn, ok := h.conn.(*net.TCPConn); ok {
			tcpConn.CloseWrite()
		}
		src := io.TeeReader(honeypotConn, teeWriterDst)
		if _, err := io.Copy(h.conn, src); err != nil {
			log.Debug("pipe dst→src encerrado", zap.Error(err))
		}
	}()

	wg.Wait()

publish:
	// --- STEP 8: sempre publica evento no Kafka (mesmo se honeypot falhou) ---
	duration := time.Since(startTime)
	event := &kafka.Event{
		FlowID:      h.flowID,
		Timestamp:   time.Now(),
		SrcIP:       srcAddr.IP.String(),
		SrcPort:     srcAddr.Port,
		DstIP:       origDstIP.String(),
		DstPort:     int(origDstPort),
		NDPIProto:   ndpiLabel,
		NDPIApp:     "",
		Honeypot:    honeypotAddr,
		HoneypotError: honeypotError,
		PayloadSrc:  bufSrc.Bytes(),
		PayloadDst:  bufDst.Bytes(),
		PayloadSize: int64(bufSrc.Len() + bufDst.Len()),
	}
	h.producer.Publish(event)

	if honeypotError != "" {
		log.Info("fluxo encerrado com erro",
			zap.String("proto", ndpiLabel),
			zap.String("honeypot", honeypotAddr),
			zap.String("error", honeypotError),
			zap.Int("payload_src_bytes", bufSrc.Len()),
		)
	} else {
		log.Info("fluxo encerrado",
			zap.String("proto", ndpiLabel),
			zap.String("honeypot", honeypotAddr),
			zap.Int("payload_src_bytes", bufSrc.Len()),
			zap.Int("payload_dst_bytes", bufDst.Len()),
			zap.Duration("duration", duration),
		)
	}
}

// limitedTeeWriter é um io.Writer que copia para um buffer
// até o limite de bytes configurado, depois descarta silenciosamente.
// Isso evita OOM se um atacante mandar um payload enorme.
type limitedTeeWriter struct {
	buf     *bytes.Buffer
	limit   int64
	written int64
}

func newLimitedTeeWriter(buf *bytes.Buffer, limit int64) *limitedTeeWriter {
	return &limitedTeeWriter{buf: buf, limit: limit}
}

func (w *limitedTeeWriter) Write(p []byte) (int, error) {
	if w.limit > 0 && w.written >= w.limit {
		// limite atingido: descarta mas reporta sucesso
		// (se retornarmos erro aqui o pipe para)
		return len(p), nil
	}
	if w.limit > 0 {
		remaining := w.limit - w.written
		if int64(len(p)) > remaining {
			p = p[:remaining]
		}
	}
	n, err := w.buf.Write(p)
	w.written += int64(n)
	if err != nil {
		return n, fmt.Errorf("limitedTeeWriter: %w", err)
	}
	return len(p), nil // retorna len original, não o truncado
}
