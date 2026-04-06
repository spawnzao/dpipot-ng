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
// Necessário quando o tráfego é redirecionado via TPROXY/iptables.
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

// Handle é o ciclo de vida completo de uma conexão:
//
//  1. Lê o primeiro chunk do atacante
//  2. Obtém IP/porta original via getsockopt
//  3. Classifica com nDPI
//  4. Conecta ao honeypot correto
//  5. Reenvia o primeiro chunk para o honeypot
//  6. Pipe bidirecional com TeeReader para capturar payload
//  7. Publica evento no Kafka ao final
func (h *Handler) Handle() {
	defer h.conn.Close()

	srcAddr := h.conn.RemoteAddr().(*net.TCPAddr)
	dstAddr := h.conn.LocalAddr().(*net.TCPAddr)

	log := h.log.With(
		zap.String("flow_id", h.flowID),
		zap.String("src", srcAddr.String()),
	)

	// --- STEP 1: lê primeiro chunk para classificação ---
	firstChunk := make([]byte, classifyBufferSize)
	h.conn.SetReadDeadline(time.Now().Add(originalDstTimeout))
	n, err := h.conn.Read(firstChunk)
	h.conn.SetReadDeadline(time.Time{})
	if err != nil {
		if err != io.EOF {
			log.Debug("erro lendo primeiro chunk", zap.Error(err))
		}
		return
	}
	firstChunk = firstChunk[:n]

	// --- STEP 2: obtém IP/porta original via getsockopt ---
	origDstIP, origDstPort, err := getOriginalDst(h.conn)
	if err != nil {
		log.Warn("falha obtendo original dst, usando local addr",
			zap.Error(err),
			zap.Stringer("local", dstAddr),
		)
		origDstIP = dstAddr.IP
		origDstPort = uint16(dstAddr.Port)
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

	ndpiLabel, err := h.ndpi.Classify(ctx, h.flowID, firstChunk, flowInfo)
	if err != nil {
		log.Warn("nDPI classify falhou, usando Unknown", zap.Error(err))
		ndpiLabel = "Unknown"
	}
	log.Info("fluxo classificado", zap.String("proto", ndpiLabel))

	// --- STEP 4: resolve honeypot pelo label ---
	honeypotAddr, _ := h.router.Resolve(ndpiLabel)

	// --- STEP 5: conecta ao honeypot ---
	honeypotConn, err := net.DialTimeout("tcp", honeypotAddr, honeypotDialTimeout)
	if err != nil {
		log.Error("falha conectando ao honeypot",
			zap.String("honeypot", honeypotAddr),
			zap.Error(err),
		)
		return
	}
	defer honeypotConn.Close()

	// --- STEP 6: reenvia o primeiro chunk para o honeypot ---
	if _, err := honeypotConn.Write(firstChunk); err != nil {
		log.Error("erro reenviando primeiro chunk", zap.Error(err))
		return
	}

	// --- STEP 7: pipe bidirecional com captura de payload ---
	var (
		bufSrc bytes.Buffer
		bufDst bytes.Buffer
	)

	bufSrc.Write(firstChunk)

	teeWriterSrc := newLimitedTeeWriter(&bufSrc, h.maxPayloadBytes)
	teeWriterDst := newLimitedTeeWriter(&bufDst, h.maxPayloadBytes)

	startTime := time.Now()
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
	duration := time.Since(startTime)

	// --- STEP 8: publica evento no Kafka ---
	event := &kafka.Event{
		FlowID:      h.flowID,
		Timestamp:   time.Now(),
		SrcIP:       flowInfo.SrcIP.String(),
		SrcPort:     int(flowInfo.SrcPort),
		DstPort:     int(flowInfo.DstPort),
		NDPIProto:   ndpiLabel,
		NDPIApp:     "",
		Honeypot:    honeypotAddr,
		PayloadSrc:  bufSrc.Bytes(),
		PayloadDst:  bufDst.Bytes(),
		PayloadSize: int64(bufSrc.Len() + bufDst.Len()),
	}
	h.producer.Publish(event)

	log.Info("fluxo encerrado",
		zap.String("proto", ndpiLabel),
		zap.String("honeypot", honeypotAddr),
		zap.Int("payload_src_bytes", bufSrc.Len()),
		zap.Int("payload_dst_bytes", bufDst.Len()),
		zap.Duration("duration", duration),
	)
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
