package proxy

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/spawnzao/dpipot-ng/proxy/internal/kafka"
	"github.com/spawnzao/dpipot-ng/proxy/internal/ndpi"
	"github.com/spawnzao/dpipot-ng/proxy/internal/router"
	"go.uber.org/zap"
)

const (
	// tamanho do buffer inicial para classificação nDPI
	// lemos até 4KB do primeiro chunk antes de rotear
	classifyBufferSize = 4096

	// timeout para conectar ao honeypot
	honeypotDialTimeout = 5 * time.Second

	// tamanho do buffer de cópia do pipe
	pipeBufferSize = 32 * 1024 // 32KB
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

// Handle é o ciclo de vida completo de uma conexão:
//
//  1. Lê o primeiro chunk do atacante
//  2. Classifica com nDPI
//  3. Conecta ao honeypot correto
//  4. Reenvia o primeiro chunk para o honeypot
//  5. Pipe bidirecional com TeeReader para capturar payload
//  6. Publica evento no Kafka ao final
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
	h.conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	n, err := h.conn.Read(firstChunk)
	h.conn.SetReadDeadline(time.Time{}) // remove deadline após leitura inicial
	if err != nil {
		if err != io.EOF {
			log.Debug("erro lendo primeiro chunk", zap.Error(err))
		}
		return
	}
	firstChunk = firstChunk[:n]

	// --- STEP 2: classifica com nDPI ---
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	ndpiLabel, err := h.ndpi.Classify(ctx, h.flowID, firstChunk)
	if err != nil {
		log.Warn("nDPI classify falhou, usando Unknown", zap.Error(err))
		ndpiLabel = "Unknown"
	}
	log.Info("fluxo classificado", zap.String("proto", ndpiLabel))

	// --- STEP 3: resolve honeypot pelo label ---
	honeypotAddr, _ := h.router.Resolve(ndpiLabel)

	// --- STEP 4: conecta ao honeypot ---
	honeypotConn, err := net.DialTimeout("tcp", honeypotAddr, honeypotDialTimeout)
	if err != nil {
		log.Error("falha conectando ao honeypot",
			zap.String("honeypot", honeypotAddr),
			zap.Error(err),
		)
		return
	}
	defer honeypotConn.Close()

	// --- STEP 5: reenvia o primeiro chunk para o honeypot ---
	if _, err := honeypotConn.Write(firstChunk); err != nil {
		log.Error("erro reenviando primeiro chunk", zap.Error(err))
		return
	}

	// --- STEP 6: pipe bidirecional com captura de payload ---

	// buffers para acumular payload de cada direção
	var (
		bufSrc bytes.Buffer // atacante → honeypot
		bufDst bytes.Buffer // honeypot → atacante
	)

	// já temos o primeiro chunk do atacante
	bufSrc.Write(firstChunk)

	// writers que capturam os bytes enquanto copiam
	// limitWriter garante que não acumulamos mais do que maxPayloadBytes
	teeWriterSrc := newLimitedTeeWriter(&bufSrc, h.maxPayloadBytes)
	teeWriterDst := newLimitedTeeWriter(&bufDst, h.maxPayloadBytes)

	startTime := time.Now()
	var wg sync.WaitGroup
	wg.Add(2)

	// goroutine 1: atacante → honeypot (com cópia para bufSrc)
	go func() {
		defer wg.Done()
		defer honeypotConn.(*net.TCPConn).CloseWrite()
		// TeeReader: lê de conn, copia para teeWriterSrc, passa para honeypotConn
		src := io.TeeReader(h.conn, teeWriterSrc)
		if _, err := io.Copy(honeypotConn, src); err != nil {
			log.Debug("pipe src→dst encerrado", zap.Error(err))
		}
	}()

	// goroutine 2: honeypot → atacante (com cópia para bufDst)
	go func() {
		defer wg.Done()
		defer h.conn.(*net.TCPConn).CloseWrite()
		src := io.TeeReader(honeypotConn, teeWriterDst)
		if _, err := io.Copy(h.conn, src); err != nil {
			log.Debug("pipe dst→src encerrado", zap.Error(err))
		}
	}()

	wg.Wait()
	duration := time.Since(startTime)

	// --- STEP 7: publica evento no Kafka (assíncrono, não bloqueia) ---
	event := &kafka.Event{
		FlowID:      h.flowID,
		Timestamp:   time.Now(),
		SrcIP:       srcAddr.IP.String(),
		SrcPort:     srcAddr.Port,
		DstPort:     dstAddr.Port,
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
