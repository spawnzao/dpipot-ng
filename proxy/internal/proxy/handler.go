package proxy

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/spawnzao/dpipot-ng/proxy/internal/flowtracker"
	"github.com/spawnzao/dpipot-ng/proxy/internal/kafka"
	"github.com/spawnzao/dpipot-ng/proxy/internal/mitm"
	"github.com/spawnzao/dpipot-ng/proxy/internal/ndpi"
	"github.com/spawnzao/dpipot-ng/proxy/internal/router"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
)

const (
	classifyBufferSize  = 4096
	honeypotDialTimeout = 5 * time.Second
	originalDstTimeout  = 2 * time.Second
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
	flowTracker     *flowtracker.Client
}

func NewHandler(
	flowID string,
	conn net.Conn,
	ndpiClient *ndpi.Client,
	r *router.Router,
	producer *kafka.Producer,
	maxPayloadBytes int64,
	log *zap.Logger,
	flowTracker *flowtracker.Client,
) *Handler {
	return &Handler{
		flowID:          flowID,
		conn:            conn,
		ndpi:            ndpiClient,
		router:          r,
		producer:        producer,
		maxPayloadBytes: maxPayloadBytes,
		log:             log,
		flowTracker:     flowTracker,
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
// Estrutura in_pktinfo: https://elixir.bootlin.com/linux/v5.15/source/include/uapi/linux/in.h#L240
type inPktInfo struct {
	ifIndex uint32
	specDst [4]byte
	addr    [4]byte
}

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

	// Tenta IP_PKTINFO primeiro
	var pktInfo inPktInfo
	var pktInfoLen uint32 = uint32(unsafe.Sizeof(pktInfo))

	_, _, errno := syscall.Syscall6(
		syscall.SYS_GETSOCKOPT,
		uintptr(fd),
		uintptr(syscall.SOL_IP),
		uintptr(25), // IP_PKTINFO
		uintptr(unsafe.Pointer(&pktInfo)),
		uintptr(unsafe.Pointer(&pktInfoLen)),
		0,
	)
	if errno != 0 {
		return nil, 0, fmt.Errorf("getsockopt IP_PKTINFO: %v", errno)
	}

	// specDst contém o IP de destino original antes do TPROXY
	ip := net.IP(pktInfo.specDst[:])

	// Se specDst for zero, usa o IP do conn local (addr do socket original)
	if ip.Equal(net.IPv4zero) {
		ip = net.IP(pktInfo.addr[:])
	}

	// Obtém a porta original usando IP_ORIGINAL_DSTADDR (20)
	var origDstAddr [4]byte
	var origDstLen uint32 = 4
	syscall.Syscall6(
		syscall.SYS_GETSOCKOPT,
		uintptr(fd),
		uintptr(syscall.SOL_IP),
		uintptr(20), // IP_ORIGINAL_DSTADDR
		uintptr(unsafe.Pointer(&origDstAddr)),
		uintptr(unsafe.Pointer(&origDstLen)),
		0,
	)
	origPort := uint16(origDstAddr[0])<<8 | uint16(origDstAddr[1])

	// Se a porta for 0, usa a porta local (porta do socket que recebeu a conexão)
	localAddr := conn.LocalAddr().(*net.TCPAddr)
	if origPort == 0 {
		origPort = uint16(localAddr.Port)
	}

	return ip, origPort, nil
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
		zap.Stringer("src", srcAddr),
		zap.Stringer("dst", dstAddr),
	)

	log.Info("🔍 Handle() iniciado")
	var (
		bufSrc           bytes.Buffer
		bufDst           bytes.Buffer
		ndpiLabel        = "Unknown"
		masterProtoFlow  = "Unknown"
		appProtoFlow     = "Unknown"
		honeypotAddr     string
		honeypotError    string
		startTime        time.Time
		wg               sync.WaitGroup
		teeWriterSrc     *limitedTeeWriter
		teeWriterDst     *limitedTeeWriter
		honeypotConn     net.Conn
		err              error
		n                int
		firstChunk       []byte
		ctx              context.Context
		cancel           context.CancelFunc
		origDstIP        net.IP
		origDstPort      uint16
		flowInfo         *ndpi.FlowInfo
		flowIDForTracker string
		isZeroIP         bool
	)

	// --- STEP 1: lê primeiro chunk para classificação ---
	firstChunk = make([]byte, classifyBufferSize)
	h.conn.SetReadDeadline(time.Now().Add(originalDstTimeout))
	n, err = h.conn.Read(firstChunk)
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
	isZeroIP = origDstIP != nil && origDstIP.IsUnspecified()
	if err != nil || isZeroIP {
		if err != nil {
			log.Debug("TPROXY não disponível, tentando REDIRECT", zap.Error(err))
		} else {
			log.Debug("TPROXY retornou IP inválido (0.0.0.0), tentando REDIRECT")
		}
		origDstIP, origDstPort, err = getOriginalDst(h.conn)
		isZeroIP = origDstIP != nil && origDstIP.IsUnspecified()
		if err != nil || isZeroIP {
			if err != nil {
				log.Debug("REDIRECT falhou, usando fallback",
					zap.Error(err),
					zap.Stringer("local", dstAddr),
				)
			} else {
				log.Debug("REDIRECT retornou IP inválido (0.0.0.0), usando fallback",
					zap.Stringer("local", dstAddr),
				)
			}
			// Fallback: usa dstAddr como origDst (o IP que o cliente Tentou alcançar)
			origDstIP = dstAddr.IP
			origDstPort = uint16(dstAddr.Port)
		}
	}

	log.Debug("IP original via TPROXY/REDIRECT",
		zap.Stringer("origDstIP", origDstIP),
		zap.Uint16("origDstPort", origDstPort),
		zap.Stringer("localAddr", dstAddr),
	)

	// Para nDPI, usa dstAddr diretamente (o IP/porta que o cliente tentou alcançar)
	flowInfo = &ndpi.FlowInfo{
		SrcIP:   srcAddr.IP,
		SrcPort: uint16(srcAddr.Port),
		DstIP:   dstAddr.IP,
		DstPort: uint16(dstAddr.Port),
	}

	log.Debug("informações do fluxo",
		zap.String("src_ip", flowInfo.SrcIP.String()),
		zap.Uint16("src_port", flowInfo.SrcPort),
		zap.String("dst_ip", flowInfo.DstIP.String()),
		zap.Uint16("dst_port", flowInfo.DstPort),
		zap.Stringer("origDstIP", origDstIP),
		zap.Uint16("origDstPort", origDstPort),
	)

	// --- STEP 3: classifica com nDPI (via FlowTracker ou local) ---
	flowIDForTracker = normalizeFlowID(flowInfo.SrcIP, flowInfo.DstIP, flowInfo.SrcPort, flowInfo.DstPort, 6)

	if h.flowTracker != nil && h.flowTracker.IsEnabled() {
		appProtoFlow, masterProtoFlow, _, found, err := h.flowTracker.QueryFlow(context.Background(), flowIDForTracker)
		if err == nil && found && appProtoFlow != "" {
			if appProtoFlow != "" && appProtoFlow != "Unknown" {
				ndpiLabel = appProtoFlow
			} else {
				ndpiLabel = masterProtoFlow
			}
			log.Info("fluxo classificado via FlowTracker",
				zap.String("ndpi_proto", masterProtoFlow),
				zap.String("ndpi_app", appProtoFlow),
				zap.String("flow_id", flowIDForTracker))
		} else {
			log.Debug("FlowTracker não tem classificação, usando nDPI local", zap.String("flow_id", flowIDForTracker), zap.Error(err))
			ctx, cancel = context.WithTimeout(context.Background(), 500*time.Millisecond)
			defer cancel()
			ndpiLabel, err = h.ndpi.Classify(ctx, h.flowID, firstChunk, flowInfo)
			if err != nil {
				log.Warn("nDPI classify falhou, usando Unknown", zap.Error(err))
				ndpiLabel = "Unknown"
			}
		}
	} else {
		ctx, cancel = context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()
		ndpiLabel, err = h.ndpi.Classify(ctx, h.flowID, firstChunk, flowInfo)
		if err != nil {
			log.Warn("nDPI classify falhou, usando Unknown", zap.Error(err))
			ndpiLabel = "Unknown"
		}
	}

	log.Info("fluxo classificado", zap.String("proto", ndpiLabel))

	// --- STEP 4: resolve honeypot pelo label nDPI ---
	honeypotAddr, _ = h.router.Resolve(ndpiLabel)

	// --- STEP 4.5: verifica se precisa de MITM ---
	// Se é SSH, usa MITM para estabelecer conexão corretamente
	log.Debug("🔍 verificando SSH",
		zap.ByteString("firstChunk", firstChunk),
		zap.Bool("isSSH", mitm.IsSSH(firstChunk)),
	)
	if mitm.IsSSH(firstChunk) {
		log.Info("🔐 SSH detectado, usando MITM", zap.String("target", honeypotAddr), zap.ByteString("banner", firstChunk[:min(20, len(firstChunk))]))

		hostKey, err := generateSSHHostKey()
		if err != nil {
			log.Error("falha gerando host key SSH", zap.Error(err))
			honeypotError = fmt.Sprintf("MITM setup failed: %v", err)
			goto publish
		}

		// Para o MITM de SSH, precisamos repassar o primeiro chunk que já foi lido
		// O MITM não viu esse dados, então criamos uma conexão com preload
		clientConn := &mitm.PreloadConn{
			Conn:    h.conn,
			Preload: firstChunk,
		}
		log.Debug("SSH MITM: passando conexão com preload", zap.Int("bytes", len(firstChunk)))
		mitmConfig := mitm.SSHMITMConfig{
			HostKey:    hostKey,
			Banner:     string(firstChunk),
			TargetAddr: honeypotAddr,
			FlowID:     h.flowID,
			SrcIP:      srcAddr.IP.String(),
			SrcPort:    srcAddr.Port,
			DstIP:      origDstIP.String(),
			DstPort:    int(origDstPort),
			OnEvent: func(event *kafka.Event) {
				h.producer.Publish(event)
			},
		}

		mitmLogger := func(format string, args ...interface{}) {
			log.Info("SSH-MITM: "+format, zap.Any("args", args))
		}

		err = mitm.HandleSSH(clientConn, mitmConfig, mitmLogger)
		if err != nil {
			log.Error("MITM SSH falhou", zap.Error(err))
			honeypotError = fmt.Sprintf("MITM failed: %v", err)
		}
		goto publish
	}

	// Se é TLS, usa MITM
	if mitm.IsTLS(firstChunk) {
		log.Info("🔐 TLS detectado, usando MITM", zap.String("target", honeypotAddr))

		cert, err := mitm.GenerateSelfSignedTLS()
		if err != nil {
			log.Error("falha gerando certificado TLS", zap.Error(err))
			honeypotError = fmt.Sprintf("TLS MITM setup failed: %v", err)
			goto publish
		}

		mitmConfig := mitm.TLSMITMConfig{
			Cert:       cert,
			TargetAddr: honeypotAddr,
		}

		mitmLogger := func(format string, args ...interface{}) {
			log.Info("TLS-MITM: "+format, zap.Any("args", args))
		}

		err = mitm.HandleTLS(h.conn, mitmConfig, mitmLogger)
		if err != nil {
			log.Error("MITM TLS falhou", zap.Error(err))
			honeypotError = fmt.Sprintf("MITM failed: %v", err)
		}
		goto publish
	}

	// --- STEP 5: tenta conectar ao honeypot ---
	honeypotConn, err = net.DialTimeout("tcp", honeypotAddr, honeypotDialTimeout)
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
	log.Debug("escrevendo firstChunk para honeypot", zap.Int("len", len(firstChunk)))
	if _, err = honeypotConn.Write(firstChunk); err != nil {
		log.Error("erro reenviando primeiro chunk", zap.Error(err))
		honeypotError = fmt.Sprintf("write failed: %v", err)
		goto publish
	}
	log.Debug("firstChunk escrito com sucesso")

	// --- STEP 7: pipe bidirecional com captura de payload ---
	teeWriterSrc = newLimitedTeeWriter(&bufSrc, h.maxPayloadBytes)
	teeWriterDst = newLimitedTeeWriter(&bufDst, h.maxPayloadBytes)

	startTime = time.Now()
	wg.Add(2)

	// goroutine 1: atacante → honeypot
	go func() {
		defer wg.Done()
		log.Debug("goroutine src→dst iniciada")
		src := io.TeeReader(h.conn, teeWriterSrc)
		n, err := io.Copy(honeypotConn, src)
		if err != nil {
			log.Debug("pipe src→dst encerrado",
				zap.Int("bytes_copied", int(n)),
				zap.String("error_type", fmt.Sprintf("%T", err)),
				zap.Error(err))
		} else {
			log.Debug("pipe src→dst concluído", zap.Int("bytes_copied", int(n)))
		}
	}()

	// goroutine 2: honeypot → atacante
	go func() {
		defer wg.Done()
		log.Debug("goroutine dst→src iniciada")
		src := io.TeeReader(honeypotConn, teeWriterDst)
		n, err := io.Copy(h.conn, src)
		if err != nil {
			log.Debug("pipe dst→src encerrado",
				zap.Int("bytes_copied", int(n)),
				zap.String("error_type", fmt.Sprintf("%T", err)),
				zap.Error(err))
		} else {
			log.Debug("pipe dst→src concluído", zap.Int("bytes_copied", int(n)))
		}
	}()

	wg.Wait()

publish:
	// --- STEP 8: sempre publica evento no Kafka (mesmo se honeypot falhou) ---
	duration := time.Since(startTime)
	event := &kafka.Event{
		FlowID:        h.flowID,
		Timestamp:     time.Now(),
		SrcIP:         srcAddr.IP.String(),
		SrcPort:       srcAddr.Port,
		DstIP:         origDstIP.String(),
		DstPort:       int(origDstPort),
		NDPIProto:     masterProtoFlow,
		NDPIApp:       appProtoFlow,
		Honeypot:      honeypotAddr,
		HoneypotError: honeypotError,
		PayloadSrc:    bufSrc.Bytes(),
		PayloadDst:    bufDst.Bytes(),
		PayloadSize:   int64(bufSrc.Len() + bufDst.Len()),
		LogType:       "application",
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

func generateSSHHostKey() (ssh.Signer, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("falha gerando chave RSA: %w", err)
	}

	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("falha criando signer SSH: %w", err)
	}

	return signer, nil
}

func normalizeFlowID(srcIP, dstIP net.IP, srcPort, dstPort uint16, protocol uint8) string {
	srcIP4 := srcIP.To4()
	dstIP4 := dstIP.To4()

	if srcIP4 == nil {
		srcIP4 = srcIP
	}
	if dstIP4 == nil {
		dstIP4 = dstIP
	}

	src := fmt.Sprintf("%s:%d", srcIP4.String(), srcPort)
	dst := fmt.Sprintf("%s:%d", dstIP4.String(), dstPort)

	if bytes.Compare(srcIP4, dstIP4) > 0 || (bytes.Equal(srcIP4, dstIP4) && srcPort > dstPort) {
		src, dst = dst, src
	}

	return fmt.Sprintf("%s-%s-%d", src, dst, protocol)
}
