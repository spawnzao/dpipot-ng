package proxy

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
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
	conn    net.Conn
	ndpi    *ndpi.Client
	router  *router.Router
	producer *kafka.Producer
	log     *zap.Logger

	srcIP   string
	srcPort int
	dstIP   string
	dstPort int

	// CertManager para TLS MITM
	certMgr *mitm.CertManager

	// captura dos payloads para o Kafka
	maxPayloadBytes int64
	flowTracker     *flowtracker.Client

	// serverFirstPorts contém as portas que usam server-first (servidor envia greeting primeiro)
	serverFirstPorts map[uint16]string

	// serverFirstPortsTLS contém as portas TLS server-first (ex: 993 IMAPS, 995 POP3S)
	serverFirstPortsTLS map[uint16]string
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
	certMgr *mitm.CertManager,
	serverFirstPorts map[uint16]string,
	serverFirstPortsTLS map[uint16]string,
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
		certMgr:         certMgr,
		serverFirstPorts: serverFirstPorts,
		serverFirstPortsTLS: serverFirstPortsTLS,
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

	h.srcIP = srcAddr.IP.String()
	h.srcPort = srcAddr.Port
	h.dstIP = dstAddr.IP.String()
	h.dstPort = dstAddr.Port

	log.Info("🔍 Handle() iniciado")

	// Aplica timeout de conexão (para evitar conexões órfãs)
	connectionTimeout := 10 * time.Second
	h.conn.SetDeadline(time.Now().Add(connectionTimeout))

	flowIDForTracker := normalizeFlowID(srcAddr.IP, dstAddr.IP, uint16(srcAddr.Port), uint16(dstAddr.Port), 6)
	appProtoFlow := "Unknown"
	if h.flowTracker != nil && h.flowTracker.IsEnabled() {
		if appProto, _, _, found, err := h.flowTracker.QueryFlow(context.Background(), flowIDForTracker); err == nil && found && appProto != "" && strings.ToUpper(appProto) != "UNKNOWN" {
			appProtoFlow = appProto
		}
	}

	// Fallback via SERVER_FIRST_PORTS (same as PORT_PROTOCOL_MAP now)
	if appProtoFlow == "Unknown" {
		if proto := h.serverFirstPorts[uint16(dstAddr.Port)]; proto != "" {
			appProtoFlow = proto
			log.Debug("proto encontrado no SERVER_FIRST_PORTS", zap.Uint16("port", uint16(dstAddr.Port)), zap.String("proto", proto))
		}
	}

	var (
		bufSrc           bytes.Buffer
		bufDst           bytes.Buffer
		ndpiLabel        = "Unknown"
		masterProtoFlow  = "Unknown"
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
		isZeroIP        bool
		isSSH          bool
		isTLS          bool
		isClientTimeout   bool
		isProbe          bool
		skipFirstChunkWrite bool // para server-first: não reescreve greeting para o honeypot
	)

	// --- STEP 1: verifica se é porta server-first ---
	dstPort := uint16(dstAddr.Port)
	isServerFirst := isServerFirstPort(h.serverFirstPorts, dstPort)
	isServerFirstTLS := mitm.IsServerFirstTLSPort(h.serverFirstPortsTLS, dstPort)

	if isServerFirst && isServerFirstTLS {
		log.Warn("porta não pode ser server-first E server-first-TLS simultaneamente", zap.Uint16("port", dstPort))
		honeypotError = "invalid server-first configuration"
		goto publish
	}

	// Server-first TLS (IMAPS 993, POP3S 995, etc): TLS handshake primeiro, depois relay
	if isServerFirstTLS {
		log.Debug("porta server-first TLS detectada",
			zap.Uint16("port", dstPort),
			zap.String("proto", h.serverFirstPortsTLS[dstPort]))

		ndpiLabel := appProtoFlow
		if ndpiLabel == "" || ndpiLabel == "Unknown" {
			ndpiLabel = h.serverFirstPortsTLS[dstPort]
		}

		honeypotAddr, _ = h.router.Resolve(ndpiLabel)
		log.Debug("rota SF-TLS resolvida",
			zap.String("proto", ndpiLabel),
			zap.String("honeypot", honeypotAddr))

		cert := h.certMgr.Cert()
		mitmLogger := func(format string, args ...interface{}) {
			msg := fmt.Sprintf("SF-TLS: "+format, args...)
			log.Info(msg)
		}

		err = mitm.HandleServerFirstTLS(mitm.ServerFirstTLSConfig{
			ClientConn:   h.conn,
			HoneypotConn: nil,
			Cert:        cert,
			FlowID:      h.flowID,
			SrcIP:       h.srcIP,
			SrcPort:     h.srcPort,
			DstIP:       h.dstIP,
			DstPort:     h.dstPort,
			HoneypotAddr: honeypotAddr,
			NDPIProto:   ndpiLabel,
			MaxPayloadSize: h.maxPayloadBytes,
			OnEvent: func(event *kafka.Event) {
				h.producer.Publish(event)
			},
			Logger: mitmLogger,
		})
		if err != nil {
			log.Error("HandleServerFirstTLS falhou", zap.Error(err))
			honeypotError = fmt.Sprintf("server-first TLS relay failed: %v", err)
		}
		goto publish
	}

	if isServerFirst {
		log.Debug("porta server-first detectada, conectando ao honeypot para greeting",
			zap.Uint16("port", dstPort))

		honeypotAddr = h.router.ResolveByPort(dstPort)
		if honeypotAddr == "" {
			log.Warn("não encontrou honeypot para porta server-first", zap.Uint16("port", dstPort))
			honeypotError = fmt.Sprintf("no honeypot for port %d", dstPort)
			goto publish
		}

		honeypotConn, err := net.DialTimeout("tcp", honeypotAddr, honeypotDialTimeout)
		if err != nil {
			log.Error("falha conectando ao honeypot (server-first)",
				zap.String("honeypot", honeypotAddr),
				zap.Error(err))
			honeypotError = fmt.Sprintf("connection failed: %v", err)
			goto publish
		}

		// Recebe greeting do servidor
		greetingBuf := make([]byte, classifyBufferSize)
		honeypotConn.SetReadDeadline(time.Now().Add(originalDstTimeout))
		n, err = honeypotConn.Read(greetingBuf)
		honeypotConn.SetReadDeadline(time.Time{})

		if err != nil {
			log.Warn("timeout/nenhum greeting do honeypot (server-first)", zap.Error(err))
			honeypotConn.Close()
			honeypotError = fmt.Sprintf("greeting failed: %v", err)
			goto publish
		}

greetingBuf = greetingBuf[:n]
		log.Debug("recebi greeting do honeypot (server-first)",
			zap.ByteString("greeting", greetingBuf[:min(20, len(greetingBuf))]),
			zap.Uint16("port", dstPort))

		parser := mitm.NewParser(appProtoFlow, int(dstPort))
		bannerEvents := parser.ParseServerData(greetingBuf, func(format string, args ...interface{}) {})

		for _, ev := range bannerEvents {
			if ev.EventType == mitm.EventBanner || ev.Banner != "" {
				if h.producer != nil {
					h.producer.Publish(&kafka.Event{
						FlowID:      h.flowID,
						Timestamp:   time.Now(),
						SrcIP:       h.srcIP,
						SrcPort:     h.srcPort,
						DstIP:       h.dstIP,
						DstPort:     int(dstPort),
						NDPIProto:   appProtoFlow,
						NDPIApp:    string(ev.EventType),
						AttackType: ev.Banner,
						Honeypot:    honeypotAddr,
						LogType:     "application",
						PayloadDst:  greetingBuf,
					})
				}
			}
		}

		log.Info("ServerFirst: banner/version publicado no Kafka")

		// Envia greeting para o cliente
		_, err = h.conn.Write(greetingBuf)
		if err != nil {
			log.Warn("falha ao enviar greeting para o cliente", zap.Error(err))
			honeypotConn.Close()
			honeypotError = fmt.Sprintf("greeting forward failed: %v", err)
			goto publish
		}

		// Flush para garantir que chegou ao cliente
		if f, ok := h.conn.(interface{ Flush() error }); ok {
			f.Flush()
		}

		mitmLogger := func(format string, args ...interface{}) {
			msg := fmt.Sprintf("ServerFirst: "+format, args...)
			log.Info(msg)
		}

		err = mitm.HandleServerFirst(mitm.ServerFirstConfig{
			ClientConn:     h.conn,
			HoneypotConn: honeypotConn,
			FlowID:       h.flowID,
			SrcIP:        h.srcIP,
			SrcPort:      h.srcPort,
			DstIP:        h.dstIP,
			DstPort:      h.dstPort,
			HoneypotAddr: honeypotAddr,
			NDPIProto:    appProtoFlow,
			MaxPayloadSize: h.maxPayloadBytes,
			OnEvent: func(event *kafka.Event) {
				h.producer.Publish(event)
			},
			Logger: mitmLogger,
		})
		if err != nil {
			log.Error("HandleServerFirst falhou", zap.Error(err))
			honeypotError = fmt.Sprintf("server-first relay failed: %v", err)
		}

		goto publish
	}

	// --- STEP 2: tenta ler primeiro chunk do cliente ---
	// Para protocolos que o cliente fala primero (HTTP, FTP, etc), isso funciona
	firstChunk = make([]byte, classifyBufferSize)
	h.conn.SetReadDeadline(time.Now().Add(originalDstTimeout))
	n, err = h.conn.Read(firstChunk)
	h.conn.SetReadDeadline(time.Time{})
	
	log.Info("📥 dados lidos do cliente", zap.Int("n", n), zap.Error(err))

	// Se der timeout (i/o timeout), pode ser:
	// 1. Cliente ainda não enviou dados (esperando greeting do servidor - ex: MySQL)
	// 2. Rede lenta
	// 3. Cliente malicioso
	isClientTimeout = false
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			log.Debug("timeout lendo do cliente, tentando conectar ao honeypot para receber greeting", zap.Error(err))
			isClientTimeout = true
		} else if err != io.EOF {
			log.Debug("erro lendo primeiro chunk", zap.Error(err))
			honeypotError = fmt.Sprintf("read error: %v", err)
			goto publish
		}
	}

	isProbe = false
	if n == 0 {
		if err == nil || err == io.EOF {
			isProbe = true
		} else if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			isProbe = true
		}
	}
	if isProbe {
		log.Debug("cliente não enviou dados ou fechou conexão (0 bytes lidos)", zap.Int("n", n), zap.Error(err))
		honeypotError = ""
		goto publish
	}

	if isClientTimeout {
		// Só tenta ler greeting do honeypot se a porta for server-first
		if !isServerFirstPort(h.serverFirstPorts, dstPort) {
			log.Debug("timeout do cliente mas porta não é server-first, fluxo normal",
				zap.Uint16("port", dstPort))
		} else {
			// Porta é server-first, conecta ao honeypot para receber greeting
			honeypotAddrFromPort := h.router.ResolveByPort(uint16(dstAddr.Port))

			if honeypotAddrFromPort != "" {
				log.Debug("conectando ao honeypot para receber greeting do servidor",
					zap.Stringer("dstAddr", dstAddr),
					zap.String("honeypot", honeypotAddrFromPort),
				)

				var honeypotGreetingConn net.Conn
				honeypotGreetingConn, err = net.DialTimeout("tcp", honeypotAddrFromPort, honeypotDialTimeout)
				if err != nil {
					log.Warn("falha conectando ao honeypot por porta", zap.Error(err))
					goto publish
				}
				defer honeypotGreetingConn.Close()

				// Agora espera o greeting do servidor (com timeout)
				greetingBuf := make([]byte, classifyBufferSize)
				honeypotGreetingConn.SetReadDeadline(time.Now().Add(originalDstTimeout))
				n, err = honeypotGreetingConn.Read(greetingBuf)
				honeypotGreetingConn.SetReadDeadline(time.Time{})

				if err != nil {
					log.Warn("timeout lendo greeting do honeypot", zap.Error(err))
				} else {
					greetingBuf = greetingBuf[:n]
					log.Debug("recebi greeting do honeypot", zap.ByteString("greeting", greetingBuf[:min(20, len(greetingBuf))]))

					// Classifica o greeting do servidor (não do cliente!)
					flowInfo = &ndpi.FlowInfo{
						SrcIP:   srcAddr.IP,
						SrcPort: uint16(srcAddr.Port),
						DstIP:   dstAddr.IP,
						DstPort: uint16(dstAddr.Port),
					}

					ndpiLabel, err = h.ndpi.Classify(context.Background(), h.flowID, greetingBuf, flowInfo)
					if err != nil {
						log.Warn("nDPI classify falhou no greeting", zap.Error(err))
						ndpiLabel = "Unknown"
					} else {
						log.Info("fluxo classificado via greeting do servidor", zap.String("proto", ndpiLabel))
					}

					// Envia greeting para o cliente
					_, err = h.conn.Write(greetingBuf)
					if err != nil {
						log.Warn("falha enviando greeting para o cliente", zap.Error(err))
					}

					// Agora conecta ao honeypot definitivo usando o protocolo classificado
					honeypotAddr, _ = h.router.Resolve(ndpiLabel)
					log.Debug("protocolo identificado via greeting, honeypot resolved",
						zap.String("proto", ndpiLabel),
						zap.String("honeypot", honeypotAddr),
					)

					// Usa o greeting como primeiro chunk
					firstChunk = greetingBuf
					bufSrc.Write(firstChunk)

					// Conecta ao honeypot definitivo
					honeypotGreetingConn.Close()
					honeypotConn, err = net.DialTimeout("tcp", honeypotAddr, honeypotDialTimeout)
					if err != nil {
						log.Error("falha conectando ao honeypot (greeting path)",
							zap.String("honeypot", honeypotAddr),
							zap.Error(err),
						)
						honeypotError = fmt.Sprintf("connection failed: %v", err)
						goto publish
					}
					defer honeypotConn.Close()

					// Vai direto para o relay (Step 6)
					goto doRelay
				}
			}
		}
	}

	if n > 0 {
		firstChunk = firstChunk[:n]
		bufSrc.Write(firstChunk)

		// Detecta se é conexão de probe (todos os bytes lidos são zeros)
		zeroCount := 0
		for i := 0; i < n; i++ {
			if firstChunk[i] == 0 {
				zeroCount++
			}
		}
		isAllZeros := zeroCount == n
		log.Info("🔍 dados recebidos", zap.Int("n", n), zap.Int("zeros", zeroCount), zap.Bool("isAllZeros", isAllZeros))
		if isAllZeros {
			isProbe = true
			log.Info("🔍 conexão de probe detectada", zap.Int("bytes", n), zap.Bool("isProbe", isProbe))
		}
	}

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
		appProtoFromTracker, masterProtoFromTracker, _, found, err := h.flowTracker.QueryFlow(context.Background(), flowIDForTracker)
		masterProtoFlow = appProtoFromTracker
		appProtoFlow = masterProtoFromTracker
		if err == nil && found && masterProtoFlow != "" && strings.ToUpper(masterProtoFlow) != "UNKNOWN" {
			ndpiLabel = masterProtoFlow
			if ndpiLabel == "" {
				ndpiLabel = appProtoFlow
			}
			log.Info("fluxo classificado via FlowTracker",
				zap.String("ndpi_proto", masterProtoFlow),
				zap.String("ndpi_app", appProtoFlow),
				zap.String("flow_id", flowIDForTracker))
		} else {
			log.Debug("FlowTracker não tem classificação ou retornou UNKNOWN, usando nDPI local", zap.String("flow_id", flowIDForTracker), zap.Error(err))
			ctx, cancel = context.WithTimeout(context.Background(), 500*time.Millisecond)
			defer cancel()
			ndpiLabel, err = h.ndpi.Classify(ctx, h.flowID, firstChunk, flowInfo)
			if err != nil {
				log.Warn("nDPI classify falhou, usando Unknown", zap.Error(err))
				ndpiLabel = "Unknown"
				masterProtoFlow = "Unknown"
				appProtoFlow = "Unknown"
			} else {
				masterProtoFlow = ndpiLabel
				appProtoFlow = ""
			}
		}
	} else {
		ctx, cancel = context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()
		ndpiLabel, err = h.ndpi.Classify(ctx, h.flowID, firstChunk, flowInfo)
		if err != nil {
			log.Warn("nDPI classify falhou, usando Unknown", zap.Error(err))
			ndpiLabel = "Unknown"
			masterProtoFlow = "Unknown"
			appProtoFlow = "Unknown"
		} else {
			masterProtoFlow = ndpiLabel
			appProtoFlow = ""
		}
	}

	log.Info("fluxo classificado", zap.String("proto", ndpiLabel))

	// --- STEP 4: resolve honeypot pelo label nDPI ---
	honeypotAddr, _ = h.router.Resolve(ndpiLabel)

	// --- STEP 4.5: verifica se precisa de MITM ---
	isSSH = mitm.IsSSH(firstChunk)
	isTLS = mitm.IsTLS(firstChunk)
	log.Debug("🔍 verificando MITM",
		zap.ByteString("firstChunk", firstChunk),
		zap.Bool("isSSH", isSSH),
		zap.Bool("isTLS", isTLS),
		zap.Bool("isProbe", isProbe),
	)

	// SSH: usa MITM
	if isSSH {
		log.Info("🔐 SSH detectado, usando MITM", zap.String("target", honeypotAddr), zap.ByteString("banner", firstChunk[:min(20, len(firstChunk))]))

		hostKey, err := GetSSHHostKey()
		if err != nil {
			log.Error("falha obtendo host key SSH", zap.Error(err))
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
			log.Info("SSH-MITM: "+fmt.Sprintf(format, args...))
		}

		err = mitm.HandleSSH(clientConn, mitmConfig, mitmLogger)
		if err != nil {
			errStr := err.Error()
			if strings.Contains(errStr, "permission denied") || strings.Contains(errStr, "no auth passed yet") {
				if strings.Contains(errStr, "permission denied, permission denied, permission denied") {
					log.Info("MITM SSH: cliente esgotou tentativas de senha (comportamento esperado)", zap.Error(err))
					event := &kafka.Event{
						FlowID:      h.flowID,
						Timestamp:   time.Now(),
						SrcIP:       srcAddr.IP.String(),
						SrcPort:     srcAddr.Port,
						DstIP:       origDstIP.String(),
						DstPort:     int(origDstPort),
						NDPIProto:   "SSH",
						NDPIApp:    "auth_exhausted",
						AttackType: "client exhausted password attempts",
						Honeypot:   honeypotAddr,
						LogType:    "application",
					}
					h.producer.Publish(event)
				} else {
					log.Info("MITM SSH: autenticação recusada pelo honeypot (comportamento esperado)", zap.Error(err))
				}
			} else {
				log.Info("MITM SSH: cliente fechou conexão antes do handshake", zap.Error(err))
			}
			honeypotError = fmt.Sprintf("MITM failed: %v", err)
		}
		goto publish
	}

	// TLS: usa MITM com certificados do CertManager (do disco ou gerados)
	if isTLS {
		log.Info("🔐 TLS detectado, usando MITM", zap.String("target", honeypotAddr))

		var bufSrcTLS, bufDstTLS bytes.Buffer

		cert := h.certMgr.Cert()
		mitmConfig := mitm.TLSMITMConfig{
			Cert:       cert,
			TargetAddr: honeypotAddr,
			FirstData:  firstChunk,
			OnSrcData: func(p []byte) {
				bufSrcTLS.Write(p) // honeypot → cliente = payload_dst
			},
			OnDstData: func(p []byte) {
				bufDstTLS.Write(p) // cliente → honeypot = payload_src
			},
		}

		mitmLogger := func(format string, args ...interface{}) {
			log.Info("TLS-MITM: "+fmt.Sprintf(format, args...))
		}

		err = mitm.HandleTLS(h.conn, mitmConfig, mitmLogger)
		if err != nil {
			log.Error("MITM TLS falhou", zap.Error(err))
			honeypotError = fmt.Sprintf("MITM failed: %v", err)
		}

		payloadSrcTLS := bufDstTLS.Bytes() // cliente → honeypot
		payloadDstTLS := bufSrcTLS.Bytes() // honeypot → cliente

		if h.producer != nil && (len(payloadSrcTLS) > 0 || len(payloadDstTLS) > 0) {
			event := &kafka.Event{
				FlowID:      h.flowID,
				Timestamp:   time.Now(),
				SrcIP:       h.srcIP,
				SrcPort:     h.srcPort,
				DstIP:       h.dstIP,
				DstPort:     h.dstPort,
				NDPIProto:   ndpiLabel,
				Honeypot:    honeypotAddr,
				PayloadSrc: payloadSrcTLS,
				PayloadDst: payloadDstTLS,
				LogType:     "application",
			}
			h.producer.Publish(event)
			log.Info("TLS-MITM: eventos publicados", zap.Int("src", len(payloadSrcTLS)), zap.Int("dst", len(payloadDstTLS)))
		}

		log.Info("fluxo encerrado", zap.String("proto", ndpiLabel), zap.String("honeypot", honeypotAddr), zap.Int("payload_src_bytes", len(payloadSrcTLS)), zap.Int("payload_dst_bytes", len(payloadDstTLS)))
		return
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

	doRelay:
	// --- STEP 6: reenvia o primeiro chunk para o honeypot ---
	// Para server-first, já enviamos o greeting sebelumnya, então pulamos esta etapa
	if !skipFirstChunkWrite && len(firstChunk) > 0 {
		log.Debug("escrevendo firstChunk para honeypot", zap.Int("len", len(firstChunk)))
		if _, err = honeypotConn.Write(firstChunk); err != nil {
			log.Error("erro reenviando primeiro chunk", zap.Error(err))
			honeypotError = fmt.Sprintf("write failed: %v", err)
			goto publish
		}
		log.Debug("firstChunk escrito com sucesso")
	} else {
		log.Debug("pulando escrita do firstChunk (server-first já enviou greeting)")
	}

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

	if (appProtoFlow == "Telnet" || appProtoFlow == "TELNET" || dstPort == 23) ||
		(appProtoFlow == "POP" || appProtoFlow == "POP3" || dstPort == 110) ||
		(appProtoFlow == "IMAP" || appProtoFlow == "IMAP4" || dstPort == 143 || dstPort == 993) {
		parser := mitm.NewParser(appProtoFlow, int(dstPort))
		protoLabel := "Telnet"
		if appProtoFlow == "POP" || appProtoFlow == "POP3" || dstPort == 110 {
			protoLabel = "POP3"
		} else if appProtoFlow == "IMAP" || appProtoFlow == "IMAP4" || dstPort == 143 || dstPort == 993 {
			protoLabel = "IMAP"
		}
		if srcData := bufSrc.Bytes(); len(srcData) > 0 {
			cmdEvents := parser.ParseClientData(srcData, func(format string, args ...interface{}) {})
			for _, ev := range cmdEvents {
				if ev.Command != "" || ev.Username != "" || ev.Password != "" {
					eventType := "command"
					attackType := ev.Command
					if ev.Username != "" {
						eventType = "credential"
						attackType = ev.Username
					} else if ev.Password != "" {
						eventType = "credential"
						attackType = ev.Password
					}
					h.producer.Publish(&kafka.Event{
						FlowID:      h.flowID,
						Timestamp:   time.Now(),
						SrcIP:       srcAddr.IP.String(),
						SrcPort:     srcAddr.Port,
						DstIP:       origDstIP.String(),
						DstPort:     int(dstPort),
						NDPIProto:   protoLabel,
						NDPIApp:    eventType,
						AttackType: attackType,
						Honeypot:    honeypotAddr,
						LogType:     "application",
					})
				}
			}
		}
		if dstData := bufDst.Bytes(); len(dstData) > 0 {
			respEvents := parser.ParseServerData(dstData, func(format string, args ...interface{}) {})
			for _, ev := range respEvents {
				if ev.Response != "" {
					h.producer.Publish(&kafka.Event{
						FlowID:      h.flowID,
						Timestamp:   time.Now(),
						SrcIP:       srcAddr.IP.String(),
						SrcPort:     srcAddr.Port,
						DstIP:       origDstIP.String(),
						DstPort:     int(dstPort),
						NDPIProto:   protoLabel,
						NDPIApp:    "response",
						AttackType: ev.Response,
						Honeypot:    honeypotAddr,
						LogType:     "application",
					})
				}
			}
		}
	}

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
	return len(p), nil
}

func (w *limitedTeeWriter) Read(p []byte) (int, error) {
	return 0, io.EOF
}

func isServerFirstPort(serverFirstPorts map[uint16]string, port uint16) bool {
	_, ok := serverFirstPorts[port]
	return ok
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
