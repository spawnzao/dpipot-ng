package mitm

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/spawnzao/dpipot-ng/proxy/internal/kafka"
	"golang.org/x/crypto/ssh"
)

func IsTLS(data []byte) bool {
	return len(data) > 3 &&
		data[0] == 0x16 &&
		data[1] == 0x03
}

func IsSSH(data []byte) bool {
	return bytes.HasPrefix(data, []byte("SSH-"))
}

func DetectProtocol(firstChunk []byte) string {
	if IsTLS(firstChunk) {
		return "TLS"
	}
	if IsSSH(firstChunk) {
		return "SSH"
	}
	return "Plaintext"
}

type SSHMITMConfig struct {
	Banner         string
	HostKey        ssh.Signer
	TargetAddr     string
	MaxPayloadSize int64
	ServerConfig   *ssh.ServerConfig
	OnEvent        func(event *kafka.Event)
	FlowID         string
	SrcIP          string
	SrcPort        int
	DstIP          string
	DstPort        int
}

var (
	promptPatterns []*regexp.Regexp = []*regexp.Regexp{
		regexp.MustCompile(`\$\s*$`),
		regexp.MustCompile(`#\s*$`),
		regexp.MustCompile(`>\s*$`),
		regexp.MustCompile(`\$\s+`),
		regexp.MustCompile(`#\s+`),
		regexp.MustCompile(`>\s+`),
	}
	commandDelimiters = []byte{'\r', '\n'}
	backspace        = byte(0x7f)
	escape          = byte(0x1b)
)

type SSHSession struct {
	mu            sync.Mutex
	inputBuffer   bytes.Buffer
	outputBuffer bytes.Buffer
	lastActivity time.Time
	pendingCmd   string
	pendingResp  string
	flowID       string
	srcIP        string
	srcPort       int
	dstIP         string
	dstPort       int
	honeypot     string
	onEvent      func(event *kafka.Event)
	logger       func(string, ...interface{})
	closed       bool
}

func NewSSHSession(flowID, srcIP string, srcPort int, dstIP string, dstPort int, honeypot string, onEvent func(event *kafka.Event), logger func(string, ...interface{})) *SSHSession {
	return &SSHSession{
		flowID:       flowID,
		srcIP:        srcIP,
		srcPort:      srcPort,
		honeypot:     honeypot,
		dstIP:        dstIP,
		dstPort:      dstPort,
		onEvent:      onEvent,
		logger:       logger,
		lastActivity: time.Now(),
	}
}

func (s *SSHSession) HandleInput(data []byte) {
	if len(data) == 0 || s.closed {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for _, b := range data {
		switch b {
		case '\r', '\n':
			cmd := s.inputBuffer.String()
			if cmd != "" {
				s.logger("SSH-MITM: comando completo capturado: %q", cmd)
				s.pendingCmd = cmd
				s.inputBuffer.Reset()
				s.emitCommand()
			}
		case 0x7f:
			if s.inputBuffer.Len() > 0 {
				s.inputBuffer.Truncate(s.inputBuffer.Len() - 1)
			}
		case 0x1b:
			s.inputBuffer.Reset()
		default:
			if b >= 0x20 && b < 0x7f {
				s.inputBuffer.WriteByte(b)
			}
		}
	}
	s.lastActivity = time.Now()
}

func (s *SSHSession) HandleOutput(data []byte) {
	if len(data) == 0 || s.closed {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.outputBuffer.Write(data)
	s.lastActivity = time.Now()

	output := s.outputBuffer.String()
	for _, pattern := range promptPatterns {
		if pattern.MatchString(output) {
			s.logger("SSH-MITM: prompt detectado, emitindo resposta: %d bytes", len(output))
			s.pendingResp = output
			s.outputBuffer.Reset()
			s.emitResponse()
			return
		}
	}
}

func (s *SSHSession) Flush() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.inputBuffer.Len() > 0 {
		cmd := s.inputBuffer.String()
		if len(cmd) > 1 {
			s.logger("SSH-MITM: flush comando pendente: %q", cmd)
			s.pendingCmd = cmd
			s.inputBuffer.Reset()
			s.emitCommand()
		} else {
			s.inputBuffer.Reset()
		}
	}

	if s.outputBuffer.Len() > 0 {
		resp := s.outputBuffer.String()
		if len(resp) > 1 {
			s.logger("SSH-MITM: flush resposta pendente: %d bytes", len(resp))
			s.pendingResp = resp
			s.outputBuffer.Reset()
			s.emitResponse()
		} else {
			s.outputBuffer.Reset()
		}
	}
}

func (s *SSHSession) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	s.Flush()
}

func (s *SSHSession) emitCommand() {
	if s.pendingCmd == "" || s.onEvent == nil {
		return
	}

	event := &kafka.Event{
		FlowID:    s.flowID,
		Timestamp: time.Now(),
		SrcIP:     s.srcIP,
		SrcPort:    s.srcPort,
		DstIP:     s.dstIP,
		DstPort:   s.dstPort,
		NDPIProto: "SSH",
		NDPIApp:   "command",
		AttackType: s.pendingCmd,
		Honeypot: s.honeypot,
		LogType:   "application",
	}
	s.onEvent(event)
	s.logger("SSH-MITM: comando publicado no Kafka: %q", s.pendingCmd)
	s.pendingCmd = ""
}

func (s *SSHSession) emitResponse() {
	if s.pendingResp == "" || s.onEvent == nil {
		return
	}

	event := &kafka.Event{
		FlowID:    s.flowID,
		Timestamp: time.Now(),
		SrcIP:     s.dstIP,
		SrcPort:    s.dstPort,
		DstIP:     s.srcIP,
		DstPort:   s.srcPort,
		NDPIProto: "SSH",
		NDPIApp:   "response",
		CVE:       strings.TrimSpace(s.pendingResp),
		Honeypot: s.honeypot,
		LogType:   "application",
	}
	s.onEvent(event)
	s.logger("SSH-MITM: resposta publicada no Kafka: %d bytes", len(s.pendingResp))
	s.pendingResp = ""
}

type CapturedCredentials struct {
	Banner string
	User   string
	Pass   string
}

type PreloadConn struct {
	Conn    net.Conn
	Preload []byte
	pos     int
}

type BannerConn struct {
	net.Conn
	Banner       string
	wroteBanner  bool
	wroteBannerM sync.Mutex
}

type directTCPConn struct {
	net.Conn
	Banner string
	Log    func(string, ...interface{})
}

func (d *directTCPConn) Write(p []byte) (int, error) {
	if len(p) > 0 && p[0] == 'S' {
		d.Log("directTCPConn: replacing banner with: %s", d.Banner)
		return d.Conn.Write([]byte(d.Banner))
	}
	return d.Conn.Write(p)
}

func (b *BannerConn) Write(p []byte) (int, error) {
	b.wroteBannerM.Lock()
	defer b.wroteBannerM.Unlock()

	if !b.wroteBanner && len(p) > 0 && bytes.HasPrefix(p, []byte("SSH-")) {
		b.wroteBanner = true
		logger := func(s string, args ...interface{}) {}
		logger("BannerConn: intercepting Go banner, replacing with: %s", b.Banner)
		return b.Conn.Write([]byte(b.Banner))
	}
	if len(p) > 0 {
		logger := func(s string, args ...interface{}) {}
		logger("BannerConn: passthrough %d bytes", len(p))
	}
	return b.Conn.Write(p)
}

func (p *PreloadConn) Read(b []byte) (int, error) {
	if p.pos < len(p.Preload) {
		n := copy(b, p.Preload[p.pos:])
		p.pos += n
		return n, nil
	}
	return p.Conn.Read(b)
}

func (p *PreloadConn) Close() error {
	return p.Conn.Close()
}

func (p *PreloadConn) LocalAddr() net.Addr {
	return p.Conn.LocalAddr()
}

func (p *PreloadConn) RemoteAddr() net.Addr {
	return p.Conn.RemoteAddr()
}

func (p *PreloadConn) SetDeadline(t time.Time) error {
	return p.Conn.SetDeadline(t)
}

func (p *PreloadConn) SetReadDeadline(t time.Time) error {
	return p.Conn.SetReadDeadline(t)
}

func (p *PreloadConn) SetWriteDeadline(t time.Time) error {
	return p.Conn.SetWriteDeadline(t)
}

func (p *PreloadConn) Write(b []byte) (int, error) {
	return p.Conn.Write(b)
}

// forwardRequests encaminha SSH requests de um canal para outro,
// respondendo ao remetente com o resultado. É necessário para
// repassar pty-req, shell, exec, window-change etc.
func forwardRequests(dst ssh.Channel, reqs <-chan *ssh.Request, logger func(string, ...interface{}), onEvent func(event *kafka.Event), config SSHMITMConfig) {
	for req := range reqs {
		logger("SSH MITM: encaminhando request tipo=%s wantReply=%v payload=%d bytes",
			req.Type, req.WantReply, len(req.Payload))

		if onEvent != nil && (req.Type == "exit-status" || req.Type == "exit-signal") {
			logger("SSH MITM: conexão SSH encerrada, tipo=%s", req.Type)
			event := &kafka.Event{
				FlowID:      config.FlowID,
				Timestamp:   time.Now(),
				SrcIP:       config.SrcIP,
				SrcPort:     config.SrcPort,
				DstIP:       config.DstIP,
				DstPort:     config.DstPort,
				NDPIProto:   "SSH",
				NDPIApp:    "exit",
				Honeypot:   config.TargetAddr,
				AttackType: string(req.Payload),
				LogType:    "application",
			}
			onEvent(event)
		}

		ok, err := dst.SendRequest(req.Type, req.WantReply, req.Payload)
		if err != nil {
			logger("SSH MITM: erro ao encaminhar request %s: %v", req.Type, err)
			if req.WantReply {
				req.Reply(false, nil)
			}
			continue
		}

		if req.WantReply {
			req.Reply(ok, nil)
		}
	}
}

func HandleSSH(clientConn net.Conn, config SSHMITMConfig, logger func(string, ...interface{})) error {
	logger("SSH MITM: iniciando handshake")

	capturedCreds := &CapturedCredentials{
		Banner: string(config.Banner),
	}

	serverConfig := &ssh.ServerConfig{
		NoClientAuth:  false,
		ServerVersion: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1",
	}

	serverConfig.PasswordCallback = func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
		capturedCreds.User = conn.User()
		capturedCreds.Pass = string(password)
		logger("🔐 CREDENCIAIS CAPTURADAS - Usuário: %s, Senha: %s, Banner: %s",
			capturedCreds.User, capturedCreds.Pass, capturedCreds.Banner)

		if config.OnEvent != nil {
			event := &kafka.Event{
				FlowID:      config.FlowID,
				Timestamp:   time.Now(),
				SrcIP:       config.SrcIP,
				SrcPort:     config.SrcPort,
				DstIP:       config.DstIP,
				DstPort:     config.DstPort,
				NDPIProto:   "SSH",
				NDPIApp:    "username",
				AttackType: capturedCreds.User,
				Honeypot:   config.TargetAddr,
				LogType:    "application",
			}
			config.OnEvent(event)

			event = &kafka.Event{
				FlowID:      config.FlowID,
				Timestamp:   time.Now(),
				SrcIP:       config.SrcIP,
				SrcPort:     config.SrcPort,
				DstIP:       config.DstIP,
				DstPort:     config.DstPort,
				NDPIProto:   "SSH",
				NDPIApp:    "password",
				AttackType: capturedCreds.Pass,
				Honeypot:   config.TargetAddr,
				LogType:    "application",
			}
			config.OnEvent(event)

			event = &kafka.Event{
				FlowID:      config.FlowID,
				Timestamp:   time.Now(),
				SrcIP:       config.SrcIP,
				SrcPort:     config.SrcPort,
				DstIP:       config.DstIP,
				DstPort:     config.DstPort,
				NDPIProto:   "SSH",
				NDPIApp:    "banner",
				AttackType: capturedCreds.Banner,
				Honeypot:   config.TargetAddr,
				LogType:    "application",
			}
			config.OnEvent(event)

			logger("SSH MITM: eventos de login publicados no Kafka (username, password, banner)")
		}

		return &ssh.Permissions{}, nil
	}

	serverConfig.AddHostKey(config.HostKey)

	logger("SSH MITM: chamando ssh.NewServerConn...")
	conn, chans, reqs, err := ssh.NewServerConn(clientConn, serverConfig)
	if err != nil {
		logger("SSH MITM: erro em NewServerConn: %v", err)
		logger("SSH MITM: cliente fechou a conexão antes do handshake")
		clientConn.Close()
		return fmt.Errorf("ssh handshake falhou: %w", err)
	}
	defer conn.Close()
	logger("SSH MITM: NewServerConn OK")

	logger("SSH MITM: conectando ao honeypot: %s", config.TargetAddr)
	targetConn, err := net.DialTimeout("tcp", config.TargetAddr, 5*time.Second)
	if err != nil {
		logger("SSH MITM: falha ao conectar no honeypot: %v", err)
		return fmt.Errorf("falha ao conectar no honeypot: %w", err)
	}
	logger("SSH MITM: conexão TCP com honeypot estabelecida")
	defer targetConn.Close()

	var authMethods []ssh.AuthMethod
	if capturedCreds.Pass != "" {
		authMethods = append(authMethods, ssh.Password(capturedCreds.Pass))
	}
	authMethods = append(authMethods,
		ssh.Password("root"),
		ssh.Password("admin"),
		ssh.Password("password"),
		ssh.Password("123456"),
		ssh.Password(""),
	)

	logger("SSH MITM: conectando SSH ao honeypot com credenciais capturadas: user=%s, pass=%s, metodos=%v",
		capturedCreds.User, capturedCreds.Pass, len(authMethods))

	logger("SSH MITM: targetConn.LocalAddr: %v, targetConn.RemoteAddr: %v",
		targetConn.LocalAddr(), targetConn.RemoteAddr())

	logger("SSH MITM: iniciando ssh.NewClientConn...")

	targetSSHConn, _, targetGlobalReqs, err := ssh.NewClientConn(targetConn, config.TargetAddr, &ssh.ClientConfig{
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Auth:            authMethods,
		User:            capturedCreds.User,
	})
	if err != nil {
		logger("SSH MITM: erro ao conectar SSH no honeypot: %s", err.Error())
		return fmt.Errorf("ssh handshake honeypot falhou: %w", err)
	}
	if targetSSHConn == nil {
		logger("SSH MITM: targetSSHConn é nil mesmo sem erro")
		return fmt.Errorf("ssh target connection é nil")
	}
	logger("SSH MITM: SSH conectado ao honeypot")
	defer targetSSHConn.Close()

	// Descarta global requests de ambos os lados
	go ssh.DiscardRequests(reqs)
	go ssh.DiscardRequests(targetGlobalReqs)

	logger("SSH MITM: esperando por channels...")

	for newChannel := range chans {
		logger("SSH MITM: novo channel recebido: %s", newChannel.ChannelType())

		// Abre o canal no honeypot ANTES de aceitar do cliente,
		// para poder recusar corretamente se o honeypot rejeitar.
		targetChannel, targetReqs, err := targetSSHConn.OpenChannel(
			newChannel.ChannelType(), newChannel.ExtraData(),
		)
		if err != nil {
			logger("SSH MITM: falha ao abrir channel no honeypot: %v", err)
			newChannel.Reject(ssh.Prohibited, "falha ao abrir channel")
			continue
		}
		logger("SSH MITM: channel aberto no honeypot OK")

		clientChannel, clientReqs, err := newChannel.Accept()
		if err != nil {
			logger("SSH MITM: falha ao aceitar channel do cliente: %v", err)
			targetChannel.Close()
			continue
		}
		logger("SSH MITM: channel aceito do cliente")

// Encaminha requests do cliente → honeypot (pty-req, shell, exec, window-change…)
		// e do honeypot → cliente (exit-status, exit-signal…)
		// SEM isso o shell nunca abre.
go forwardRequests(targetChannel, clientReqs, logger, config.OnEvent, config)

		go forwardRequests(clientChannel, targetReqs, logger, config.OnEvent, config)
		// Nova estrutura SSHSession para TTY Stream Reconstruction
		sshSession := NewSSHSession(
			config.FlowID,
			config.SrcIP, config.SrcPort,
			config.DstIP, config.DstPort,
			config.TargetAddr,
			config.OnEvent,
			logger,
		)

		// Copia dados brutos em ambas as direções (stdin/stdout do canal).
		//.stderr é tratado separadamente pois é um sub-canal distinto.
		go func() {
			defer targetChannel.Close()
			defer clientChannel.Close()
			defer sshSession.Close()
			buf := make([]byte, 4096)
			for {
				n, err := clientChannel.Read(buf)
				if n > 0 {
					data := bytes.Clone(buf[:n])
					logger("SSH MITM: cliente→honeypot lendo %d bytes", n)
					sshSession.HandleInput(data)
					targetChannel.Write(data)
				}
				if err != nil {
					logger("SSH MITM: cliente→honeypot erro: %v", err)
					break
				}
			}
		}()

		go func() {
			defer targetChannel.Close()
			defer clientChannel.Close()
			buf := make([]byte, 4096)
			for {
				n, err := targetChannel.Read(buf)
				if n > 0 {
					data := bytes.Clone(buf[:n])
					logger("SSH MITM: honeypot→cliente lendo %d bytes", n)
					sshSession.HandleOutput(data)
					clientChannel.Write(data)
				}
				if err != nil {
					logger("SSH MITM: honeypot→cliente erro: %v", err)
					break
				}
			}
		}()

		// Stderr: honeypot → cliente (ex: mensagens de erro do shell remoto)
		go func() {
			defer func() { recover() }() // stderr pode não estar disponível
			io.Copy(clientChannel.Stderr(), targetChannel.Stderr())
		}()

		go func() {
			defer func() { recover() }()
			io.Copy(targetChannel.Stderr(), clientChannel.Stderr())
		}()
	}

	logger("SSH MITM: HandleSSH retornando nil")
return nil
}

type ServerFirstConfig struct {
	ClientConn    net.Conn
	HoneypotConn net.Conn
	FlowID       string
	SrcIP        string
	SrcPort      int
	DstIP        string
	DstPort      int
	HoneypotAddr string
	NDPIProto    string
	MaxPayloadSize int64
	OnEvent      func(event *kafka.Event)
	Logger      func(string, ...interface{})
}

func HandleServerFirst(config ServerFirstConfig) error {
	config.Logger("ServerFirst: relay iniciado com conexão existente")

	hasSentGreeting := false

	parser := NewParser(config.NDPIProto, config.DstPort)

	errChan := make(chan error, 2)

	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := config.ClientConn.Read(buf)
			if n > 0 {
				data := make([]byte, n)
				copy(data, buf[:n])

				if !hasSentGreeting {
					hasSentGreeting = true
					config.Logger("ServerFirst: primeiro pacote do cliente: %d bytes", n)
				}

				if config.OnEvent != nil {
					events := parser.ParseClientData(data, config.Logger)
					for _, ev := range events {
						config.OnEvent(&kafka.Event{
							FlowID:      config.FlowID,
							Timestamp:   time.Now(),
							SrcIP:       config.SrcIP,
							SrcPort:     config.SrcPort,
							DstIP:       config.DstIP,
							DstPort:     config.DstPort,
							NDPIProto:   config.NDPIProto,
							NDPIApp:    string(ev.EventType),
							AttackType: formatAttackType(ev),
							Honeypot:   config.HoneypotAddr,
							LogType:     "application",
							PayloadSrc: data,
						})
					}
				}

				_, wErr := config.HoneypotConn.Write(data)
				if wErr != nil {
					errChan <- wErr
					return
				}
			}
			if err != nil {
				errChan <- err
				return
			}
		}
	}()

	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := config.HoneypotConn.Read(buf)
			if n > 0 {
				data := make([]byte, n)
				copy(data, buf[:n])

				if config.OnEvent != nil {
					events := parser.ParseServerData(data, config.Logger)
					for _, ev := range events {
						config.OnEvent(&kafka.Event{
							FlowID:       config.FlowID,
							Timestamp:    time.Now(),
							SrcIP:        config.SrcIP,
							SrcPort:      config.SrcPort,
							DstIP:        config.DstIP,
							DstPort:      config.DstPort,
							NDPIProto:    config.NDPIProto,
							NDPIApp:     string(ev.EventType),
							AttackType:   formatAttackType(ev),
							Honeypot:     config.HoneypotAddr,
							LogType:      "application",
							PayloadDst:   data,
						})
					}
				}

				_, wErr := config.ClientConn.Write(data)
				if wErr != nil {
					errChan <- wErr
					return
				}
			}
			if err != nil {
				errChan <- err
				return
			}
		}
	}()

	relayErr := <-errChan
	config.Logger("ServerFirst: relay encerrou: %v", relayErr)

	config.HoneypotConn.Close()
	config.ClientConn.Close()

	return nil
}

func formatAttackType(ev CaptureEvent) string {
	switch ev.EventType {
	case EventCredential:
		if ev.Username != "" {
			return ev.Username
		}
		if ev.Password != "" {
			return ev.Password
		}
	case EventCommand:
		return ev.Command
	case EventResponse:
		return ev.Response
	case EventBanner:
		return ev.Banner
	case EventRawData:
		return ev.RawPayload
	}
	return ""
}

func extractMySQLUsername(data []byte, logger func(string, ...interface{})) string {
	if len(data) < 36 {
		return ""
	}

	offset := 32
	for i := offset; i < len(data); i++ {
		if data[i] == 0x00 {
			user := string(data[offset:i])
			if len(user) > 0 && len(user) < 32 && !strings.Contains(user, "\ufffd") && !strings.Contains(user, "\u001d") {
				logger("extractMySQLUsername: found user at offset %d: %q", offset, user)
				return user
			}
		}
	}

	return ""
}

func extractMySQLPassword(data []byte, logger func(string, ...interface{})) string {
	return ""
}

type TLSMITMConfig struct {
	Cert          tls.Certificate
	TargetAddr   string
	FirstData    []byte
	OnSrcData    func([]byte)
	OnDstData    func([]byte)
}

type bufferedConn struct {
	net.Conn
	buffer []byte
	pos    int
}

func (b *bufferedConn) Read(p []byte) (n int, err error) {
	if b.pos < len(b.buffer) {
		n = copy(p, b.buffer[b.pos:])
		b.pos += n
		if b.pos >= len(b.buffer) {
			return n, io.EOF
		}
		return n, nil
	}
	return b.Conn.Read(p)
}

type captureWriter struct {
	w      io.WriteCloser
	caller func([]byte)
}

func (c *captureWriter) Write(p []byte) (n int, err error) {
	if c.caller != nil && len(p) > 0 {
		c.caller(p)
	}
	return c.w.Write(p)
}

func (c *captureWriter) Close() error {
	return c.w.Close()
}

func HandleTLS(clientConn net.Conn, config TLSMITMConfig, logger func(string, ...interface{})) error {
	var connToUse net.Conn = clientConn

	if len(config.FirstData) > 0 {
		connToUse = &bufferedConn{Conn: clientConn, buffer: config.FirstData}
		logger("TLS MITM: usando primeiro chunk já lido (len=%d)", len(config.FirstData))
	}

	tlsServer := tls.Server(connToUse, &tls.Config{
		Certificates: []tls.Certificate{config.Cert},
	})

	if err := tlsServer.Handshake(); err != nil {
		return fmt.Errorf("TLS handshake server falhou: %w", err)
	}
	logger("TLS MITM: handshake feito com cliente")

	targetConn, err := net.DialTimeout("tcp", config.TargetAddr, 5*time.Second)
	if err != nil {
		return fmt.Errorf("falha ao conectar no honeypot: %w", err)
	}
	defer targetConn.Close()

	logger("TLS MITM: conectado ao honeypot (plain)")

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		defer targetConn.Close()
		defer tlsServer.Close()

		buf := make([]byte, 8192)
		for {
			n, err := tlsServer.Read(buf)
			if n > 0 {
				if config.OnDstData != nil {
					config.OnDstData(buf[:n])
				}
				if _, werr := targetConn.Write(buf[:n]); werr != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
	}()
	go func() {
		defer wg.Done()
		defer targetConn.Close()
		defer tlsServer.Close()

		buf := make([]byte, 8192)
		for {
			n, err := targetConn.Read(buf)
			if n > 0 {
				if config.OnSrcData != nil {
					config.OnSrcData(buf[:n])
				}
				if _, werr := tlsServer.Write(buf[:n]); werr != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
	}()

	wg.Wait()
	return nil
}

func GenerateSelfSignedTLS() (tls.Certificate, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("falha ao gerar chave RSA: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"DPIot MITM"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("falha ao criar certificado: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("falha ao criar tls.Certificate: %w", err)
	}

	return cert, nil
}

func PeekFirstChunk(conn net.Conn, size int) ([]byte, error) {
	reader := bufio.NewReader(conn)
	peek, err := reader.Peek(size)
	if err != nil {
		return nil, err
	}
	return peek, nil
}

func NewBufioReader(conn net.Conn) *bufio.Reader {
	return bufio.NewReader(conn)
}
