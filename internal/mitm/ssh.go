package mitm

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/spawnzao/dpipot-ng/internal/kafka"
	"golang.org/x/crypto/ssh"
)

// SSHMITMConfig holds all parameters for the SSH MITM handler.
type SSHMITMConfig struct {
	Banner           string
	HostKey          ssh.Signer
	TargetAddr       string
	MaxPayloadSize   int64
	SSHInputBufSize  int
	SSHOutputBufSize int
	ServerConfig     *ssh.ServerConfig
	OnEvent          func(event *kafka.Event)
	FlowID           string
	TupleID          string
	SrcIP            string
	SrcPort          int
	DstIP            string
	DstPort          int
	Deadline         time.Time
}

const (
	defaultSSHInputBufSize  = 4096
	defaultSSHOutputBufSize = 65536
)

var (
	promptPatterns = []*regexp.Regexp{
		regexp.MustCompile(`\$\s*$`),
		regexp.MustCompile(`#\s*$`),
		regexp.MustCompile(`>\s*$`),
		regexp.MustCompile(`\$\s+`),
		regexp.MustCompile(`#\s+`),
		regexp.MustCompile(`>\s+`),
	}
)

// SSHSession tracks per-channel input/output buffers and emits Kafka events
// when a complete command line or server response is detected.
type SSHSession struct {
	mu               sync.Mutex
	inputBuffer      bytes.Buffer
	outputBuffer     bytes.Buffer
	lastActivity     time.Time
	pendingCmd       string
	pendingResp      string
	flowID           string
	srcIP            string
	srcPort          int
	dstIP            string
	dstPort          int
	honeypot         string
	onEvent          func(event *kafka.Event)
	logger           func(string, ...interface{})
	closed           bool
	maxInputBufSize  int
	maxOutputBufSize int
}

func NewSSHSession(flowID, srcIP string, srcPort int, dstIP string, dstPort int, honeypot string,
	onEvent func(event *kafka.Event), logger func(string, ...interface{}),
	maxInputBufSize, maxOutputBufSize int) *SSHSession {

	if maxInputBufSize <= 0 {
		maxInputBufSize = defaultSSHInputBufSize
	}
	if maxOutputBufSize <= 0 {
		maxOutputBufSize = defaultSSHOutputBufSize
	}
	return &SSHSession{
		flowID:           flowID,
		srcIP:            srcIP,
		srcPort:          srcPort,
		dstIP:            dstIP,
		dstPort:          dstPort,
		honeypot:         honeypot,
		onEvent:          onEvent,
		logger:           logger,
		lastActivity:     time.Now(),
		maxInputBufSize:  maxInputBufSize,
		maxOutputBufSize: maxOutputBufSize,
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
		case 0x7f: // backspace
			if s.inputBuffer.Len() > 0 {
				s.inputBuffer.Truncate(s.inputBuffer.Len() - 1)
			}
		case 0x1b: // escape
			s.inputBuffer.Reset()
		default:
			if b >= 0x20 && b < 0x7f {
				s.inputBuffer.WriteByte(b)
				if s.inputBuffer.Len() >= s.maxInputBufSize {
					cmd := s.inputBuffer.String()
					s.logger("SSH-MITM: comando truncado por limite de tamanho: %d bytes", len(cmd))
					s.pendingCmd = cmd
					s.inputBuffer.Reset()
					s.emitCommand()
				}
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

	if s.outputBuffer.Len() >= s.maxOutputBufSize {
		output := s.outputBuffer.String()
		s.logger("SSH-MITM: output truncado por limite de tamanho: %d bytes", len(output))
		s.pendingResp = output
		s.outputBuffer.Reset()
		s.emitResponse()
		return
	}

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
	s.flushLocked()
}

func (s *SSHSession) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	s.flushLocked()
}

func (s *SSHSession) flushLocked() {
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

func (s *SSHSession) emitCommand() {
	if s.pendingCmd == "" || s.onEvent == nil {
		return
	}
	s.onEvent(&kafka.Event{
		FlowID:     s.flowID,
		Timestamp:  time.Now(),
		SrcIP:      s.srcIP,
		SrcPort:    s.srcPort,
		DstIP:      s.dstIP,
		DstPort:    s.dstPort,
		NDPIProto:  "SSH",
		NDPIApp:    "command",
		AttackType: s.pendingCmd,
		Honeypot:   s.honeypot,
		Instance:   "proxy",
	})
	s.logger("SSH-MITM: comando publicado no Kafka: %q", s.pendingCmd)
	s.pendingCmd = ""
}

func (s *SSHSession) emitResponse() {
	if s.pendingResp == "" || s.onEvent == nil {
		return
	}
	s.onEvent(&kafka.Event{
		FlowID:     s.flowID,
		Timestamp:  time.Now(),
		SrcIP:      s.srcIP,
		SrcPort:    s.srcPort,
		DstIP:      s.dstIP,
		DstPort:    s.dstPort,
		NDPIProto:  "SSH",
		NDPIApp:    "response",
		CVE:        strings.TrimSpace(s.pendingResp),
		Honeypot:   s.honeypot,
		Instance:   "proxy",
	})
	s.logger("SSH-MITM: resposta publicada no Kafka: %d bytes", len(s.pendingResp))
	s.pendingResp = ""
}

// BannerConn intercepts the first SSH banner write from the Go ssh library and
// replaces it with the configured honeypot banner so the attacker sees a realistic
// server version string.
type BannerConn struct {
	net.Conn
	Banner       string
	wroteBanner  bool
	wroteBannerM sync.Mutex
}

func (b *BannerConn) Write(p []byte) (int, error) {
	b.wroteBannerM.Lock()
	defer b.wroteBannerM.Unlock()
	if !b.wroteBanner && len(p) > 0 && bytes.HasPrefix(p, []byte("SSH-")) {
		b.wroteBanner = true
		return b.Conn.Write([]byte(b.Banner))
	}
	return b.Conn.Write(p)
}

// directTCPConn replaces any outgoing SSH banner with a fixed banner string.
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

// HandleSSH performs a full SSH MITM:
//  1. Presents proxy's host key to the client and captures credentials via PasswordCallback.
//  2. Validates credentials against the honeypot (tryAuthOnHoneypot).
//  3. Opens a real SSH session to the honeypot with the captured credentials.
//  4. Relays channels bidirectionally, recording commands and responses.
func HandleSSH(clientConn net.Conn, config SSHMITMConfig, logger func(string, ...interface{})) error {
	logger("SSH MITM: iniciando handshake")

	if !config.Deadline.IsZero() {
		clientConn.SetDeadline(config.Deadline) //nolint:errcheck
	}

	serverConfig := &ssh.ServerConfig{
		NoClientAuth:  false,
		ServerVersion: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1",
	}

	var authMu sync.Mutex
	var authSuccess bool
	var capturedUser, capturedPass string

	serverConfig.PasswordCallback = func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
		user := conn.User()
		pass := string(password)
		logger("SSH MITM: credenciais capturadas — user=%s", user)

		if config.OnEvent != nil {
			config.OnEvent(&kafka.Event{
				FlowID:     config.FlowID,
				TupleID:    config.TupleID,
				Timestamp:  time.Now(),
				SrcIP:      config.SrcIP,
				SrcPort:    config.SrcPort,
				DstIP:      config.DstIP,
				DstPort:    config.DstPort,
				NDPIProto:  "SSH",
				NDPIApp:    "username",
				AttackType: user,
				Honeypot:   config.TargetAddr,
				Instance:   "proxy",
			})
			config.OnEvent(&kafka.Event{
				FlowID:     config.FlowID,
				TupleID:    config.TupleID,
				Timestamp:  time.Now(),
				SrcIP:      config.SrcIP,
				SrcPort:    config.SrcPort,
				DstIP:      config.DstIP,
				DstPort:    config.DstPort,
				NDPIProto:  "SSH",
				NDPIApp:    "password",
				AttackType: pass,
				Honeypot:   config.TargetAddr,
				Instance:   "proxy",
			})
		}

		if tryAuthOnHoneypot(config.TargetAddr, user, pass, logger) {
			logger("SSH MITM: autenticação aceita pelo honeypot")
			authMu.Lock()
			capturedUser = user
			capturedPass = pass
			authSuccess = true
			authMu.Unlock()
			return &ssh.Permissions{}, nil
		}

		logger("SSH MITM: autenticação rejeitada pelo honeypot")
		if config.OnEvent != nil {
			config.OnEvent(&kafka.Event{
				FlowID:     config.FlowID,
				TupleID:    config.TupleID,
				Timestamp:  time.Now(),
				SrcIP:      config.SrcIP,
				SrcPort:    config.SrcPort,
				DstIP:      config.DstIP,
				DstPort:    config.DstPort,
				NDPIProto:  "SSH",
				NDPIApp:    "auth_failed",
				AttackType: "Authentication failed — rejected by honeypot.",
				Honeypot:   config.TargetAddr,
				Instance:   "proxy",
			})
		}
		return nil, fmt.Errorf("permission denied")
	}

	serverConfig.AddHostKey(config.HostKey)

	conn, chans, reqs, err := ssh.NewServerConn(clientConn, serverConfig)
	if err != nil {
		errStr := err.Error()
		isAuthFailure := strings.Contains(errStr, "permission denied") || strings.Contains(errStr, "no auth passed yet")
		if !isAuthFailure && config.OnEvent != nil {
			config.OnEvent(&kafka.Event{
				FlowID:     config.FlowID,
				TupleID:    config.TupleID,
				Timestamp:  time.Now(),
				SrcIP:      config.SrcIP,
				SrcPort:    config.SrcPort,
				DstIP:      config.DstIP,
				DstPort:    config.DstPort,
				NDPIProto:  "SSH",
				NDPIApp:    "wrong_key",
				AttackType: "client disconnected before handshake (possible wrong host key)",
				Honeypot:   config.TargetAddr,
				Instance:   "proxy",
			})
		}
		clientConn.Close() //nolint:errcheck
		return fmt.Errorf("ssh handshake falhou: %w", err)
	}
	defer conn.Close()

	authMu.Lock()
	success := authSuccess
	user := capturedUser
	pass := capturedPass
	authMu.Unlock()

	if !success {
		logger("SSH MITM: autenticação falhou, conexão será encerrada")
		return nil
	}

	targetConn, err := net.DialTimeout("tcp", config.TargetAddr, 5*time.Second)
	if err != nil {
		return fmt.Errorf("falha ao conectar no honeypot: %w", err)
	}
	defer targetConn.Close()
	if !config.Deadline.IsZero() {
		targetConn.SetDeadline(config.Deadline) //nolint:errcheck
	}

	targetSSHConn, _, targetGlobalReqs, err := ssh.NewClientConn(targetConn, config.TargetAddr, &ssh.ClientConfig{
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Auth:            []ssh.AuthMethod{ssh.Password(pass)},
		User:            user,
	})
	if err != nil {
		return fmt.Errorf("ssh handshake honeypot failed: %w", err)
	}
	defer targetSSHConn.Close()

	go ssh.DiscardRequests(reqs)
	go ssh.DiscardRequests(targetGlobalReqs)

	var chanWg sync.WaitGroup

	for newChannel := range chans {
		logger("SSH MITM: novo channel recebido: %s", newChannel.ChannelType())

		targetChannel, targetReqs, err := targetSSHConn.OpenChannel(newChannel.ChannelType(), newChannel.ExtraData())
		if err != nil {
			logger("SSH MITM: falha ao abrir channel no honeypot: %v", err)
			newChannel.Reject(ssh.Prohibited, "falha ao abrir channel") //nolint:errcheck
			continue
		}

		clientChannel, clientReqs, err := newChannel.Accept()
		if err != nil {
			logger("SSH MITM: falha ao aceitar channel do cliente: %v", err)
			targetChannel.Close() //nolint:errcheck
			continue
		}

		sshSession := NewSSHSession(
			config.FlowID,
			config.SrcIP, config.SrcPort,
			config.DstIP, config.DstPort,
			config.TargetAddr,
			config.OnEvent, logger,
			config.SSHInputBufSize, config.SSHOutputBufSize,
		)

		chanWg.Add(6)

		go func() { defer chanWg.Done(); forwardRequests(targetChannel, clientReqs, logger, config.OnEvent, config) }()
		go func() { defer chanWg.Done(); forwardRequests(clientChannel, targetReqs, logger, config.OnEvent, config) }()

		go func() {
			defer chanWg.Done()
			defer targetChannel.Close()
			defer clientChannel.Close()
			defer sshSession.Close()
			buf := make([]byte, 4096)
			for {
				n, err := clientChannel.Read(buf)
				if n > 0 {
					sshSession.HandleInput(buf[:n])
					targetChannel.Write(buf[:n]) //nolint:errcheck
				}
				if err != nil {
					break
				}
			}
		}()

		go func() {
			defer chanWg.Done()
			defer targetChannel.Close()
			defer clientChannel.Close()
			buf := make([]byte, 4096)
			for {
				n, err := targetChannel.Read(buf)
				if n > 0 {
					sshSession.HandleOutput(buf[:n])
					clientChannel.Write(buf[:n]) //nolint:errcheck
				}
				if err != nil {
					break
				}
			}
		}()

		go func() {
			defer chanWg.Done()
			defer func() { recover() }() //nolint:errcheck
			io.Copy(clientChannel.Stderr(), targetChannel.Stderr()) //nolint:errcheck
		}()

		go func() {
			defer chanWg.Done()
			defer func() { recover() }() //nolint:errcheck
			io.Copy(targetChannel.Stderr(), clientChannel.Stderr()) //nolint:errcheck
		}()
	}

	chanWg.Wait()
	return nil
}

func forwardRequests(dst ssh.Channel, reqs <-chan *ssh.Request, logger func(string, ...interface{}), onEvent func(*kafka.Event), config SSHMITMConfig) {
	for req := range reqs {
		logger("SSH MITM: encaminhando request tipo=%s wantReply=%v payload=%d bytes",
			req.Type, req.WantReply, len(req.Payload))

		if onEvent != nil && (req.Type == "exit-status" || req.Type == "exit-signal") {
			onEvent(&kafka.Event{
				FlowID:     config.FlowID,
				TupleID:    config.TupleID,
				Timestamp:  time.Now(),
				SrcIP:      config.SrcIP,
				SrcPort:    config.SrcPort,
				DstIP:      config.DstIP,
				DstPort:    config.DstPort,
				NDPIProto:  "SSH",
				NDPIApp:    "exit",
				Honeypot:   config.TargetAddr,
				AttackType: decodeSSHExitPayload(req.Type, req.Payload),
				Instance:   "proxy",
			})
		}

		ok, err := dst.SendRequest(req.Type, req.WantReply, req.Payload)
		if err != nil {
			logger("SSH MITM: erro ao encaminhar request %s: %v", req.Type, err)
			if req.WantReply {
				req.Reply(false, nil) //nolint:errcheck
			}
			continue
		}
		if req.WantReply {
			req.Reply(ok, nil) //nolint:errcheck
		}
	}
}

func tryAuthOnHoneypot(targetAddr, user, pass string, logger func(string, ...interface{})) bool {
	tcpConn, err := net.DialTimeout("tcp", targetAddr, 5*time.Second)
	if err != nil {
		logger("SSH MITM: falha ao conectar no honeypot para autenticação: %v", err)
		return false
	}
	sshConn, _, _, err := ssh.NewClientConn(tcpConn, targetAddr, &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.Password(pass)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
	if err != nil {
		logger("SSH MITM: autenticação no honeypot falhou: %s", err.Error())
		tcpConn.Close() //nolint:errcheck
		return false
	}
	logger("SSH MITM: autenticação no honeypot bem-sucedida")
	sshConn.Close() //nolint:errcheck
	return true
}

func decodeSSHExitPayload(reqType string, payload []byte) string {
	switch reqType {
	case "exit-status":
		if len(payload) == 4 {
			return fmt.Sprintf("exit_code:%d", binary.BigEndian.Uint32(payload))
		}
	case "exit-signal":
		if len(payload) >= 4 {
			nameLen := binary.BigEndian.Uint32(payload)
			if nameLen <= uint32(len(payload)-4) {
				return fmt.Sprintf("signal:%s", payload[4:4+nameLen])
			}
		}
	}
	return fmt.Sprintf("%s:hex:%x", reqType, payload)
}
