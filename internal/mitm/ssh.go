package mitm

import (
	"bytes"
	"crypto/md5" //nolint:gosec
	"encoding/binary"
	"encoding/hex"
	"errors"
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
	Banner           string // raw firstChunk from client (client SSH banner bytes)
	ServerVersion    string // SSH server version string to present to attacker
	HostKeys         []ssh.Signer
	TargetAddr       string
	MaxPayloadSize   int64
	SSHInputBufSize  int
	SSHOutputBufSize int
	ServerConfig     *ssh.ServerConfig
	OnEvent          func(event *kafka.Event)
	OnAuthExhausted  func(attempts int, hassh, algos string) // called when client exhausts all auth attempts
	HASSH            string                                   // populated by HandleSSH after KEXINIT exchange
	HASSHAlgos       string
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

// authTracker records the sequence and count of authentication method attempts.
type authTracker struct {
	mu       sync.Mutex
	methods  []string
	attempts int
}

func (t *authTracker) add(method string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.methods = append(t.methods, method)
	t.attempts++
}

func (t *authTracker) joined() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return strings.Join(t.methods, ",")
}

func (t *authTracker) count() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.attempts
}

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
		FlowID:      s.flowID,
		Timestamp:   time.Now(),
		SrcIP:       s.srcIP,
		SrcPort:     s.srcPort,
		DstIP:       s.dstIP,
		DstPort:     s.dstPort,
		NDPIProto:   "SSH",
		NDPIApp:     "response",
		SSHResponse: strings.TrimSpace(s.pendingResp),
		Honeypot:    s.honeypot,
		Instance:    "proxy",
	})
	s.logger("SSH-MITM: resposta publicada no Kafka: %d bytes", len(s.pendingResp))
	s.pendingResp = ""
}

// kexInitCapture wraps a net.Conn and passively reads the SSH_MSG_KEXINIT (type=20)
// packet to compute the HASSH fingerprint (MD5 of kex;enc_c2s;mac_c2s;cmp_c2s).
// All bytes are passed through unchanged — the SSH library sees the full stream.
type kexInitCapture struct {
	net.Conn
	raw    []byte
	parsed bool
	hassh  string
	algos  string
}

func (k *kexInitCapture) Read(p []byte) (int, error) {
	n, err := k.Conn.Read(p)
	if n > 0 && !k.parsed {
		k.raw = append(k.raw, p[:n]...)
		k.tryParse()
	}
	return n, err
}

func (k *kexInitCapture) tryParse() {
	data := k.raw
	// Phase 1: skip client banner (text, ends with \n)
	nlIdx := bytes.IndexByte(data, '\n')
	if nlIdx < 0 {
		return
	}
	data = data[nlIdx+1:]
	// Phase 2: parse SSH binary packet header (4-byte length + 1-byte padding_len + 1-byte type)
	if len(data) < 6 {
		return
	}
	pktLen := binary.BigEndian.Uint32(data[0:4])
	if pktLen < 17 || pktLen > 65535 {
		k.parsed = true
		return
	}
	if uint32(len(data)) < 4+pktLen {
		return // wait for more data
	}
	paddingLen := int(data[4])
	if data[5] != 20 { // SSH_MSG_KEXINIT
		k.parsed = true
		return
	}
	payloadLen := int(pktLen) - 1 - paddingLen
	if payloadLen < 1+16+4 {
		k.parsed = true
		return
	}
	payload := data[5 : 5+payloadLen]
	pos := 1 + 16 // skip type byte (20) + 16-byte cookie

	readNameList := func() (string, bool) {
		if pos+4 > len(payload) {
			return "", false
		}
		l := int(binary.BigEndian.Uint32(payload[pos : pos+4]))
		pos += 4
		if l < 0 || pos+l > len(payload) {
			return "", false
		}
		s := string(payload[pos : pos+l])
		pos += l
		return s, true
	}

	kex, ok := readNameList() // kex_algorithms
	if !ok {
		k.parsed = true
		return
	}
	if _, ok = readNameList(); !ok { // server_host_key_algorithms (skip)
		k.parsed = true
		return
	}
	encC2s, ok := readNameList() // encryption_algorithms_client_to_server
	if !ok {
		k.parsed = true
		return
	}
	if _, ok = readNameList(); !ok { // encryption_algorithms_server_to_client (skip)
		k.parsed = true
		return
	}
	macC2s, ok := readNameList() // mac_algorithms_client_to_server
	if !ok {
		k.parsed = true
		return
	}
	if _, ok = readNameList(); !ok { // mac_algorithms_server_to_client (skip)
		k.parsed = true
		return
	}
	cmpC2s, ok := readNameList() // compression_algorithms_client_to_server
	if !ok {
		k.parsed = true
		return
	}

	algos := kex + ";" + encC2s + ";" + macC2s + ";" + cmpC2s
	sum := md5.Sum([]byte(algos)) //nolint:gosec
	k.hassh = hex.EncodeToString(sum[:])
	k.algos = algos
	k.parsed = true
}

// HandleSSH performs a full SSH MITM:
//  1. Presents proxy's host key to the client and captures credentials via callbacks.
//  2. Validates credentials against the honeypot (tryAuthOnHoneypot).
//  3. Opens a real SSH session to the honeypot with the captured credentials.
//  4. Relays channels bidirectionally, recording commands and responses.
func HandleSSH(clientConn net.Conn, config SSHMITMConfig, logger func(string, ...interface{})) error {
	logger("SSH MITM: iniciando handshake")

	if !config.Deadline.IsZero() {
		clientConn.SetDeadline(config.Deadline) //nolint:errcheck
	}

	serverVersion := "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1"
	if config.ServerVersion != "" {
		serverVersion = config.ServerVersion
	}
	serverConfig := &ssh.ServerConfig{
		NoClientAuth:  false,
		ServerVersion: serverVersion,
	}

	var authMu sync.Mutex
	var authSuccess bool
	var capturedUser, capturedPass string

	tracker := &authTracker{}
	kexCapture := &kexInitCapture{Conn: clientConn}

	serverConfig.PublicKeyCallback = func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		tracker.add("publickey")
		if config.OnEvent != nil {
			config.OnEvent(&kafka.Event{
				FlowID:          config.FlowID,
				TupleID:         config.TupleID,
				Timestamp:       time.Now(),
				SrcIP:           config.SrcIP,
				SrcPort:         config.SrcPort,
				DstIP:           config.DstIP,
				DstPort:         config.DstPort,
				NDPIProto:       "SSH",
				NDPIApp:         "pubkey_attempt",
				AttackType:      conn.User(),
				SSHKeyType:      key.Type(),
				SSHFingerprint:  ssh.FingerprintSHA256(key),
				SSHPublicKey:    strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))),
				SSHAuthMethods:  tracker.joined(),
				SSHAuthAttempts: tracker.count(),
				HASSH:           kexCapture.hassh,
				HASSHAlgos:      kexCapture.algos,
				Honeypot:        config.TargetAddr,
				Instance:        "proxy",
			})
		}
		return nil, errors.New("publickey auth not accepted")
	}

	serverConfig.KeyboardInteractiveCallback = func(conn ssh.ConnMetadata, challenge ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
		tracker.add("keyboard-interactive")
		answers, err := challenge("", "", []string{"Password: "}, []bool{false})
		if err != nil || len(answers) == 0 {
			return nil, errors.New("keyboard-interactive auth not accepted")
		}
		pass := answers[0]
		if config.OnEvent != nil {
			user := conn.User()
			config.OnEvent(&kafka.Event{
				FlowID:         config.FlowID,
				TupleID:        config.TupleID,
				Timestamp:      time.Now(),
				SrcIP:          config.SrcIP,
				SrcPort:        config.SrcPort,
				DstIP:          config.DstIP,
				DstPort:        config.DstPort,
				NDPIProto:      "SSH",
				NDPIApp:        "username",
				AttackType:     user,
				SSHUserHex:     hex.EncodeToString([]byte(user)),
				SSHAuthMethods: tracker.joined(),
				HASSH:          kexCapture.hassh,
				HASSHAlgos:     kexCapture.algos,
				Honeypot:       config.TargetAddr,
				Instance:       "proxy",
			})
			config.OnEvent(&kafka.Event{
				FlowID:          config.FlowID,
				TupleID:         config.TupleID,
				Timestamp:       time.Now(),
				SrcIP:           config.SrcIP,
				SrcPort:         config.SrcPort,
				DstIP:           config.DstIP,
				DstPort:         config.DstPort,
				NDPIProto:       "SSH",
				NDPIApp:         "keyboard_interactive",
				AttackType:      pass,
				SSHPassHex:      hex.EncodeToString([]byte(pass)),
				SSHAuthMethods:  tracker.joined(),
				SSHAuthAttempts: tracker.count(),
				HASSH:           kexCapture.hassh,
				HASSHAlgos:      kexCapture.algos,
				Honeypot:        config.TargetAddr,
				Instance:        "proxy",
			})
		}
		if tryAuthOnHoneypot(config.TargetAddr, conn.User(), pass, logger) {
			authMu.Lock()
			capturedUser = conn.User()
			capturedPass = pass
			authSuccess = true
			authMu.Unlock()
			return &ssh.Permissions{}, nil
		}
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
				HASSH:      kexCapture.hassh,
				HASSHAlgos: kexCapture.algos,
				Honeypot:   config.TargetAddr,
				Instance:   "proxy",
			})
		}
		return nil, errors.New("keyboard-interactive auth not accepted")
	}

	serverConfig.PasswordCallback = func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
		user := conn.User()
		pass := string(password)
		logger("SSH MITM: credenciais capturadas — user=%s", user)

		tracker.add("password")

		if config.OnEvent != nil {
			config.OnEvent(&kafka.Event{
				FlowID:          config.FlowID,
				TupleID:         config.TupleID,
				Timestamp:       time.Now(),
				SrcIP:           config.SrcIP,
				SrcPort:         config.SrcPort,
				DstIP:           config.DstIP,
				DstPort:         config.DstPort,
				NDPIProto:       "SSH",
				NDPIApp:         "username",
				AttackType:      user,
				SSHUserHex:      hex.EncodeToString([]byte(user)),
				SSHAuthMethods:  tracker.joined(),
				SSHAuthAttempts: tracker.count(),
				HASSH:           kexCapture.hassh,
				HASSHAlgos:      kexCapture.algos,
				Honeypot:        config.TargetAddr,
				Instance:        "proxy",
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
				SSHPassHex: hex.EncodeToString(password),
				HASSH:      kexCapture.hassh,
				HASSHAlgos: kexCapture.algos,
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
				HASSH:      kexCapture.hassh,
				HASSHAlgos: kexCapture.algos,
				Honeypot:   config.TargetAddr,
				Instance:   "proxy",
			})
		}
		return nil, fmt.Errorf("permission denied")
	}

	for _, hk := range config.HostKeys {
		serverConfig.AddHostKey(hk)
	}

	conn, chans, reqs, err := ssh.NewServerConn(kexCapture, serverConfig)
	if err != nil {
		errStr := err.Error()
		isAuthDenied := strings.Contains(errStr, "permission denied")
		isProbe := strings.Contains(errStr, "no auth passed yet") ||
			strings.Contains(errStr, "unexpected EOF") ||
			strings.Contains(errStr, "connection reset by peer")
		switch {
		case isAuthDenied:
			if config.OnAuthExhausted != nil {
				config.OnAuthExhausted(tracker.count(), kexCapture.hassh, kexCapture.algos)
			}
		case isProbe:
			if config.OnEvent != nil {
				config.OnEvent(&kafka.Event{
					FlowID:          config.FlowID,
					TupleID:         config.TupleID,
					Timestamp:       time.Now(),
					SrcIP:           config.SrcIP,
					SrcPort:         config.SrcPort,
					DstIP:           config.DstIP,
					DstPort:         config.DstPort,
					NDPIProto:       "SSH",
					NDPIApp:         "ssh_probe",
					AttackType:      "scanner probe (disconnected without auth)",
					SSHClientBanner: strings.TrimRight(config.Banner, "\r\n"),
					SSHServerBanner: serverVersion,
					HASSH:           kexCapture.hassh,
					HASSHAlgos:      kexCapture.algos,
					Honeypot:        config.TargetAddr,
					Instance:        "proxy",
				})
			}
		default:
			if config.OnEvent != nil {
				config.OnEvent(&kafka.Event{
					FlowID:          config.FlowID,
					TupleID:         config.TupleID,
					Timestamp:       time.Now(),
					SrcIP:           config.SrcIP,
					SrcPort:         config.SrcPort,
					DstIP:           config.DstIP,
					DstPort:         config.DstPort,
					NDPIProto:       "SSH",
					NDPIApp:         "wrong_key",
					AttackType:      "client disconnected before handshake (possible wrong host key)",
					SSHClientBanner: strings.TrimRight(config.Banner, "\r\n"),
					HASSH:           kexCapture.hassh,
					HASSHAlgos:      kexCapture.algos,
					Honeypot:        config.TargetAddr,
					Instance:        "proxy",
				})
			}
		}
		clientConn.Close() //nolint:errcheck
		return fmt.Errorf("ssh handshake falhou: %w", err)
	}
	defer conn.Close()

	config.HASSH = kexCapture.hassh
	config.HASSHAlgos = kexCapture.algos

	// Emit client banner event immediately after successful handshake.
	if config.OnEvent != nil {
		config.OnEvent(&kafka.Event{
			FlowID:          config.FlowID,
			TupleID:         config.TupleID,
			Timestamp:       time.Now(),
			SrcIP:           config.SrcIP,
			SrcPort:         config.SrcPort,
			DstIP:           config.DstIP,
			DstPort:         config.DstPort,
			NDPIProto:       "SSH",
			NDPIApp:         "client_banner",
			SSHClientBanner: string(conn.ClientVersion()),
			SSHServerBanner: serverVersion,
			HASSH:           config.HASSH,
			HASSHAlgos:      config.HASSHAlgos,
			Honeypot:        config.TargetAddr,
			Instance:        "proxy",
		})
	}

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
		chanType := newChannel.ChannelType()
		logger("SSH MITM: novo channel recebido: %s", chanType)

		if config.OnEvent != nil {
			ev := &kafka.Event{
				FlowID:         config.FlowID,
				TupleID:        config.TupleID,
				Timestamp:      time.Now(),
				SrcIP:          config.SrcIP,
				SrcPort:        config.SrcPort,
				DstIP:          config.DstIP,
				DstPort:        config.DstPort,
				NDPIProto:      "SSH",
				NDPIApp:        "channel_open",
				SSHChannelType: chanType,
				HASSH:          config.HASSH,
				HASSHAlgos:     config.HASSHAlgos,
				Honeypot:       config.TargetAddr,
				Instance:       "proxy",
			}
			if chanType == "direct-tcpip" {
				var tcpipReq struct {
					DestAddr string
					DestPort uint32
					SrcAddr  string
					SrcPort  uint32
				}
				if ssh.Unmarshal(newChannel.ExtraData(), &tcpipReq) == nil {
					ev.AttackType = fmt.Sprintf("%s:%d", tcpipReq.DestAddr, tcpipReq.DestPort)
				}
			}
			config.OnEvent(ev)
		}

		targetChannel, targetReqs, err := targetSSHConn.OpenChannel(chanType, newChannel.ExtraData())
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

		if onEvent != nil {
			switch req.Type {
			case "exit-status", "exit-signal":
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
					HASSH:      config.HASSH,
					HASSHAlgos: config.HASSHAlgos,
					Instance:   "proxy",
				})
			case "pty-req":
				var ptyReq struct {
					Term   string
					Cols   uint32
					Rows   uint32
					PixelW uint32
					PixelH uint32
					Modes  string
				}
				if ssh.Unmarshal(req.Payload, &ptyReq) == nil {
					onEvent(&kafka.Event{
						FlowID:     config.FlowID,
						TupleID:    config.TupleID,
						Timestamp:  time.Now(),
						SrcIP:      config.SrcIP,
						SrcPort:    config.SrcPort,
						DstIP:      config.DstIP,
						DstPort:    config.DstPort,
						NDPIProto:  "SSH",
						NDPIApp:    "pty_request",
						SSHPtyTerm: ptyReq.Term,
						SSHPtyCols: ptyReq.Cols,
						SSHPtyRows: ptyReq.Rows,
						HASSH:      config.HASSH,
						HASSHAlgos: config.HASSHAlgos,
						Honeypot:   config.TargetAddr,
						Instance:   "proxy",
					})
				}
			case "exec":
				var execReq struct{ Cmd string }
				if ssh.Unmarshal(req.Payload, &execReq) == nil && execReq.Cmd != "" {
					onEvent(&kafka.Event{
						FlowID:     config.FlowID,
						TupleID:    config.TupleID,
						Timestamp:  time.Now(),
						SrcIP:      config.SrcIP,
						SrcPort:    config.SrcPort,
						DstIP:      config.DstIP,
						DstPort:    config.DstPort,
						NDPIProto:  "SSH",
						NDPIApp:    "exec",
						SSHExecCmd: execReq.Cmd,
						AttackType: execReq.Cmd,
						HASSH:      config.HASSH,
						HASSHAlgos: config.HASSHAlgos,
						Honeypot:   config.TargetAddr,
						Instance:   "proxy",
					})
				}
			case "subsystem":
				var subsysReq struct{ Name string }
				if ssh.Unmarshal(req.Payload, &subsysReq) == nil && subsysReq.Name != "" {
					onEvent(&kafka.Event{
						FlowID:       config.FlowID,
						TupleID:      config.TupleID,
						Timestamp:    time.Now(),
						SrcIP:        config.SrcIP,
						SrcPort:      config.SrcPort,
						DstIP:        config.DstIP,
						DstPort:      config.DstPort,
						NDPIProto:    "SSH",
						NDPIApp:      "subsystem",
						SSHSubsystem: subsysReq.Name,
						AttackType:   subsysReq.Name,
						HASSH:        config.HASSH,
						HASSHAlgos:   config.HASSHAlgos,
						Honeypot:     config.TargetAddr,
						Instance:     "proxy",
					})
				}
			case "env":
				var envReq struct{ Name, Value string }
				if ssh.Unmarshal(req.Payload, &envReq) == nil && envReq.Name != "" {
					onEvent(&kafka.Event{
						FlowID:     config.FlowID,
						TupleID:    config.TupleID,
						Timestamp:  time.Now(),
						SrcIP:      config.SrcIP,
						SrcPort:    config.SrcPort,
						DstIP:      config.DstIP,
						DstPort:    config.DstPort,
						NDPIProto:  "SSH",
						NDPIApp:    "env",
						AttackType: envReq.Name + "=" + envReq.Value,
						HASSH:      config.HASSH,
						HASSHAlgos: config.HASSHAlgos,
						Honeypot:   config.TargetAddr,
						Instance:   "proxy",
					})
				}
			case "shell":
				onEvent(&kafka.Event{
					FlowID:     config.FlowID,
					TupleID:    config.TupleID,
					Timestamp:  time.Now(),
					SrcIP:      config.SrcIP,
					SrcPort:    config.SrcPort,
					DstIP:      config.DstIP,
					DstPort:    config.DstPort,
					NDPIProto:  "SSH",
					NDPIApp:    "shell_open",
					HASSH:      config.HASSH,
					HASSHAlgos: config.HASSHAlgos,
					Honeypot:   config.TargetAddr,
					Instance:   "proxy",
				})
			}
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
