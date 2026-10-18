package mitm

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"time"
)

type CaptureEventType string

const (
	EventBanner        CaptureEventType = "banner"
	EventCredential    CaptureEventType = "credential"
	EventCommand       CaptureEventType = "command"
	EventResponse      CaptureEventType = "response"
	EventRawData       CaptureEventType = "raw_data"
	EventVNCVersion    CaptureEventType = "vnc_version"
	EventVNCSecType    CaptureEventType = "vnc_security"
	EventVNCAuth       CaptureEventType = "vnc_auth"
	EventVNCResult     CaptureEventType = "vnc_result"
	EventSMTPRelayProbe CaptureEventType = "smtp_relay_probe"
)

type CaptureEvent struct {
	FlowID     string           `json:"flow_id"`
	Timestamp  time.Time        `json:"timestamp"`
	SrcIP      string           `json:"src_ip"`
	SrcPort    int              `json:"src_port"`
	DstIP      string           `json:"dst_ip"`
	DstPort    int              `json:"dst_port"`
	Protocol   string           `json:"protocol"`
	Honeypot   string           `json:"honeypot"`
	Direction  string           `json:"direction"`
	EventType  CaptureEventType `json:"event_type"`
	RawPayload string           `json:"raw_payload,omitempty"`
	Username   string           `json:"username,omitempty"`
	Password   string           `json:"password,omitempty"`
	Command    string           `json:"command,omitempty"`
	Response   string           `json:"response,omitempty"`
	Banner     string           `json:"banner,omitempty"`

	// Telnet MITM
	TelnetAttempt int `json:"telnet_attempt,omitempty"`

	// VNC RFB tap
	VNCServerVersion string `json:"vnc_server_version,omitempty"`
	VNCClientVersion string `json:"vnc_client_version,omitempty"`
	VNCSecType       int    `json:"vnc_sec_type,omitempty"`
	VNCAuthHash      string `json:"vnc_auth_hash,omitempty"`
	VNCAuthResult    string `json:"vnc_auth_result,omitempty"`

	// SMTP relay probe
	SMTPSender    string `json:"smtp_sender,omitempty"`
	SMTPRecipient string `json:"smtp_recipient,omitempty"`
}

type ProtocolParser interface {
	ParseClientData(data []byte, logger func(string, ...interface{})) []CaptureEvent
	ParseServerData(data []byte, logger func(string, ...interface{})) []CaptureEvent
}

// BiParser is implemented by stateful parsers that need ordered server/client
// data to correctly classify events. FeedServer and FeedClient are called in
// the actual order data arrives over the wire.
type BiParser interface {
	FeedServer(data []byte) []CaptureEvent
	FeedClient(data []byte) []CaptureEvent
}

type RawParser struct{}

func (p *RawParser) ParseClientData(data []byte, logger func(string, ...interface{})) []CaptureEvent {
	return []CaptureEvent{{
		EventType:  EventRawData,
		Direction:  "client->honeypot",
		RawPayload: hex.EncodeToString(data),
	}}
}

func (p *RawParser) ParseServerData(data []byte, logger func(string, ...interface{})) []CaptureEvent {
	return []CaptureEvent{{
		EventType:  EventRawData,
		Direction:  "honeypot->client",
		RawPayload: hex.EncodeToString(data),
	}}
}

// MySQLSession is a stateful BiParser for MySQL server-first relay.
// FeedServer captures the 20-byte auth challenge from the Initial Handshake (seq=0);
// FeedClient parses HandshakeResponse41 (seq=1) and emits a mysql_login event
// with a hashcat mode-11200-compatible hash when mysql_native_password is used.
type MySQLSession struct {
	salt       []byte // 20-byte auth-plugin-data from server
	authPlugin string // e.g. "mysql_native_password"
}

func (s *MySQLSession) FeedServer(data []byte) []CaptureEvent {
	// Only parse the Initial Handshake (seq=0, protocol version=0x0a).
	if len(data) < 5 || data[3] != 0 || data[4] != 0x0a {
		return nil
	}
	payload := data[4:]
	i := 1 // skip protocol version byte
	for i < len(payload) && payload[i] != 0x00 {
		i++ // skip server version string
	}
	i++    // skip null terminator
	i += 4 // skip connection ID
	if i+8 > len(payload) {
		return nil
	}
	part1 := payload[i : i+8]
	i += 9 // skip auth-plugin-data-part-1 (8) + filler (1)
	if i+7 > len(payload) {
		return nil
	}
	// capability lower (2) + charset (1) + status (2) + capability upper (2) = 7 bytes
	i += 7
	if i >= len(payload) {
		return nil
	}
	authDataLen := int(payload[i])
	i += 11 // skip auth-plugin-data-len (1) + reserved (10)
	// auth-plugin-data-part-2: max(13, authDataLen-8) bytes (incl. null terminator)
	part2Len := authDataLen - 8
	if part2Len < 13 {
		part2Len = 13
	}
	if i+part2Len > len(payload) {
		part2Len = len(payload) - i
	}
	salt := append([]byte(nil), part1...)
	if part2Len > 0 {
		take := part2Len - 1 // drop null terminator byte
		if take > 12 {
			take = 12
		}
		salt = append(salt, payload[i:i+take]...)
	}
	if len(salt) == 20 {
		s.salt = salt
	}
	i += part2Len
	// auth-plugin-name (null-terminated)
	if i < len(payload) {
		end := i
		for end < len(payload) && payload[end] != 0x00 {
			end++
		}
		s.authPlugin = string(payload[i:end])
	}
	version := extractMySQLVersion(data)
	banner := "MySQL"
	if version != "" {
		banner = "MySQL " + version
	}
	return []CaptureEvent{{EventType: EventBanner, Direction: "honeypot->client", Banner: banner}}
}

func (s *MySQLSession) FeedClient(data []byte) []CaptureEvent {
	// Only parse HandshakeResponse41 (seq=1).
	if len(data) < 5 || data[3] != 1 {
		return nil
	}
	payload := data[4:]
	// caps(4) + max_packet(4) + charset(1) + reserved(23) = 32 bytes before username
	if len(payload) < 33 {
		return nil
	}
	caps := uint32(payload[0]) | uint32(payload[1])<<8 | uint32(payload[2])<<16 | uint32(payload[3])<<24
	i := 32
	userStart := i
	for i < len(payload) && payload[i] != 0x00 {
		i++
	}
	username := string(payload[userStart:i])
	if i >= len(payload) {
		return nil
	}
	i++ // skip null
	// auth response length: lenenc if CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA, else 1 byte
	const clientPluginAuthLenenc = uint32(1 << 21)
	var authLen int
	if caps&clientPluginAuthLenenc != 0 {
		if i >= len(payload) {
			return nil
		}
		fb := payload[i]
		i++
		switch {
		case fb < 0xfb:
			authLen = int(fb)
		case fb == 0xfc:
			if i+2 > len(payload) {
				return nil
			}
			authLen = int(payload[i]) | int(payload[i+1])<<8
			i += 2
		default:
			return nil
		}
	} else {
		if i >= len(payload) {
			return nil
		}
		authLen = int(payload[i])
		i++
	}
	if authLen < 0 || i+authLen > len(payload) {
		return nil
	}
	authResp := payload[i : i+authLen]
	usernameEv := CaptureEvent{
		EventType: EventCredential,
		Direction: "client->honeypot",
		Username:  username,
	}
	events := []CaptureEvent{usernameEv}
	if len(s.salt) == 20 && len(authResp) == 20 {
		plugin := s.authPlugin
		if plugin == "" {
			plugin = "mysql_native_password"
		}
		var authHash string
		if plugin == "mysql_native_password" {
			authHash = fmt.Sprintf("$mysqlna$%s*%s",
				hex.EncodeToString(s.salt), hex.EncodeToString(authResp))
		} else {
			authHash = fmt.Sprintf("%s:%s*%s",
				plugin, hex.EncodeToString(s.salt), hex.EncodeToString(authResp))
		}
		events = append(events, CaptureEvent{
			EventType: EventCredential,
			Direction: "client->honeypot",
			Password:  authHash,
		})
	}
	return events
}

func (s *MySQLSession) ParseClientData(data []byte, logger func(string, ...interface{})) []CaptureEvent {
	user := extractMySQLUsername(data, logger)
	if user != "" {
		return []CaptureEvent{{EventType: EventCredential, Direction: "client->honeypot", Username: user}}
	}
	if len(data) > 5 {
		return []CaptureEvent{{EventType: EventRawData, Direction: "client->honeypot", RawPayload: hex.EncodeToString(data)}}
	}
	return nil
}

func (s *MySQLSession) ParseServerData(data []byte, logger func(string, ...interface{})) []CaptureEvent {
	if len(data) > 5 {
		if version := extractMySQLVersion(data); version != "" {
			return []CaptureEvent{{EventType: EventBanner, Direction: "honeypot->client", Banner: fmt.Sprintf("MySQL %s", version)}}
		}
	}
	return []CaptureEvent{{EventType: EventRawData, Direction: "honeypot->client", RawPayload: hex.EncodeToString(data)}}
}

// FTPBiParser is a stateful BiParser that accumulates the USER command across
// chunks and emits a single ftp_login event with both username and password
// when the PASS command arrives.
type FTPBiParser struct {
	username string
	buf      []byte
}

func (p *FTPBiParser) FeedClient(data []byte) []CaptureEvent {
	p.buf = append(p.buf, data...)
	var events []CaptureEvent
	for {
		idx := bytes.Index(p.buf, []byte("\r\n"))
		if idx < 0 {
			break
		}
		line := string(p.buf[:idx])
		p.buf = p.buf[idx+2:]
		upper := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(upper, "USER "):
			p.username = strings.TrimSpace(line[5:])
		case strings.HasPrefix(upper, "PASS "):
			password := strings.TrimSpace(line[5:])
			events = append(events,
				CaptureEvent{EventType: EventCredential, Direction: "client->honeypot",
					Username: p.username},
				CaptureEvent{EventType: EventCredential, Direction: "client->honeypot",
					Password: password},
			)
		case line != "":
			events = append(events, CaptureEvent{
				EventType: EventCommand,
				Direction: "client->honeypot",
				Command:   line,
			})
		}
	}
	return events
}

func (p *FTPBiParser) FeedServer(data []byte) []CaptureEvent {
	text := strings.TrimSpace(string(data))
	if strings.HasPrefix(text, "220") {
		return []CaptureEvent{{EventType: EventBanner, Direction: "honeypot->client", Banner: text}}
	}
	return nil
}

func (p *FTPBiParser) ParseClientData(data []byte, _ func(string, ...interface{})) []CaptureEvent {
	return p.FeedClient(data)
}

func (p *FTPBiParser) ParseServerData(data []byte, _ func(string, ...interface{})) []CaptureEvent {
	return p.FeedServer(data)
}

var smtpCommandPrefixes = []string{
	"EHLO", "HELO", "MAIL", "RCPT", "DATA", "QUIT", "RSET",
	"NOOP", "VRFY", "EXPN", "HELP", "STARTTLS", "AUTH",
}

// SMTPSession is a stateful BiParser for SMTP relay.
// It tracks the envelope sender and emits smtp_relay_probe events for each RCPT TO.
type SMTPSession struct {
	sender string
}

func (s *SMTPSession) FeedServer(data []byte) []CaptureEvent {
	var events []CaptureEvent
	for _, raw := range strings.Split(string(data), "\n") {
		text := strings.TrimSpace(strings.TrimRight(raw, "\r"))
		if text == "" {
			continue
		}
		if strings.HasPrefix(text, "220") {
			events = append(events, CaptureEvent{EventType: EventBanner, Direction: "honeypot->client", Banner: text})
		} else {
			events = append(events, CaptureEvent{EventType: EventResponse, Direction: "honeypot->client", Response: text})
		}
	}
	return events
}

func (s *SMTPSession) FeedClient(data []byte) []CaptureEvent {
	var events []CaptureEvent
	for _, raw := range strings.Split(string(data), "\n") {
		text := strings.TrimSpace(strings.TrimRight(raw, "\r"))
		if text == "" {
			continue
		}
		upper := strings.ToUpper(text)
		switch {
		case strings.HasPrefix(upper, "MAIL FROM:"):
			s.sender = extractSMTPAddress(text[10:])
		case strings.HasPrefix(upper, "RCPT TO:"):
			events = append(events, CaptureEvent{
				EventType:     EventSMTPRelayProbe,
				Direction:     "client->honeypot",
				SMTPSender:    s.sender,
				SMTPRecipient: extractSMTPAddress(text[8:]),
			})
		case strings.HasPrefix(upper, "RSET"):
			s.sender = ""
			events = append(events, CaptureEvent{EventType: EventCommand, Direction: "client->honeypot", Command: text})
		default:
			ev := CaptureEvent{Direction: "client->honeypot"}
			isCmd := false
			for _, pfx := range smtpCommandPrefixes {
				if strings.HasPrefix(upper, pfx) {
					isCmd = true
					break
				}
			}
			if isCmd {
				ev.EventType = EventCommand
				ev.Command = text
			} else if dec, err := base64.StdEncoding.DecodeString(text); err == nil && len(dec) > 0 && isPrintableOrControlASCII(dec) {
				ev.EventType = EventCredential
				ev.Username = string(dec)
			} else {
				ev.EventType = EventCommand
				ev.Command = text
			}
			events = append(events, ev)
		}
	}
	return events
}

func (s *SMTPSession) ParseClientData(data []byte, _ func(string, ...interface{})) []CaptureEvent {
	text := strings.TrimSpace(string(data))
	upper := strings.ToUpper(text)
	for _, prefix := range smtpCommandPrefixes {
		if strings.HasPrefix(upper, prefix) {
			return []CaptureEvent{{EventType: EventCommand, Direction: "client->honeypot", Command: text}}
		}
	}
	if decoded, err := base64.StdEncoding.DecodeString(text); err == nil && len(decoded) > 0 && isPrintableOrControlASCII(decoded) {
		return []CaptureEvent{{EventType: EventCredential, Direction: "client->honeypot", Username: string(decoded)}}
	}
	return []CaptureEvent{{EventType: EventCommand, Direction: "client->honeypot", Command: text}}
}

func (s *SMTPSession) ParseServerData(data []byte, _ func(string, ...interface{})) []CaptureEvent {
	text := strings.TrimSpace(string(data))
	if strings.HasPrefix(text, "220") {
		return []CaptureEvent{{EventType: EventBanner, Direction: "honeypot->client", Banner: text}}
	}
	return []CaptureEvent{{EventType: EventResponse, Direction: "honeypot->client", Response: text}}
}

const (
	telnetIAC  = 0xFF
	telnetDONT = 0xFE
	telnetDO   = 0xFD
	telnetWONT = 0xFC
	telnetWILL = 0xFB
	telnetSB   = 0xFA
	telnetSE   = 0xF0
)

type telnetState int

const (
	telnetAwaitUsername telnetState = iota
	telnetAwaitPassword
	telnetAwaitCommand
	telnetAuthenticated
)

var (
	reLoginPrompt    = regexp.MustCompile(`(?i)(?:login|username|user)\s*:`)
	rePasswordPrompt = regexp.MustCompile(`(?i)(?:password|passwd)\s*:`)
	reAuthError      = regexp.MustCompile(`(?i)(?:incorrect|failed|invalid|denied|wrong password|authentication error|login error)`)
	reShellPrompt    = regexp.MustCompile(`\S[#$>]\s*$`)
)

// TelnetSession is a stateful, bidirectional Telnet parser. It implements both
// ProtocolParser (bulk fallback for non-server-first paths) and BiParser (ordered
// chunk replay for the server-first relay path).
type TelnetSession struct {
	state     telnetState
	attempt   int
	clientBuf []byte
}

// FeedServer updates the state machine based on server prompts and returns response events.
func (s *TelnetSession) FeedServer(data []byte) []CaptureEvent {
	text := stripTelnetControl(data)
	if text == "" {
		return nil
	}
	switch {
	case reAuthError.MatchString(text):
		s.attempt++
		s.state = telnetAwaitUsername
		s.clientBuf = s.clientBuf[:0]
	case reLoginPrompt.MatchString(text):
		s.state = telnetAwaitUsername
	case rePasswordPrompt.MatchString(text):
		s.state = telnetAwaitPassword
	case reShellPrompt.MatchString(text):
		s.state = telnetAuthenticated
	}
	return []CaptureEvent{{
		EventType: EventResponse,
		Direction: "honeypot->client",
		Response:  text,
	}}
}

// FeedClient accumulates client bytes (handling char-by-char NVT mode and backspace),
// emitting credential/command events per complete line based on current state.
func (s *TelnetSession) FeedClient(data []byte) []CaptureEvent {
	stripped := stripTelnetControlBytes(data)
	var events []CaptureEvent
	for _, b := range stripped {
		switch b {
		case '\r':
			line := strings.TrimSpace(string(s.clientBuf))
			s.clientBuf = s.clientBuf[:0]
			if ev := s.emitLine(line); ev != nil {
				events = append(events, *ev)
			}
		case '\n':
			// LF right after CR: clientBuf was already cleared; skip.
			if len(s.clientBuf) == 0 {
				continue
			}
			line := strings.TrimSpace(string(s.clientBuf))
			s.clientBuf = s.clientBuf[:0]
			if ev := s.emitLine(line); ev != nil {
				events = append(events, *ev)
			}
		case 0x08, 0x7f:
			if len(s.clientBuf) > 0 {
				s.clientBuf = s.clientBuf[:len(s.clientBuf)-1]
			}
		default:
			s.clientBuf = append(s.clientBuf, b)
		}
	}
	return events
}

func (s *TelnetSession) emitLine(line string) *CaptureEvent {
	ev := &CaptureEvent{Direction: "client->honeypot", TelnetAttempt: s.attempt + 1}
	switch s.state {
	case telnetAwaitUsername:
		if line == "" {
			return nil // blank username: ignore and keep waiting
		}
		ev.EventType = EventCredential
		ev.Username = line
		s.state = telnetAwaitPassword
	case telnetAwaitPassword:
		ev.EventType = EventCredential
		if line == "" {
			ev.Password = "<blank>"
		} else {
			ev.Password = line
		}
		s.state = telnetAwaitCommand
	case telnetAwaitCommand, telnetAuthenticated:
		if line == "" {
			return nil
		}
		ev.EventType = EventCommand
		ev.Command = line
	}
	return ev
}

// Flush emits any bytes still buffered in clientBuf when the connection closes
// before the client sent a CR/LF terminator.
func (s *TelnetSession) Flush() []CaptureEvent {
	line := strings.TrimSpace(string(s.clientBuf))
	s.clientBuf = s.clientBuf[:0]
	if line == "" {
		return nil
	}
	if ev := s.emitLine(line); ev != nil {
		return []CaptureEvent{*ev}
	}
	return nil
}

// ParseClientData implements ProtocolParser as a stateless fallback used when
// the connection does not go through the ordered BiParser path.
func (s *TelnetSession) ParseClientData(data []byte, _ func(string, ...interface{})) []CaptureEvent {
	text := stripTelnetControl(data)
	if text == "" {
		return nil
	}
	lines := strings.FieldsFunc(text, func(r rune) bool { return r == '\r' || r == '\n' })
	var events []CaptureEvent
	credIdx := 0
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		ev := CaptureEvent{Direction: "client->honeypot", TelnetAttempt: 1}
		switch credIdx {
		case 0:
			ev.EventType = EventCredential
			ev.Username = line
		case 1:
			ev.EventType = EventCredential
			ev.Password = line
		default:
			ev.EventType = EventCommand
			ev.Command = line
		}
		credIdx++
		events = append(events, ev)
	}
	return events
}

func (s *TelnetSession) ParseServerData(data []byte, _ func(string, ...interface{})) []CaptureEvent {
	text := stripTelnetControl(data)
	if text == "" {
		return nil
	}
	return []CaptureEvent{{EventType: EventResponse, Direction: "honeypot->client", Response: text}}
}

func stripTelnetControlBytes(data []byte) []byte {
	var result []byte
	i := 0
	for i < len(data) {
		if data[i] == telnetIAC {
			if i+1 >= len(data) {
				break
			}
			opt := data[i+1]
			if opt == telnetSB {
				for i += 2; i < len(data); i++ {
					if i+1 < len(data) && data[i] == telnetIAC && data[i+1] == telnetSE {
						i++
						break
					}
				}
				i++
				continue
			}
			if opt >= telnetWILL && opt <= telnetDONT {
				i += 3
				continue
			}
			i += 2
			continue
		}
		// Strip ANSI/VT100 CSI escape sequences (ESC '[' ... letter) so that
		// colored prompts (e.g. Cowrie's root@host:~#\x1b[0m) don't obscure the
		// trailing '#' that reShellPrompt needs to match.
		if data[i] == 0x1b && i+1 < len(data) && data[i+1] == '[' {
			i += 2
			for i < len(data) && !((data[i] >= 'a' && data[i] <= 'z') || (data[i] >= 'A' && data[i] <= 'Z')) {
				i++
			}
			if i < len(data) {
				i++
			}
			continue
		}
		b := data[i]
		if b >= 32 && b < 127 {
			result = append(result, b)
		} else if b == '\r' || b == '\n' || b == '\t' || b == 0x08 || b == 0x7f {
			result = append(result, b)
		}
		i++
	}
	return result
}

func stripTelnetControl(data []byte) string {
	return strings.TrimSpace(string(stripTelnetControlBytes(data)))
}

type POP3Parser struct{}

func (p *POP3Parser) ParseClientData(data []byte, logger func(string, ...interface{})) []CaptureEvent {
	text := strings.TrimSpace(string(data))
	upper := strings.ToUpper(text)

	if strings.HasPrefix(upper, "USER ") {
		return []CaptureEvent{{
			EventType: EventCredential,
			Direction: "client->honeypot",
			Username:  strings.TrimPrefix(text[5:], " "),
		}}
	}
	if strings.HasPrefix(upper, "PASS ") {
		return []CaptureEvent{{
			EventType: EventCredential,
			Direction: "client->honeypot",
			Password:  strings.TrimPrefix(text[5:], " "),
		}}
	}
	return []CaptureEvent{{
		EventType: EventCommand,
		Direction: "client->honeypot",
		Command:   text,
	}}
}

func (p *POP3Parser) ParseServerData(data []byte, logger func(string, ...interface{})) []CaptureEvent {
	text := strings.TrimSpace(string(data))
	if strings.HasPrefix(text, "+OK") {
		return []CaptureEvent{{
			EventType: EventResponse,
			Direction: "honeypot->client",
			Response:  text,
		}}
	}
	if strings.HasPrefix(text, "-ERR") {
		return []CaptureEvent{{
			EventType: EventResponse,
			Direction: "honeypot->client",
			Response:  text,
		}}
	}
	return nil
}

type IMAPParser struct{}

func (p *IMAPParser) ParseClientData(data []byte, logger func(string, ...interface{})) []CaptureEvent {
	text := strings.TrimSpace(string(data))
	if text == "" {
		return nil
	}

	// Formato IMAP: "tag command [args]"
	parts := strings.SplitN(text, " ", 3)
	if len(parts) < 2 {
		return []CaptureEvent{{EventType: EventCommand, Direction: "client->honeypot", Command: text}}
	}

	cmd := strings.ToUpper(parts[1])

	if cmd == "LOGIN" && len(parts) == 3 {
		argParts := strings.SplitN(parts[2], " ", 2)
		var events []CaptureEvent
		events = append(events, CaptureEvent{
			EventType: EventCredential,
			Direction: "client->honeypot",
			Username:  strings.Trim(argParts[0], "\""),
		})
		if len(argParts) == 2 {
			events = append(events, CaptureEvent{
				EventType: EventCredential,
				Direction: "client->honeypot",
				Password:  strings.Trim(argParts[1], "\""),
			})
		}
		return events
	}

	return []CaptureEvent{{EventType: EventCommand, Direction: "client->honeypot", Command: text}}
}

func (p *IMAPParser) ParseServerData(data []byte, logger func(string, ...interface{})) []CaptureEvent {
	text := strings.TrimSpace(string(data))
	if text == "" {
		return nil
	}
	// Untagged: "* OK ...", "* NO ...", "* BAD ..."
	if strings.HasPrefix(text, "* ") {
		return []CaptureEvent{{EventType: EventResponse, Direction: "honeypot->client", Response: text}}
	}
	// Tagged: "tag OK ...", "tag NO ...", "tag BAD ..."
	parts := strings.SplitN(text, " ", 3)
	if len(parts) >= 2 {
		status := strings.ToUpper(parts[1])
		if status == "OK" || status == "NO" || status == "BAD" {
			return []CaptureEvent{{EventType: EventResponse, Direction: "honeypot->client", Response: text}}
		}
	}
	return nil
}

// RDPParser handles RDP protocol (basic hex capture)
type RDPParser struct{}

func (p *RDPParser) ParseClientData(data []byte, logger func(string, ...interface{})) []CaptureEvent {
	if len(data) == 0 {
		return nil
	}
	return []CaptureEvent{{
		EventType: EventCommand,
		Direction: "client->honeypot",
		Command:   fmt.Sprintf("rdp_client:%d_bytes", len(data)),
	}}
}

func (p *RDPParser) ParseServerData(data []byte, logger func(string, ...interface{})) []CaptureEvent {
	if len(data) == 0 {
		return nil
	}
	return []CaptureEvent{{
		EventType: EventResponse,
		Direction: "honeypot->client",
		Response: fmt.Sprintf("rdp_server:%d_bytes", len(data)),
	}}
}

func NewParser(protocol string, port int) ProtocolParser {
	switch strings.ToUpper(protocol) {
	case "FTP":
		return &FTPBiParser{}
	case "MYSQL":
		return &MySQLSession{}
	case "SMTP", "MAIL", "MAIL_SMTP":
		return &SMTPSession{}
	case "TELNET":
		return &TelnetSession{}
	case "VNC":
		return &VNCSession{}
	case "POP", "POP3":
		return &POP3Parser{}
	case "IMAP", "IMAP4":
		return &IMAPParser{}
	case "RDP":
		return &RDPParser{}
	default:
		switch port {
		case 21:
			return &FTPBiParser{}
		case 23:
			return &TelnetSession{}
		case 25, 465, 587:
			return &SMTPSession{}
		case 110:
			return &POP3Parser{}
		case 143, 993:
			return &IMAPParser{}
		case 3306:
			return &MySQLSession{}
		case 5900:
			return &VNCSession{}
		default:
			return &RawParser{}
		}
	}
}

// isPrintableOrControlASCII retorna true se o slice contiver apenas bytes ASCII imprimíveis
// ou caracteres de controle legítimos (null byte como separador AUTH PLAIN, tab, CR, LF).
// Garante que base64 decodificado para credenciais SMTP seja texto legível, não lixo binário.
func isPrintableOrControlASCII(b []byte) bool {
	for _, c := range b {
		if c != 0x00 && c != '\t' && c != '\r' && c != '\n' && (c < 0x20 || c > 0x7e) {
			return false
		}
	}
	return true
}

func extractMySQLVersion(data []byte) string {
	for i := 0; i < len(data)-5; i++ {
		if data[i] == 0x0a {
			start := i + 1
			for j := start; j < len(data); j++ {
				if data[j] == 0x00 || data[j] == 0x0a {
					if j > start {
						return string(data[start:j])
					}
				}
			}
		}
	}
	return string(data[5:])
}