package mitm

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"time"
)

type CaptureEventType string

const (
	EventBanner     CaptureEventType = "banner"
	EventCredential CaptureEventType = "credential"
	EventCommand    CaptureEventType = "command"
	EventResponse   CaptureEventType = "response"
	EventRawData    CaptureEventType = "raw_data"
	EventVNCVersion CaptureEventType = "vnc_version"
	EventVNCSecType CaptureEventType = "vnc_security"
	EventVNCAuth    CaptureEventType = "vnc_auth"
	EventVNCResult  CaptureEventType = "vnc_result"
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

type MySQLParser struct{}

func (p *MySQLParser) ParseClientData(data []byte, logger func(string, ...interface{})) []CaptureEvent {
	var events []CaptureEvent

	user := extractMySQLUsername(data, logger)
	if user != "" {
		events = append(events, CaptureEvent{
			EventType: EventCredential,
			Direction: "client->honeypot",
			Username:  user,
		})
	}

	pass := extractMySQLPassword(data, logger)
	if pass != "" {
		events = append(events, CaptureEvent{
			EventType: EventCredential,
			Direction: "client->honeypot",
			Password:  pass,
		})
	}

	if len(events) == 0 && len(data) > 5 {
		events = append(events, CaptureEvent{
			EventType:  EventRawData,
			Direction: "client->honeypot",
			RawPayload: hex.EncodeToString(data),
		})
	}

	return events
}

func (p *MySQLParser) ParseServerData(data []byte, logger func(string, ...interface{})) []CaptureEvent {
	if len(data) > 5 {
		version := extractMySQLVersion(data)
		if version != "" {
			return []CaptureEvent{{
				EventType: EventBanner,
				Direction: "honeypot->client",
				Banner:    fmt.Sprintf("MySQL %s", version),
			}}
		}
	}
	return []CaptureEvent{{
		EventType:  EventRawData,
		Direction: "honeypot->client",
		RawPayload: hex.EncodeToString(data),
	}}
}

type FTPParser struct{}

func (p *FTPParser) ParseClientData(data []byte, logger func(string, ...interface{})) []CaptureEvent {
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

func (p *FTPParser) ParseServerData(data []byte, logger func(string, ...interface{})) []CaptureEvent {
	text := strings.TrimSpace(string(data))
	if strings.HasPrefix(text, "220") {
		return []CaptureEvent{{
			EventType: EventBanner,
			Direction: "honeypot->client",
			Banner:    text,
		}}
	}
	return []CaptureEvent{{
		EventType: EventResponse,
		Direction: "honeypot->client",
		Response:  text,
	}}
}

type SMTPParser struct{}

var smtpCommandPrefixes = []string{
	"EHLO", "HELO", "MAIL", "RCPT", "DATA", "QUIT", "RSET",
	"NOOP", "VRFY", "EXPN", "HELP", "STARTTLS", "AUTH",
}

func (p *SMTPParser) ParseClientData(data []byte, logger func(string, ...interface{})) []CaptureEvent {
	text := strings.TrimSpace(string(data))
	upper := strings.ToUpper(text)

	// Comandos SMTP têm prioridade — evita que "QUIT" e outros sejam
	// decodificados como base64 por coincidência.
	for _, prefix := range smtpCommandPrefixes {
		if strings.HasPrefix(upper, prefix) {
			return []CaptureEvent{{
				EventType: EventCommand,
				Direction: "client->honeypot",
				Command:   text,
			}}
		}
	}

	// Linhas de credencial base64 (respostas ao AUTH LOGIN/PLAIN challenge)
	if decoded, err := base64.StdEncoding.DecodeString(text); err == nil && len(decoded) > 0 && isPrintableOrControlASCII(decoded) {
		return []CaptureEvent{{
			EventType: EventCredential,
			Direction: "client->honeypot",
			Username:  string(decoded),
		}}
	}
	return []CaptureEvent{{
		EventType: EventCommand,
		Direction: "client->honeypot",
		Command:   text,
	}}
}

func (p *SMTPParser) ParseServerData(data []byte, logger func(string, ...interface{})) []CaptureEvent {
	text := strings.TrimSpace(string(data))
	if strings.HasPrefix(text, "220") {
		return []CaptureEvent{{
			EventType: EventBanner,
			Direction: "honeypot->client",
			Banner:    text,
		}}
	}
	return []CaptureEvent{{
		EventType: EventResponse,
		Direction: "honeypot->client",
		Response:  text,
	}}
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
	reShellPrompt    = regexp.MustCompile(`\S[#$]\s*$`)
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
			if line == "" {
				continue
			}
			if ev := s.emitLine(line); ev != nil {
				events = append(events, *ev)
			}
		case '\n':
			if len(s.clientBuf) == 0 {
				continue
			}
			line := strings.TrimSpace(string(s.clientBuf))
			s.clientBuf = s.clientBuf[:0]
			if line == "" {
				continue
			}
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
		ev.EventType = EventCredential
		ev.Username = line
		s.state = telnetAwaitPassword
	case telnetAwaitPassword:
		ev.EventType = EventCredential
		ev.Password = line
		s.state = telnetAwaitCommand
	case telnetAwaitCommand, telnetAuthenticated:
		ev.EventType = EventCommand
		ev.Command = line
	}
	return ev
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
			// WILL/WONT/DO/DONT: sequência de 3 bytes (IAC + verb + option).
			// Condição correta: telnetWILL(0xFB) ≤ opt ≤ telnetDONT(0xFE).
			// i aponta no IAC; i+3 pula os 3 bytes completos.
			if opt >= telnetWILL && opt <= telnetDONT {
				i += 3
				continue
			}
			// Outros comandos IAC de 2 bytes (SE, NOP, etc.)
			i += 2
			continue
		}
		if data[i] >= 32 && data[i] < 127 {
			result = append(result, data[i])
		} else if data[i] == '\n' || data[i] == '\r' || data[i] == '\t' {
			result = append(result, data[i])
		}
		i++
	}
	return strings.TrimSpace(string(result))
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
		return &FTPParser{}
	case "MYSQL":
		return &MySQLParser{}
	case "SMTP", "MAIL", "MAIL_SMTP":
		return &SMTPParser{}
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
			return &FTPParser{}
		case 23:
			return &TelnetSession{}
		case 25, 465, 587:
			return &SMTPParser{}
		case 110:
			return &POP3Parser{}
		case 143, 993:
			return &IMAPParser{}
		case 3306:
			return &MySQLParser{}
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