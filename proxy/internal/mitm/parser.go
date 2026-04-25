package mitm

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

type CaptureEventType string

const (
	EventBanner    CaptureEventType = "banner"
	EventCredential CaptureEventType = "credential"
	EventCommand   CaptureEventType = "command"
	EventResponse  CaptureEventType = "response"
	EventRawData   CaptureEventType = "raw_data"
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
}

type ProtocolParser interface {
	ParseClientData(data []byte, logger func(string, ...interface{})) []CaptureEvent
	ParseServerData(data []byte, logger func(string, ...interface{})) []CaptureEvent
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

func (p *SMTPParser) ParseClientData(data []byte, logger func(string, ...interface{})) []CaptureEvent {
	text := strings.TrimSpace(string(data))
	upper := strings.ToUpper(text)

	if strings.HasPrefix(upper, "AUTH LOGIN") || strings.HasPrefix(upper, "AUTH PLAIN") {
		return []CaptureEvent{{
			EventType: EventCommand,
			Direction: "client->honeypot",
			Command:   text,
		}}
	}
	if decoded, err := base64.StdEncoding.DecodeString(text); err == nil && len(decoded) > 0 {
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

type TelnetParser struct{}

const (
	telnetIAC  = 0xFF
	telnetDONT = 0xFE
	telnetDO   = 0xFD
	telnetWONT = 0xFC
	telnetWILL = 0xFB
	telnetSB   = 0xFA
	telnetSE   = 0xF0
)

func (p *TelnetParser) ParseClientData(data []byte, logger func(string, ...interface{})) []CaptureEvent {
	text := stripTelnetControl(data)
	if text == "" {
		return nil
	}
	return []CaptureEvent{{
		EventType: EventCommand,
		Direction: "client->honeypot",
		Command:   text,
	}}
}

func (p *TelnetParser) ParseServerData(data []byte, logger func(string, ...interface{})) []CaptureEvent {
	text := stripTelnetControl(data)
	if text == "" {
		return nil
	}
	return []CaptureEvent{{
		EventType: EventResponse,
		Direction: "honeypot->client",
		Response:  text,
	}}
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
			if opt >= telnetDONT && opt <= telnetSE {
				i += 2
				continue
			}
			i++
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

func NewParser(protocol string, port int) ProtocolParser {
	switch strings.ToUpper(protocol) {
	case "FTP":
		return &FTPParser{}
	case "MYSQL":
		return &MySQLParser{}
	case "SMTP", "MAIL":
		return &SMTPParser{}
	case "TELNET":
		return &TelnetParser{}
	default:
		switch port {
		case 21:
			return &FTPParser{}
		case 23:
			return &TelnetParser{}
		case 3306:
			return &MySQLParser{}
		case 25, 465, 587:
			return &SMTPParser{}
		default:
			return &RawParser{}
		}
	}
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