package mitm

import (
	"fmt"
	"strings"
)

// ndpiAppFromEvent mapeia o tipo de evento para o valor de ndpi_app no ES.
// Usa "username"/"password" em vez de "credential" genérico para ser filtrável.
func ndpiAppFromEvent(ev CaptureEvent) string {
	switch ev.EventType {
	case EventCredential:
		if ev.Username != "" {
			return "username"
		}
		if ev.Password != "" {
			return "password"
		}
		return "credential"
	case EventBanner:
		if ev.VNCServerVersion != "" {
			return "vnc_banner"
		}
		return "banner"
	case EventVNCVersion:
		return "vnc_version"
	case EventVNCSecType:
		return "vnc_security"
	case EventVNCAuth:
		return "vnc_auth"
	case EventVNCResult:
		return "vnc_result"
	case EventMySQLLogin:
		return "mysql_login"
	case EventSMTPRelayProbe:
		return "smtp_relay_probe"
	default:
		return string(ev.EventType)
	}
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
		if ev.VNCServerVersion != "" {
			return ev.VNCServerVersion
		}
		return ev.Banner
	case EventRawData:
		return ev.RawPayload
	case EventVNCVersion:
		return ev.VNCClientVersion
	case EventVNCSecType:
		return fmt.Sprintf("type_%d", ev.VNCSecType)
	case EventVNCAuth:
		return ev.VNCAuthHash
	case EventVNCResult:
		return ev.VNCAuthResult
	case EventMySQLLogin:
		if ev.MySQLUsername != "" {
			return ev.MySQLUsername
		}
		return ev.MySQLAuthHash
	case EventSMTPRelayProbe:
		return ev.SMTPRecipient
	}
	return ""
}

func isPrintableASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 32 || s[i] > 126 {
			return false
		}
	}
	return true
}

func extractMySQLUsername(data []byte, logger func(string, ...interface{})) string {
	if len(data) < 36 {
		return ""
	}
	offset := 32
	for i := offset; i < len(data); i++ {
		if data[i] == 0x00 {
			user := string(data[offset:i])
			if len(user) > 0 && len(user) < 64 && isPrintableASCII(user) {
				logger("extractMySQLUsername: found user at offset %d: %q", offset, user)
				return user
			}
		}
	}
	return ""
}

// extractSMTPAddress parses the address from the argument part of a MAIL FROM or RCPT TO command.
// Input is the text after "MAIL FROM:" or "RCPT TO:", e.g. " <user@example.com> SIZE=1000".
func extractSMTPAddress(s string) string {
	s = strings.TrimSpace(s)
	if start := strings.Index(s, "<"); start >= 0 {
		if end := strings.Index(s[start:], ">"); end >= 0 {
			return s[start+1 : start+end]
		}
	}
	if idx := strings.Index(s, " "); idx >= 0 {
		s = s[:idx]
	}
	return s
}
