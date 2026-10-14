package mitm

import "fmt"

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
	case EventVNCVersion:
		return "vnc_version"
	case EventVNCSecType:
		return "vnc_security"
	case EventVNCAuth:
		return "vnc_auth"
	case EventVNCResult:
		return "vnc_result"
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

func extractMySQLPassword(_ []byte, _ func(string, ...interface{})) string {
	return ""
}
