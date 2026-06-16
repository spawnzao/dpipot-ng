package mitm

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
