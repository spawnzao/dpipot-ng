package mitm

import "bytes"

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

// IsRDP validates a TPKT + X.224 Connection Request PDU (RFC 1006 / ITU-T X.224).
// Requires: TPKT version (0x03), reserved (0x00), coherent length, and X.224 CR code (0xe0).
func IsRDP(data []byte) bool {
	if len(data) < 11 {
		return false
	}
	if data[0] != 0x03 || data[1] != 0x00 {
		return false
	}
	tpktLen := uint16(data[2])<<8 | uint16(data[3])
	// Only check the lower bound: the first chunk may be a TCP fragment smaller than
	// the full PDU (e.g. large RDP cookie). Upper-bound check causes false negatives.
	if tpktLen < 11 {
		return false
	}
	// data[5] = X.224 PDU type; 0xe0 = Connection Request (CR).
	return data[5] == 0xe0
}

// IsHTTP reports whether data begins with a recognized HTTP request method token.
func IsHTTP(data []byte) bool {
	for _, prefix := range [][]byte{
		[]byte("GET "), []byte("POST "), []byte("HEAD "), []byte("OPTIONS "),
		[]byte("PUT "), []byte("DELETE "), []byte("CONNECT "), []byte("PATCH "),
		[]byte("TRACE "), []byte("PRI "),
	} {
		if bytes.HasPrefix(data, prefix) {
			return true
		}
	}
	return false
}

// IsMQTT reports whether data is a MQTT CONNECT packet (type 1).
// Checks for the fixed-header byte and the mandatory protocol-name field.
func IsMQTT(data []byte) bool {
	// data[0] == 0x10: packet type 1 (CONNECT), flags 0.
	return len(data) >= 4 && data[0] == 0x10 &&
		(bytes.Contains(data, []byte("MQTT")) || bytes.Contains(data, []byte("MQIsdp")))
}

// IsRedis reports whether data looks like a Redis client greeting.
// Covers both RESP (array/bulk-string prefixes) and common inline commands.
func IsRedis(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	// RESP: '*' or '$' followed by a digit — e.g. *3\r\n or $4\r\n
	if (data[0] == '*' || data[0] == '$') && data[1] >= '0' && data[1] <= '9' {
		return true
	}
	// Inline commands sent without framing
	for _, prefix := range [][]byte{
		[]byte("PING"), []byte("INFO"), []byte("AUTH"),
		[]byte("COMMAND"), []byte("CONFIG"),
	} {
		if bytes.HasPrefix(data, prefix) {
			return true
		}
	}
	return false
}

// FastpathDetect returns a protocol label for flows whose nDPI classification is still
// Unknown. Returns "" when no protocol is recognizable from the payload alone.
func FastpathDetect(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	if IsRDP(data) {
		return "RDP"
	}
	if IsHTTP(data) {
		return "HTTP"
	}
	if IsSSH(data) {
		return "SSH"
	}
	if IsMQTT(data) {
		return "MQTT"
	}
	if IsRedis(data) {
		return "REDIS"
	}
	return ""
}
