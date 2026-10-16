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
	// tpktLen encodes total TPKT packet size; must be at least 11 bytes and fit in data.
	if tpktLen < 11 || int(tpktLen) > len(data) {
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
	return ""
}
