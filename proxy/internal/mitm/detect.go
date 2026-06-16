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
