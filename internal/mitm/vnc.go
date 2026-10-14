package mitm

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

type vncState int

const (
	vncStateVersion     vncState = iota // waiting for server RFB version string
	vncStateVersionEcho                 // waiting for client version echo
	vncStateSecList                     // waiting for server security type list
	vncStateSecChoice                   // waiting for client security type selection
	vncStateChallenge                   // waiting for server 16-byte DES challenge
	vncStateResponse                    // waiting for client 16-byte DES response
	vncStateAuthResult                  // waiting for server 4-byte auth result
	vncStateDone                        // handshake complete
)

// VNCSession passively taps an RFB (VNC) handshake, extracting version, security
// type, and the DES challenge/response pair as a hashcat-compatible VNC auth hash.
// Implements both BiParser (primary path) and ProtocolParser (stub fallback).
type VNCSession struct {
	state       vncState
	serverBuf   []byte
	clientBuf   []byte
	challenge   []byte
	useOldProto bool // true for RFB 003.003 (4-byte sec type from server, no client choice)
	secType     int
}

// FeedServer processes data arriving from the honeypot/server.
func (v *VNCSession) FeedServer(data []byte) []CaptureEvent {
	v.serverBuf = append(v.serverBuf, data...)
	var events []CaptureEvent
	for {
		ev, n := v.tryConsumeServer()
		if n == 0 {
			break
		}
		v.serverBuf = v.serverBuf[n:]
		if ev != nil {
			events = append(events, *ev)
		}
	}
	return events
}

func (v *VNCSession) tryConsumeServer() (*CaptureEvent, int) {
	switch v.state {
	case vncStateVersion:
		idx := -1
		for i, b := range v.serverBuf {
			if b == '\n' {
				idx = i
				break
			}
		}
		if idx < 0 {
			return nil, 0
		}
		text := strings.TrimSpace(string(v.serverBuf[:idx+1]))
		if !strings.HasPrefix(text, "RFB ") {
			// Not an RFB banner — skip and go done
			v.state = vncStateDone
			return nil, idx + 1
		}
		v.useOldProto = strings.HasSuffix(text, "003.003")
		v.state = vncStateVersionEcho
		return &CaptureEvent{
			EventType:        EventBanner,
			Direction:        "honeypot->client",
			Banner:           text,
			VNCServerVersion: text,
		}, idx + 1

	case vncStateSecList:
		if v.useOldProto {
			// RFB 003.003: server sends 4-byte security type, client does not choose
			if len(v.serverBuf) < 4 {
				return nil, 0
			}
			v.secType = int(binary.BigEndian.Uint32(v.serverBuf[:4]))
			if v.secType == 2 {
				v.state = vncStateChallenge
			} else {
				v.state = vncStateDone
			}
			return &CaptureEvent{
				EventType:  EventVNCSecType,
				Direction:  "honeypot->client",
				VNCSecType: v.secType,
			}, 4
		}
		// RFB 003.007+: 1 byte count followed by N security type bytes
		if len(v.serverBuf) < 1 {
			return nil, 0
		}
		count := int(v.serverBuf[0])
		if len(v.serverBuf) < 1+count {
			return nil, 0
		}
		v.state = vncStateSecChoice
		return nil, 1 + count

	case vncStateChallenge:
		if len(v.serverBuf) < 16 {
			return nil, 0
		}
		v.challenge = make([]byte, 16)
		copy(v.challenge, v.serverBuf[:16])
		v.state = vncStateResponse
		return nil, 16

	case vncStateAuthResult:
		if len(v.serverBuf) < 4 {
			return nil, 0
		}
		result := binary.BigEndian.Uint32(v.serverBuf[:4])
		authResult := "success"
		if result != 0 {
			authResult = "failed"
		}
		v.state = vncStateDone
		return &CaptureEvent{
			EventType:     EventVNCResult,
			Direction:     "honeypot->client",
			VNCAuthResult: authResult,
		}, 4
	}
	return nil, 0
}

// FeedClient processes data arriving from the attacker/client.
func (v *VNCSession) FeedClient(data []byte) []CaptureEvent {
	v.clientBuf = append(v.clientBuf, data...)
	var events []CaptureEvent
	for {
		ev, n := v.tryConsumeClient()
		if n == 0 {
			break
		}
		v.clientBuf = v.clientBuf[n:]
		if ev != nil {
			events = append(events, *ev)
		}
	}
	return events
}

func (v *VNCSession) tryConsumeClient() (*CaptureEvent, int) {
	switch v.state {
	case vncStateVersionEcho:
		idx := -1
		for i, b := range v.clientBuf {
			if b == '\n' {
				idx = i
				break
			}
		}
		if idx < 0 {
			return nil, 0
		}
		text := strings.TrimSpace(string(v.clientBuf[:idx+1]))
		v.state = vncStateSecList
		if !strings.HasPrefix(text, "RFB ") {
			return nil, idx + 1
		}
		return &CaptureEvent{
			EventType:        EventVNCVersion,
			Direction:        "client->honeypot",
			Banner:           text,
			VNCClientVersion: text,
		}, idx + 1

	case vncStateSecChoice:
		if len(v.clientBuf) < 1 {
			return nil, 0
		}
		v.secType = int(v.clientBuf[0])
		if v.secType == 2 {
			v.state = vncStateChallenge
		} else {
			v.state = vncStateDone
		}
		return &CaptureEvent{
			EventType:  EventVNCSecType,
			Direction:  "client->honeypot",
			VNCSecType: v.secType,
		}, 1

	case vncStateResponse:
		if len(v.clientBuf) < 16 {
			return nil, 0
		}
		hash := fmt.Sprintf("$vnc$*%s*%s",
			hex.EncodeToString(v.challenge),
			hex.EncodeToString(v.clientBuf[:16]))
		v.state = vncStateAuthResult
		return &CaptureEvent{
			EventType:   EventVNCAuth,
			Direction:   "client->honeypot",
			VNCAuthHash: hash,
			VNCSecType:  v.secType,
		}, 16
	}
	return nil, 0
}

// ParseClientData and ParseServerData implement ProtocolParser as no-op stubs.
// VNCSession always operates correctly via the BiParser interface.
func (v *VNCSession) ParseClientData(_ []byte, _ func(string, ...interface{})) []CaptureEvent {
	return nil
}

func (v *VNCSession) ParseServerData(_ []byte, _ func(string, ...interface{})) []CaptureEvent {
	return nil
}
