package mitm

import (
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/spawnzao/dpipot-ng/proxy/internal/kafka"
)

// syntheticX224CC announces PROTOCOL_HYBRID (NLA) to the client.
//
// Why PROTOCOL_HYBRID instead of PROTOCOL_SSL:
//   - PROTOCOL_SSL causes mstsc.exe to use TWO TCP connections: the first only
//     for the certificate warning, the second for the actual session. The second
//     connection goes through the same synthetic-CC path and never reaches the
//     honeypot for credential collection.
//   - PROTOCOL_HYBRID (NLA) keeps everything on ONE TCP connection: TLS
//     handshake (cert warning, if any), CredSSP/NTLM auth, and session — all
//     on the same socket. No reconnect.
//   - NTLM credentials sent over CredSSP are visible to the proxy (after TLS
//     decryption) and can be relayed raw to the honeypot, which captures them.
//     RDP Classic Security Exchange (used by PROTOCOL_SSL) encrypts the password
//     with the server's RSA key, making capture impossible without the exact cert.
var syntheticX224CC = []byte{
	0x03, 0x00, 0x00, 0x13, // TPKT header, total length = 19
	0x0E,                   // LI = 14
	0xD0,                   // CC TPDU
	0x00, 0x00,             // DST-REF
	0x00, 0x00,             // SRC-REF
	0x00,                   // Class 0
	0x02,                   // TYPE_RDP_NEG_RSP
	0x00,                   // flags
	0x08, 0x00,             // length = 8
	0x02, 0x00, 0x00, 0x00, // selectedProtocol = PROTOCOL_HYBRID (NLA)
}

// RDPConfig holds configuration for the RDP MITM handler.
type RDPConfig struct {
	ClientConn   net.Conn
	HoneypotAddr string  // HandleRDP dials the honeypot itself, after client TLS succeeds
	FirstChunk   []byte  // X.224 Connection Request read from the client
	TLSCert      tls.Certificate
	FlowID       string
	SrcIP        string
	SrcPort      int
	DstIP        string
	DstPort      int
	TupleID      string
	Deadline     time.Time
	OnEvent      func(*kafka.Event)
	Logger       func(string, ...interface{})
}

// HandleRDP performs RDP MITM with half-TLS and deferred honeypot connection.
//
// Flow:
//  1. Send synthetic X.224 CC (PROTOCOL_HYBRID) to client — no honeypot dial yet.
//  2. TLS handshake with client (proxy = TLS server).  Certificate warning is shown
//     here; if the client rejects or is a scanner, we return quickly.
//  3. Dial honeypot, replay X.224 CR, read (and discard) X.224 CC from honeypot.
//  4. Half-TLS relay: decrypt client data (CredSSP/NTLM) and relay raw to honeypot;
//     relay raw honeypot responses back to client over TLS.
//
// Why skip TLS with the honeypot:
//   Go 1.22+ TLS client is incompatible with heralding's Python SSL server —
//   the handshake consistently fails with EOF after 30 s regardless of cipher suite
//   or version settings. After X.224 CC heralding falls back to reading raw data;
//   sending decrypted CredSSP bytes directly allows it to capture credentials.
func HandleRDP(config RDPConfig) error {
	if len(config.FirstChunk) > 0 {
		config.Logger("received %d bytes (X.224 CR) from client", len(config.FirstChunk))
	}

	// 1. Synthetic X.224 CC with PROTOCOL_HYBRID → no reconnect, no second connection.
	if _, err := config.ClientConn.Write(syntheticX224CC); err != nil {
		return fmt.Errorf("rdp: failed sending X.224 CC to client: %w", err)
	}
	config.Logger("sent synthetic X.224 CC (PROTOCOL_HYBRID/NLA) to client")

	// 2. TLS with client. Scanner probes and cert rejections fail here quickly.
	clientTLS := tls.Server(config.ClientConn, &tls.Config{
		Certificates: []tls.Certificate{config.TLSCert},
	})
	if err := clientTLS.Handshake(); err != nil {
		return fmt.Errorf("rdp: TLS handshake with client failed: %w", err)
	}
	config.Logger("TLS with client established")

	// 3. Dial honeypot only after client TLS succeeds.
	dialTimeout := time.Until(config.Deadline)
	if dialTimeout <= 0 {
		return fmt.Errorf("rdp: deadline exceeded before honeypot dial")
	}
	honeypotConn, err := net.DialTimeout("tcp", config.HoneypotAddr, dialTimeout)
	if err != nil {
		return fmt.Errorf("rdp: failed connecting to honeypot: %w", err)
	}
	defer honeypotConn.Close()
	honeypotConn.SetDeadline(config.Deadline) //nolint:errcheck

	// Replay X.224 CR so the honeypot enters its TLS-or-raw read loop.
	if len(config.FirstChunk) > 0 {
		if _, err := honeypotConn.Write(config.FirstChunk); err != nil {
			return fmt.Errorf("rdp: failed forwarding X.224 CR to honeypot: %w", err)
		}
	}
	serverBuf := make([]byte, 4096)
	n, err := honeypotConn.Read(serverBuf)
	if err != nil || n == 0 {
		return fmt.Errorf("rdp: failed reading X.224 CC from honeypot: %w", err)
	}
	config.Logger("received X.224 CC from honeypot, selectedProtocol=0x%08x",
		parseX224CCProtocol(serverBuf[:n]))
	// Honeypot CC is intentionally not forwarded — the client already has the synthetic one.
	// We also skip TLS with the honeypot (see package-level comment above).

	// 4. Half-TLS relay: clientTLS (decrypted) ↔ honeypotConn (raw TCP).
	done := make(chan error, 2)

	// client → honeypot: decrypt TLS, detect CredSSP/NTLM, forward raw
	go func() {
		buf := make([]byte, 4096)
		for {
			nr, err := clientTLS.Read(buf)
			if nr > 0 {
				if isCredSSP(buf[:nr]) && config.OnEvent != nil {
					config.OnEvent(&kafka.Event{
						FlowID:     config.FlowID,
						TupleID:    config.TupleID,
						Timestamp:  time.Now(),
						SrcIP:      config.SrcIP,
						SrcPort:    config.SrcPort,
						DstIP:      config.DstIP,
						DstPort:    config.DstPort,
						NDPIProto:  "RDP",
						NDPIApp:    "ntlmssp_auth",
						AttackType: fmt.Sprintf("ntlmssp:%x", buf[:min(nr, 32)]),
						Honeypot:   config.HoneypotAddr,
						Instance:   "proxy",
					})
				}
				if _, werr := honeypotConn.Write(buf[:nr]); werr != nil {
					done <- werr
					return
				}
			}
			if err != nil {
				done <- err
				return
			}
		}
	}()

	// honeypot → client: forward raw honeypot responses encrypted over TLS
	go func() {
		buf := make([]byte, 4096)
		for {
			nr, err := honeypotConn.Read(buf)
			if nr > 0 {
				if _, werr := clientTLS.Write(buf[:nr]); werr != nil {
					done <- werr
					return
				}
			}
			if err != nil {
				done <- err
				return
			}
		}
	}()

	return <-done
}

// parseX224CCProtocol extracts the selectedProtocol field from an RDP X.224 CC TPDU.
func parseX224CCProtocol(data []byte) uint32 {
	if len(data) < 19 || data[11] != 0x02 {
		return 0
	}
	return binary.LittleEndian.Uint32(data[15:19])
}

// isCredSSP detects NLA/CredSSP traffic: NTLMSSP marker or SPNEGO ASN.1 SEQUENCE.
func isCredSSP(data []byte) bool {
	for i := 0; i+6 < len(data); i++ {
		if data[i] == 'N' && data[i+1] == 'T' && data[i+2] == 'L' &&
			data[i+3] == 'M' && data[i+4] == 'S' && data[i+5] == 'S' && data[i+6] == 'P' {
			return true
		}
		if data[i] == 0x30 {
			return true
		}
	}
	return false
}
