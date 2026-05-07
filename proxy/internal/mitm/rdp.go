package mitm

import (
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/spawnzao/dpipot-ng/proxy/internal/kafka"
)

const (
	rdpProtocolSSL      = 0x00000001
	rdpProtocolHybrid   = 0x00000002
	rdpProtocolHybridEx = 0x00000008
)

// syntheticX224CC is a standard X.224 Connection Confirm with PROTOCOL_SSL selected.
// Sent to the client immediately — no honeypot connection needed at this stage.
// mstsc.exe / rdesktop use the first TCP connection only to present the TLS certificate;
// the real session comes on a second TCP connection after the user accepts the cert.
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
	0x01, 0x00, 0x00, 0x00, // selectedProtocol = PROTOCOL_SSL
}

// honeypotTLSConfig is a TLS client config for connecting to the honeypot.
// Go 1.22+ removed RSA key exchange cipher suites from its defaults. Explicitly
// listing them here re-enables negotiation with Python-based honeypots (heralding)
// that do not support ECDHE. MaxVersion=TLS12 avoids sending a TLS 1.3 ClientHello
// that old Python ssl / OpenSSL versions may not handle.
var honeypotTLSConfig = &tls.Config{
	InsecureSkipVerify: true, //nolint:gosec
	MinVersion:         tls.VersionTLS10,
	MaxVersion:         tls.VersionTLS12,
	CipherSuites: []uint16{
		// ECDHE — forward-secrecy suites
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		// RSA key exchange — disabled by default in Go 1.22+; heralding (Python ssl)
		// typically falls back to these when ECDHE is unavailable.
		tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_RSA_WITH_AES_256_CBC_SHA,
	},
}

// RDPConfig holds configuration for the RDP MITM handler.
type RDPConfig struct {
	// ClientConn is the accepted TCP connection from the external client.
	ClientConn net.Conn
	// HoneypotAddr is "host:port" for the RDP honeypot. HandleRDP dials this
	// itself — AFTER client TLS succeeds — so the first (cert-probe) connection
	// never touches the honeypot.
	HoneypotAddr string
	FirstChunk   []byte // X.224 Connection Request read from the client
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

// HandleRDP performs RDP MITM with deferred honeypot connection.
//
// Flow:
//  1. Send synthetic X.224 CC (PROTOCOL_SSL) to client — no honeypot dial yet.
//  2. TLS handshake with client (proxy = TLS server, presents proxy cert).
//     If this fails the connection was a scanner or a certificate-probe; return quickly.
//  3. Dial honeypot, replay X.224 CR, read X.224 CC to put honeypot into TLS mode.
//  4. TLS handshake with honeypot (proxy = TLS client) using legacy-compatible config.
//  5. Bidirectional relay with CredSSP/NLA detection.
//
// Why defer the honeypot dial:
//   - mstsc.exe opens a first TCP connection purely to display the proxy TLS certificate.
//     That connection is closed as soon as the user accepts (or rejects) the cert.
//     Connecting to the honeypot for that probe wastes a session and causes a 30 s
//     timeout while Go's TLS client and heralding's Python ssl negotiate ciphers.
//   - On the second TCP connection (the real session) the cert is already trusted,
//     TLS with the client completes in <1 s, and the honeypot sees only real traffic.
func HandleRDP(config RDPConfig) error {
	if len(config.FirstChunk) > 0 {
		config.Logger("received %d bytes (X.224 CR) from client", len(config.FirstChunk))
	}

	// 1. Reply with synthetic X.224 CC — no honeypot involved yet.
	if _, err := config.ClientConn.Write(syntheticX224CC); err != nil {
		return fmt.Errorf("rdp: failed sending X.224 CC to client: %w", err)
	}
	config.Logger("sent synthetic X.224 CC (PROTOCOL_SSL) to client")

	// 2. TLS with client.
	clientTLS := tls.Server(config.ClientConn, &tls.Config{
		Certificates: []tls.Certificate{config.TLSCert},
	})
	if err := clientTLS.Handshake(); err != nil {
		return fmt.Errorf("rdp: TLS handshake with client failed: %w", err)
	}
	config.Logger("TLS with client established")

	// 3. Dial honeypot and replay X.224 exchange.
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
	config.Logger("received %d bytes (X.224 CC) from honeypot, selectedProtocol=0x%08x",
		n, parseX224CCProtocol(serverBuf[:n]))
	// X.224 CC from honeypot is intentionally NOT forwarded to the client — the
	// client already received the synthetic CC at step 1.

	// 4. TLS with honeypot.
	honeypotTLS := tls.Client(honeypotConn, honeypotTLSConfig)
	if err := honeypotTLS.Handshake(); err != nil {
		return fmt.Errorf("rdp: TLS handshake with honeypot failed: %w", err)
	}
	defer honeypotTLS.Close()
	config.Logger("TLS with honeypot established")

	// 5. Bidirectional relay with CredSSP/NLA detection.
	done := make(chan error, 2)

	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := clientTLS.Read(buf)
			if n > 0 {
				if isCredSSP(buf[:n]) && config.OnEvent != nil {
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
						AttackType: fmt.Sprintf("ntlmssp:%x", buf[:min(n, 32)]),
						Honeypot:   config.HoneypotAddr,
						Instance:   "proxy",
					})
				}
				if _, werr := honeypotTLS.Write(buf[:n]); werr != nil {
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

	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := honeypotTLS.Read(buf)
			if n > 0 {
				if _, werr := clientTLS.Write(buf[:n]); werr != nil {
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
