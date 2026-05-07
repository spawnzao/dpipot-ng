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

// RDPConfig holds configuration for RDP MITM handler
type RDPConfig struct {
	ClientConn   net.Conn
	HoneypotConn net.Conn
	FirstChunk   []byte // X.224 Connection Request already read from client
	HoneypotAddr string
	TLSCert      tls.Certificate // proxy certificate — used as TLS server toward client
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

type rdpTLSResult struct {
	conn *tls.Conn
	err  error
}

// HandleRDP performs RDP MITM relay.
//
// RDP protocol flow:
//  1. Client → Proxy → Honeypot : X.224 Connection Request (plaintext)
//  2. Honeypot → Proxy → Client : X.224 Connection Confirm (plaintext)
//  3. Parse selectedProtocol from X.224 CC:
//     - PROTOCOL_SSL (0x01): full TLS MITM on both sides
//     - PROTOCOL_HYBRID / PROTOCOL_HYBRID_EX: heralding expects raw CredSSP (no TLS toward honeypot);
//       proxy terminates TLS only with the client and relays plaintext to honeypot
func HandleRDP(config RDPConfig) error {
	// 1. Forward X.224 Connection Request to honeypot
	if len(config.FirstChunk) > 0 {
		if _, err := config.HoneypotConn.Write(config.FirstChunk); err != nil {
			return fmt.Errorf("rdp: failed forwarding X.224 CR to honeypot: %w", err)
		}
		config.Logger("RDP: forwarded %d bytes (X.224 CR) to honeypot", len(config.FirstChunk))
	}

	// 2. Read X.224 Connection Confirm from honeypot
	serverBuf := make([]byte, 4096)
	n, err := config.HoneypotConn.Read(serverBuf)
	if err != nil || n == 0 {
		return fmt.Errorf("rdp: failed reading X.224 CC from honeypot: %w", err)
	}
	config.Logger("RDP: received %d bytes (X.224 CC) from honeypot", n)

	// 3. Forward X.224 CC to client
	if _, err := config.ClientConn.Write(serverBuf[:n]); err != nil {
		return fmt.Errorf("rdp: failed writing X.224 CC to client: %w", err)
	}

	// 4. Parse selectedProtocol to choose relay mode
	selectedProto := parseX224CCProtocol(serverBuf[:n])
	config.Logger("RDP: selectedProtocol=0x%08x", selectedProto)

	switch selectedProto {
	case rdpProtocolSSL:
		// Full TLS MITM: honeypot also does TLS (both sides)
		return rdpRelayFullTLS(config)
	default:
		// PROTOCOL_HYBRID / PROTOCOL_HYBRID_EX: heralding reads raw CredSSP after X.224 CC.
		// Proxy terminates TLS only with the external client; honeypot gets plaintext.
		return rdpRelayHalfTLS(config)
	}
}

// rdpRelayFullTLS performs TLS MITM on both sides (PROTOCOL_SSL).
// Both handshakes run in parallel to avoid heralding timeout.
func rdpRelayFullTLS(config RDPConfig) error {
	honeyResCh := make(chan rdpTLSResult, 1)
	clientResCh := make(chan rdpTLSResult, 1)

	// TLS toward honeypot (proxy = TLS client)
	go func() {
		conn := tls.Client(config.HoneypotConn, &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec
			MinVersion:         tls.VersionTLS10,
		})
		honeyResCh <- rdpTLSResult{conn, conn.Handshake()}
	}()

	// TLS toward external client (proxy = TLS server)
	go func() {
		conn := tls.Server(config.ClientConn, &tls.Config{
			Certificates: []tls.Certificate{config.TLSCert},
		})
		clientResCh <- rdpTLSResult{conn, conn.Handshake()}
	}()

	honeyRes := <-honeyResCh
	if honeyRes.err != nil {
		<-clientResCh
		return fmt.Errorf("rdp: TLS handshake with honeypot failed: %w", honeyRes.err)
	}
	honeypotTLS := honeyRes.conn
	defer honeypotTLS.Close() // sends TLS close_notify → heralding gets clean EOF

	clientRes := <-clientResCh
	if clientRes.err != nil {
		return fmt.Errorf("rdp: TLS handshake with client failed: %w", clientRes.err)
	}
	clientTLS := clientRes.conn

	return rdpBidirectionalRelay(clientTLS, honeypotTLS, config)
}

// rdpRelayHalfTLS terminates TLS only toward the external client; relays plaintext to honeypot.
// Used for PROTOCOL_HYBRID and PROTOCOL_HYBRID_EX where the honeypot reads raw CredSSP frames.
func rdpRelayHalfTLS(config RDPConfig) error {
	clientTLS := tls.Server(config.ClientConn, &tls.Config{
		Certificates: []tls.Certificate{config.TLSCert},
	})
	if err := clientTLS.Handshake(); err != nil {
		return fmt.Errorf("rdp: TLS handshake with client failed: %w", err)
	}
	defer clientTLS.Close()

	return rdpBidirectionalRelay(clientTLS, config.HoneypotConn, config)
}

// rdpBidirectionalRelay relays data between clientSide and honeypotSide.
// clientSide may be a *tls.Conn; honeypotSide may be a plain net.Conn or *tls.Conn.
func rdpBidirectionalRelay(clientSide net.Conn, honeypotSide net.Conn, config RDPConfig) error {
	done := make(chan error, 2)

	// client → honeypot (with CredSSP/NLA detection)
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := clientSide.Read(buf)
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
				if _, werr := honeypotSide.Write(buf[:n]); werr != nil {
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

	// honeypot → client
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := honeypotSide.Read(buf)
			if n > 0 {
				if _, werr := clientSide.Write(buf[:n]); werr != nil {
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
// The CC with an RDP Negotiation Response is exactly 19 bytes:
//
//	[0-3]   TPKT header
//	[4]     LI (14)
//	[5]     CC TPDU code (0xD0)
//	[6-10]  DST-REF, SRC-REF, Class
//	[11]    RDP Negotiation Response type (0x02)
//	[12]    flags
//	[13-14] length (8)
//	[15-18] selectedProtocol (uint32 LE)
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
