package mitm

import (
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/spawnzao/dpipot-ng/proxy/internal/kafka"
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

// HandleRDP performs RDP MITM relay with TLS termination on both sides.
//
// RDP with TLS (PROTOCOL_SSL) negotiation flow:
//  1. Client  → Proxy  → Honeypot : X.224 Connection Request (plaintext)
//  2. Honeypot → Proxy  → Client  : X.224 Connection Confirm  (plaintext, PROTOCOL_SSL selected)
//  3. Proxy does TLS as server with client, TLS as client with honeypot
//  4. Bidirectional relay over the two TLS sessions (CredSSP/NLA detection)
func HandleRDP(config RDPConfig) error {
	// 1. Forward client's X.224 Connection Request to honeypot
	if len(config.FirstChunk) > 0 {
		if _, err := config.HoneypotConn.Write(config.FirstChunk); err != nil {
			return fmt.Errorf("rdp: failed forwarding X.224 CR to honeypot: %w", err)
		}
		config.Logger("RDP: forwarded %d bytes (X.224 CR) to honeypot", len(config.FirstChunk))
	}

	// 2. Read honeypot's X.224 Connection Confirm
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

	// 4. TLS MITM: proxy acts as TLS server toward client, TLS client toward honeypot.
	//    Ambos os lados precisam de canais TLS independentes — relay transparente de bytes
	//    não funciona porque o honeypot chama do_handshake() na própria conexão TCP.

	// 4a. TLS com o cliente (proxy = servidor TLS)
	clientTLSCfg := &tls.Config{
		Certificates: []tls.Certificate{config.TLSCert},
	}
	clientTLS := tls.Server(config.ClientConn, clientTLSCfg)
	if err := clientTLS.Handshake(); err != nil {
		return fmt.Errorf("rdp: TLS handshake with client failed: %w", err)
	}
	config.Logger("RDP: TLS handshake with client OK")

	// 4b. TLS com o honeypot (proxy = cliente TLS, skipa verificação de cert)
	honeypotTLS := tls.Client(config.HoneypotConn, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec
	if err := honeypotTLS.Handshake(); err != nil {
		return fmt.Errorf("rdp: TLS handshake with honeypot failed: %w", err)
	}
	config.Logger("RDP: TLS handshake with honeypot OK")

	// 5. Bidirectional relay — buffers separados por goroutine
	done := make(chan error, 2)

	// client → honeypot (com detecção de CredSSP/NLA)
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

	// honeypot → client
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

// isCredSSP detects NLA/CredSSP traffic: NTLMSSP marker ou SPNEGO ASN.1 SEQUENCE.
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
