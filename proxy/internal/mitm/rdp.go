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

type rdpTLSResult struct {
	conn *tls.Conn
	err  error
}

// HandleRDP performs RDP MITM relay with TLS termination on both sides.
//
// RDP com TLS (PROTOCOL_SSL) flow:
//  1. Client  → Proxy  → Honeypot : X.224 Connection Request (plaintext)
//  2. Honeypot → Proxy  → Client  : X.224 Connection Confirm  (plaintext, PROTOCOL_SSL)
//  3. Proxy faz TLS com honeypot E com client em paralelo para evitar timeout
//  4. Relay bidirecional sobre os dois canais TLS (detecção de CredSSP/NLA)
func HandleRDP(config RDPConfig) error {
	// 1. Encaminha X.224 Connection Request do client para o honeypot
	if len(config.FirstChunk) > 0 {
		if _, err := config.HoneypotConn.Write(config.FirstChunk); err != nil {
			return fmt.Errorf("rdp: failed forwarding X.224 CR to honeypot: %w", err)
		}
		config.Logger("RDP: forwarded %d bytes (X.224 CR) to honeypot", len(config.FirstChunk))
	}

	// 2. Lê X.224 Connection Confirm do honeypot
	serverBuf := make([]byte, 4096)
	n, err := config.HoneypotConn.Read(serverBuf)
	if err != nil || n == 0 {
		return fmt.Errorf("rdp: failed reading X.224 CC from honeypot: %w", err)
	}
	config.Logger("RDP: received %d bytes (X.224 CC) from honeypot", n)

	// 3. Encaminha X.224 CC para o client
	if _, err := config.ClientConn.Write(serverBuf[:n]); err != nil {
		return fmt.Errorf("rdp: failed writing X.224 CC to client: %w", err)
	}

	// 4. Handshakes TLS em paralelo.
	//    Paralelo é obrigatório: o honeypot chama do_tls_handshake() imediatamente após
	//    enviar o X.224 CC. Se esperarmos o client TLS terminar antes de iniciar o
	//    honeypot TLS, o honeypot pode sofrer timeout. Com goroutines simultâneas,
	//    ambos os lados completam (ou falham) de forma independente.

	honeyResCh := make(chan rdpTLSResult, 1)
	clientResCh := make(chan rdpTLSResult, 1)

	// TLS com honeypot (proxy = cliente TLS)
	go func() {
		conn := tls.Client(config.HoneypotConn, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec
		honeyResCh <- rdpTLSResult{conn, conn.Handshake()}
	}()

	// TLS com o client externo (proxy = servidor TLS)
	go func() {
		conn := tls.Server(config.ClientConn, &tls.Config{
			Certificates: []tls.Certificate{config.TLSCert},
		})
		clientResCh <- rdpTLSResult{conn, conn.Handshake()}
	}()

	// Aguarda honeypot TLS — deve concluir rápido (LAN interna)
	honeyRes := <-honeyResCh
	if honeyRes.err != nil {
		<-clientResCh // drena o canal para evitar goroutine leak
		return fmt.Errorf("rdp: TLS handshake with honeypot failed: %w", honeyRes.err)
	}
	honeypotTLS := honeyRes.conn
	defer honeypotTLS.Close() // envia TLS close_notify → heralding recebe EOF limpo

	// Aguarda client TLS — scanners RST aqui, clientes reais completam
	clientRes := <-clientResCh
	if clientRes.err != nil {
		// defer fecha honeypotTLS com close_notify → sem SSLSyscallError no heralding
		return fmt.Errorf("rdp: TLS handshake with client failed: %w", clientRes.err)
	}
	clientTLS := clientRes.conn

	// 5. Relay bidirecional — buffers separados por goroutine
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

// isCredSSP detecta tráfego NLA/CredSSP: marcador NTLMSSP ou SPNEGO ASN.1 SEQUENCE.
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
