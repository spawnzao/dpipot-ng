package mitm

import (
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

// HandleRDP performs RDP MITM relay with CredSSP/NLA detection.
// RDP is client-first: client sends X.224 Connection Request, server responds
// with X.224 Connection Confirm, then TLS or NLA negotiation follows.
func HandleRDP(config RDPConfig) error {
	// 1. Forward client's X.224 Connection Request to honeypot
	if len(config.FirstChunk) > 0 {
		if _, err := config.HoneypotConn.Write(config.FirstChunk); err != nil {
			return fmt.Errorf("rdp: failed forwarding client request to honeypot: %w", err)
		}
		config.Logger("RDP: forwarded %d bytes from client to honeypot (X.224 CR)", len(config.FirstChunk))
	}

	// 2. Read honeypot's X.224 Connection Confirm response
	serverBuf := make([]byte, 4096)
	n, err := config.HoneypotConn.Read(serverBuf)
	if err != nil || n == 0 {
		return fmt.Errorf("rdp: failed reading X.224 CC from honeypot: %w", err)
	}
	config.Logger("RDP: received %d bytes from honeypot (X.224 CC)", n)

	// 3. Forward honeypot response to client
	if _, err := config.ClientConn.Write(serverBuf[:n]); err != nil {
		return fmt.Errorf("rdp: failed writing to client: %w", err)
	}

	// 4. Bidirectional relay — buffers separados por goroutine para evitar data race
	done := make(chan error, 2)

	// client → honeypot
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := config.ClientConn.Read(buf)
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
				if _, err := config.HoneypotConn.Write(buf[:n]); err != nil {
					done <- err
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
			n, err := config.HoneypotConn.Read(buf)
			if n > 0 {
				if _, err := config.ClientConn.Write(buf[:n]); err != nil {
					done <- err
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
