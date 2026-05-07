package mitm

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/spawnzao/dpipot-ng/proxy/internal/kafka"
	"go.uber.org/zap"
)

// RDPConfig holds configuration for RDP MITM handler
type RDPConfig struct {
	ClientConn net.Conn
	HoneypotConn net.Conn
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

// HandleRDP performs RDP MITM with NLA/CredSSP detection
// RDP is server-first: honeypot sends X.224 + TLS ServerHello first
func HandleRDP(config RDPConfig) error {
	serverBuf := make([]byte, 4096)

	// 1. Read first packet from honeypot (X.224 Connection Confirm + TLS)
	n, err := config.HoneypotConn.Read(serverBuf)
	if err != nil || n == 0 {
		return fmt.Errorf("rdp: failed reading from honeypot: %w", err)
	}
	config.Logger("RDP: received %d bytes from honeypot (X.224+TLS)", n)

	// 2. Forward honeypot greeting to client
	if _, err := config.ClientConn.Write(serverBuf[:n]); err != nil {
		return fmt.Errorf("rdp: failed writing to client: %w", err)
	}

	// 3. Main bidirectional loop with CredSSP/NLA detection
	clientBuf := make([]byte, 4096)
	done := make(chan error, 2)

	// Goroutine: client → honeypot
	go func() {
		for {
			n, err := config.ClientConn.Read(clientBuf)
			if n > 0 {
				// Detect CredSSP/NLA (starts with ASN.1 SEQUENCE 0x30)
				if isCredSSP(clientBuf[:n]) {
					config.OnEvent(&kafka.Event{
						FlowID:      config.FlowID,
						Timestamp:   time.Now(),
						SrcIP:       config.SrcIP,
						SrcPort:     config.SrcPort,
						DstIP:       config.DstIP,
						DstPort:     config.DstPort,
						NDPIProto:   "RDP",
						NDPIApp:    "ntlmssp_auth",
						AttackType:  fmt.Sprintf("ntlmssp:%x", clientBuf[:min(n, 32)]),
						Honeypot:   "heralding:3389",
						Instance:    "proxy",
					})
				}
				// Forward to honeypot
				if _, err := config.HoneypotConn.Write(clientBuf[:n]); err != nil {
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

	// Goroutine: honeypot → client
	go func() {
		for {
			n, err := config.HoneypotConn.Read(clientBuf)
			if n > 0 {
				if _, err := config.ClientConn.Write(clientBuf[:n]); err != nil {
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

// isCredSSP detects NLA CredSSP in client data
// CredSSP starts with ASN.1 SEQUENCE (0x30) containing SPNEGO/NTLM
func isCredSSP(data []byte) bool {
	if len(data) < 2 {
		return false
	}
	// Look for ASN.1 SEQUENCE tag (0x30) followed by length
	// CredSSP/NTLM typically starts with SPNEGO OID or NTLMSSP marker
	for i := 0; i < len(data)-5; i++ {
		// Check for "NTLMSSP" marker in CredSSP
		if data[i] == 'N' && data[i+1] == 'T' && data[i+2] == 'L' && 
			data[i+3] == 'M' && data[i+4] == 'S' && data[i+5] == 'S' && data[i+6] == 'P' {
			return true
		}
		// Check for ASN.1 SEQUENCE (SPNEGO negotiation)
		if data[i] == 0x30 {
			return true
		}
	}
	return false
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
