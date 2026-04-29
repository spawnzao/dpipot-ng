package mitm

import (
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/spawnzao/dpipot-ng/proxy/internal/kafka"
)

func IsServerFirstTLSPort(portMap map[uint16]string, port uint16) bool {
	_, ok := portMap[port]
	return ok
}

type ServerFirstTLSConfig struct {
	ClientConn     net.Conn
	HoneypotConn   net.Conn
	Cert           tls.Certificate
	FlowID         string
	SrcIP          string
	SrcPort        int
	DstIP          string
	DstPort        int
	HoneypotAddr   string
	NDPIProto      string
	MaxPayloadSize int64
	OnEvent        func(event *kafka.Event)
	Logger         func(string, ...interface{})
}

func HandleServerFirstTLS(config ServerFirstTLSConfig) error {
	config.Logger("SF-TLS: started (port=%d, proto=%s, honeypot=%s)",
		config.DstPort, config.NDPIProto, config.HoneypotAddr)

	honeypotConn, err := net.DialTimeout("tcp", config.HoneypotAddr, 5*time.Second)
	if err != nil {
		config.Logger("SF-TLS: honeypot dial failed: %v", err)
		return fmt.Errorf("honeypot dial: %w", err)
	}
	config.Logger("SF-TLS: connected to honeypot")

	clientTLS := tls.Server(config.ClientConn, &tls.Config{
		Certificates: []tls.Certificate{config.Cert},
		MinVersion:   tls.VersionTLS10,
	})

	if err := clientTLS.Handshake(); err != nil {
		config.Logger("SF-TLS: handshake failed: %v", err)
		honeypotConn.Close()
		return fmt.Errorf("tls handshake: %w", err)
	}
	config.Logger("SF-TLS: TLS handshake OK")

	parser := NewParser(config.NDPIProto, config.DstPort)

	errChan := make(chan error, 2)

	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := clientTLS.Read(buf)
			if n > 0 {
				data := make([]byte, n)
				copy(data, buf[:n])

				if config.OnEvent != nil {
					events := parser.ParseClientData(data, config.Logger)
					for _, ev := range events {
						if ev.Command != "" || ev.Username != "" || ev.Password != "" {
							config.OnEvent(&kafka.Event{
								FlowID:     config.FlowID,
								Timestamp:  time.Now(),
								SrcIP:      config.SrcIP,
								SrcPort:    config.SrcPort,
								DstIP:      config.DstIP,
								DstPort:    config.DstPort,
								NDPIProto:  config.NDPIProto,
								NDPIApp:    string(ev.EventType),
								AttackType: formatAttackType(ev),
								Honeypot:   config.HoneypotAddr,
								LogType:    "application",
								PayloadSrc: data,
							})
						}
					}
				}

				_, wErr := honeypotConn.Write(data)
				if wErr != nil {
					errChan <- wErr
					return
				}
			}
			if err != nil {
				errChan <- err
				return
			}
		}
	}()

	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := honeypotConn.Read(buf)
			if n > 0 {
				data := make([]byte, n)
				copy(data, buf[:n])

				if config.OnEvent != nil {
					events := parser.ParseServerData(data, config.Logger)
					for _, ev := range events {
						if ev.Response != "" || ev.Banner != "" {
							config.OnEvent(&kafka.Event{
								FlowID:     config.FlowID,
								Timestamp:  time.Now(),
								SrcIP:      config.SrcIP,
								SrcPort:    config.SrcPort,
								DstIP:      config.DstIP,
								DstPort:    config.DstPort,
								NDPIProto:  config.NDPIProto,
								NDPIApp:    string(ev.EventType),
								AttackType: formatAttackType(ev),
								Honeypot:   config.HoneypotAddr,
								LogType:    "application",
								PayloadDst: data,
							})
						}
					}
				}

				_, wErr := clientTLS.Write(data)
				if wErr != nil {
					errChan <- wErr
					return
				}
			}
			if err != nil {
				errChan <- err
				return
			}
		}
	}()

	relayErr := <-errChan
	config.Logger("SF-TLS: relay ended: %v", relayErr)

	honeypotConn.Close()
	clientTLS.Close()
	config.ClientConn.Close()

	return nil
}