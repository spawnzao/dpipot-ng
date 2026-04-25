package mitm

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/spawnzao/dpipot-ng/proxy/internal/kafka"
)

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

func ParseServerFirstPortsTLS(raw string) map[uint16]string {
	result := make(map[uint16]string)
	if raw == "" {
		return result
	}

	for _, pair := range strings.Split(raw, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		parts := strings.SplitN(pair, ":", 2)
		if len(parts) != 2 {
			continue
		}
		port, err := strconv.ParseUint(strings.TrimSpace(parts[0]), 10, 16)
		if err != nil {
			continue
		}
		result[uint16(port)] = strings.TrimSpace(parts[1])
	}
	return result
}

func IsServerFirstTLSPort(portMap map[uint16]string, port uint16) bool {
	_, ok := portMap[port]
	return ok
}

func HandleServerFirstTLS(config ServerFirstTLSConfig) error {
	config.Logger("SF-TLS: started (port=%d, proto=%s, honeypot=%s)",
		config.DstPort, config.NDPIProto, config.HoneypotAddr)

	honeypotConn, err := net.DialTimeout("tcp", config.HoneypotAddr, 5*time.Second)
	if err != nil {
		config.Logger("SF-TLS: honeypot dial failed: %v", err)
		return fmt.Errorf("honeypot dial: %w", err)
	}
	defer honeypotConn.Close()
	config.Logger("SF-TLS: connected to honeypot")

	clientTLS := tls.Server(config.ClientConn, &tls.Config{
		Certificates: []tls.Certificate{config.Cert},
	})

	if err := clientTLS.Handshake(); err != nil {
		config.Logger("SF-TLS: handshake failed: %v", err)
		return fmt.Errorf("tls handshake: %w", err)
	}
	config.Logger("SF-TLS: TLS handshake OK")

	parser := NewParser(config.NDPIProto, config.DstPort)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		handleSFTLSData(clientTLS, honeypotConn, parser, config, "client->honeypot")
	}()

	go func() {
		defer wg.Done()
		handleSFTLSData(honeypotConn, clientTLS, parser, config, "honeypot->client")
	}()

	wg.Wait()
	config.Logger("SF-TLS: relay encerrado")
	return nil
}

func handleSFTLSData(src net.Conn, dst net.Conn, parser ProtocolParser, config ServerFirstTLSConfig, direction string) {
	buf := make([]byte, 4096)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			data := make([]byte, n)
			copy(data, buf[:n])

			if config.OnEvent != nil {
				var events []CaptureEvent
				if direction == "client->honeypot" {
					events = parser.ParseClientData(data, config.Logger)
				} else {
					events = parser.ParseServerData(data, config.Logger)
				}

				for _, ev := range events {
					if ev.Command != "" || ev.Username != "" || ev.Password != "" ||
						ev.Response != "" || ev.Banner != "" {
						config.OnEvent(&kafka.Event{
							FlowID:      config.FlowID,
							Timestamp:   time.Now(),
							SrcIP:       config.SrcIP,
							SrcPort:     config.SrcPort,
							DstIP:       config.DstIP,
							DstPort:     config.DstPort,
							NDPIProto:   config.NDPIProto,
							Honeypot:    config.HoneypotAddr,
							LogType:     "application",
						})
					}
				}
			}

			_, wErr := dst.Write(data)
			if wErr != nil {
				config.Logger("SF-TLS: erro escrevendo %s: %v", direction, wErr)
				return
			}
		}
		if err != nil {
			if err != io.EOF {
				config.Logger("SF-TLS: erro lendo %s: %v", direction, err)
			}
			return
		}
	}
}