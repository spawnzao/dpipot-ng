package mitm

import (
	"fmt"
	"net"
	"time"

	"github.com/spawnzao/dpipot-ng/proxy/internal/kafka"
)

type ServerFirstConfig struct {
	ClientConn     net.Conn
	HoneypotConn   net.Conn
	FlowID         string
	TupleID        string
	SrcIP          string
	SrcPort        int
	DstIP          string
	DstPort        int
	HoneypotAddr   string
	NDPIProto      string
	MaxPayloadSize int64
	Deadline       time.Time
	OnEvent        func(event *kafka.Event)
	Logger         func(string, ...interface{})
}

func HandleServerFirst(config ServerFirstConfig) error {
	config.Logger("ServerFirst: relay iniciado com conexão existente")

	if !config.Deadline.IsZero() {
		config.ClientConn.SetDeadline(config.Deadline)   //nolint:errcheck
		config.HoneypotConn.SetDeadline(config.Deadline) //nolint:errcheck
	}

	parser := NewParser(config.NDPIProto, config.DstPort)

	errChan := make(chan error, 2)

	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := config.ClientConn.Read(buf)
			if n > 0 {
				chunk := make([]byte, n)
				copy(chunk, buf[:n])

				if config.OnEvent != nil {
					for _, ev := range parser.ParseClientData(chunk, config.Logger) {
						config.OnEvent(&kafka.Event{
							FlowID:     config.FlowID,
							TupleID:    config.TupleID,
							Timestamp:  time.Now(),
							SrcIP:      config.SrcIP,
							SrcPort:    config.SrcPort,
							DstIP:      config.DstIP,
							DstPort:    config.DstPort,
							NDPIProto:  config.NDPIProto,
							NDPIApp:    string(ev.EventType),
							AttackType: formatAttackType(ev),
							Honeypot:   config.HoneypotAddr,
							Instance:   "proxy",
							PayloadSrc: chunk,
						})
					}
				}

				if _, wErr := config.HoneypotConn.Write(chunk); wErr != nil {
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
			n, err := config.HoneypotConn.Read(buf)
			if n > 0 {
				chunk := make([]byte, n)
				copy(chunk, buf[:n])

				if config.OnEvent != nil {
					for _, ev := range parser.ParseServerData(chunk, config.Logger) {
						config.OnEvent(&kafka.Event{
							FlowID:     config.FlowID,
							TupleID:    config.TupleID,
							Timestamp:  time.Now(),
							SrcIP:      config.SrcIP,
							SrcPort:    config.SrcPort,
							DstIP:      config.DstIP,
							DstPort:    config.DstPort,
							NDPIProto:  config.NDPIProto,
							NDPIApp:    string(ev.EventType),
							AttackType: formatAttackType(ev),
							Honeypot:   config.HoneypotAddr,
							Instance:   "proxy",
							PayloadDst: chunk,
						})
					}
				}

				if _, wErr := config.ClientConn.Write(chunk); wErr != nil {
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
	config.Logger("ServerFirst: relay encerrou: %v", relayErr)

	config.HoneypotConn.Close() //nolint:errcheck
	config.ClientConn.Close()   //nolint:errcheck

	return fmt.Errorf("serverfirst: %w", relayErr)
}
