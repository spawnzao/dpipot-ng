package mitm

import (
	"bytes"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/spawnzao/dpipot-ng/internal/kafka"
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

	// Acumula o payload completo de cada direção — necessário para protocolos
	// em modo-caractere (Telnet) onde cada Read() retorna 1 byte e o parser
	// precisa do stream completo para extrair username/password corretamente.
	var (
		mu        sync.Mutex
		clientBuf bytes.Buffer
		serverBuf bytes.Buffer
	)

	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := config.ClientConn.Read(buf)
			if n > 0 {
				chunk := make([]byte, n)
				copy(chunk, buf[:n])
				mu.Lock()
				clientBuf.Write(chunk)
				mu.Unlock()
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
				mu.Lock()
				serverBuf.Write(chunk)
				mu.Unlock()
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

	// Parseia os buffers acumulados UMA VEZ após o fechamento da conexão.
	// Isso garante que protocolos modo-caractere (Telnet) tenham o stream
	// completo disponível para extrair username/password corretamente.
	if config.OnEvent != nil {
		mu.Lock()
		srcData := clientBuf.Bytes()
		dstData := serverBuf.Bytes()
		mu.Unlock()

		for _, ev := range parser.ParseClientData(srcData, config.Logger) {
			ndpiApp := ndpiAppFromEvent(ev)
			attackType := formatAttackType(ev)
			if attackType == "" {
				continue
			}
			config.OnEvent(&kafka.Event{
				FlowID:     config.FlowID,
				TupleID:    config.TupleID,
				Timestamp:  time.Now(),
				SrcIP:      config.SrcIP,
				SrcPort:    config.SrcPort,
				DstIP:      config.DstIP,
				DstPort:    config.DstPort,
				NDPIProto:  config.NDPIProto,
				NDPIApp:    ndpiApp,
				AttackType: attackType,
				Honeypot:   config.HoneypotAddr,
				Instance:   "proxy",
				PayloadSrc: srcData,
			})
		}

		for _, ev := range parser.ParseServerData(dstData, config.Logger) {
			ndpiApp := ndpiAppFromEvent(ev)
			attackType := formatAttackType(ev)
			if attackType == "" {
				continue
			}
			config.OnEvent(&kafka.Event{
				FlowID:     config.FlowID,
				TupleID:    config.TupleID,
				Timestamp:  time.Now(),
				SrcIP:      config.SrcIP,
				SrcPort:    config.SrcPort,
				DstIP:      config.DstIP,
				DstPort:    config.DstPort,
				NDPIProto:  config.NDPIProto,
				NDPIApp:    ndpiApp,
				AttackType: attackType,
				Honeypot:   config.HoneypotAddr,
				Instance:   "proxy",
				PayloadDst: dstData,
			})
		}
	}

	return fmt.Errorf("serverfirst: %w", relayErr)
}
