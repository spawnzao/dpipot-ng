package mitm

import (
	"bytes"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/spawnzao/dpipot-ng/internal/kafka"
)

// orderedChunk records a single read from one direction of the relay in the order
// it arrived, so BiParser implementations can correlate server prompts with the
// client responses that follow them.
type orderedChunk struct {
	fromClient bool
	data       []byte
}

type ServerFirstConfig struct {
	ClientConn        net.Conn
	HoneypotConn      net.Conn
	FlowID            string
	TupleID           string
	SrcIP             string
	SrcPort           int
	DstIP             string
	DstPort           int
	HoneypotAddr      string
	NDPIProto         string
	MaxPayloadSize    int64
	Deadline          time.Time
	InitialServerData []byte // greeting already read and forwarded by handler.go before calling us
	OnEvent           func(event *kafka.Event)
	Logger            func(string, ...interface{})
}

func HandleServerFirst(config ServerFirstConfig) error {
	config.Logger("ServerFirst: relay iniciado com conexão existente")

	if !config.Deadline.IsZero() {
		config.ClientConn.SetDeadline(config.Deadline)   //nolint:errcheck
		config.HoneypotConn.SetDeadline(config.Deadline) //nolint:errcheck
	}

	parser := NewParser(config.NDPIProto, config.DstPort)

	errChan := make(chan error, 2)

	var (
		mu        sync.Mutex
		chunks    []orderedChunk
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
				chunks = append(chunks, orderedChunk{fromClient: true, data: chunk})
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
				chunks = append(chunks, orderedChunk{fromClient: false, data: chunk})
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

	if config.OnEvent == nil {
		return fmt.Errorf("serverfirst: %w", relayErr)
	}

	mu.Lock()
	localChunks := chunks
	srcPayload := clientBuf.Bytes()
	dstPayload := serverBuf.Bytes()
	mu.Unlock()

	if bp, ok := parser.(BiParser); ok {
		// Feed the initial greeting so the state machine sees the first server prompt.
		if len(config.InitialServerData) > 0 {
			for _, ev := range bp.FeedServer(config.InitialServerData) {
				emitBiEvent(config, ev, srcPayload, dstPayload)
			}
		}
		for _, chunk := range localChunks {
			var events []CaptureEvent
			if chunk.fromClient {
				events = bp.FeedClient(chunk.data)
			} else {
				events = bp.FeedServer(chunk.data)
			}
			for _, ev := range events {
				emitBiEvent(config, ev, srcPayload, dstPayload)
			}
		}
	} else {
		for _, ev := range parser.ParseClientData(srcPayload, config.Logger) {
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
				PayloadSrc: srcPayload,
			})
		}
		for _, ev := range parser.ParseServerData(dstPayload, config.Logger) {
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
				PayloadDst: dstPayload,
			})
		}
	}

	return fmt.Errorf("serverfirst: %w", relayErr)
}

func emitBiEvent(config ServerFirstConfig, ev CaptureEvent, payloadSrc, payloadDst []byte) {
	if config.OnEvent == nil {
		return
	}
	ndpiApp := ndpiAppFromEvent(ev)
	attackType := formatAttackType(ev)
	if ndpiApp == "" && attackType == "" && ev.VNCAuthHash == "" && ev.VNCAuthResult == "" {
		return
	}
	config.OnEvent(&kafka.Event{
		FlowID:           config.FlowID,
		TupleID:          config.TupleID,
		Timestamp:        time.Now(),
		SrcIP:            config.SrcIP,
		SrcPort:          config.SrcPort,
		DstIP:            config.DstIP,
		DstPort:          config.DstPort,
		NDPIProto:        config.NDPIProto,
		NDPIApp:          ndpiApp,
		AttackType:       attackType,
		Honeypot:         config.HoneypotAddr,
		Instance:         "proxy",
		TelnetAttempt:    ev.TelnetAttempt,
		VNCServerVersion: ev.VNCServerVersion,
		VNCClientVersion: ev.VNCClientVersion,
		VNCSecType:       ev.VNCSecType,
		VNCAuthHash:      ev.VNCAuthHash,
		VNCAuthResult:    ev.VNCAuthResult,
		PayloadSrc:       payloadSrc,
		PayloadDst:       payloadDst,
	})
}
