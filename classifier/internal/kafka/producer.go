package kafka

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/confluentinc/confluent-kafka-go/v2/kafka"
	"go.uber.org/zap"
)

type Event struct {
	FlowID     string    `json:"flow_id"`
	TupleID    string    `json:"tuple_id,omitempty"`
	Timestamp  time.Time `json:"timestamp"`
	SrcIP      string    `json:"src_ip"`
	SrcPort    int       `json:"src_port"`
	DstIP      string    `json:"dst_ip"`
	DstPort    int       `json:"dst_port"`
	NDPIProto  string    `json:"ndpi_proto"`
	NDPIApp    string    `json:"ndpi_app"`
	Category   uint32    `json:"category,omitempty"`
	TCPFlags   string    `json:"tcp_flags,omitempty"`
	PayloadLen int       `json:"payload_len,omitempty"`
	EtherType  string    `json:"ethertype,omitempty"`
	IPProto    uint8     `json:"ip_proto,omitempty"`
	Transport  string    `json:"transport,omitempty"`
	Instance   string    `json:"instance"`
}

type Producer struct {
	mu    sync.RWMutex
	inner *kafka.Producer // guarded by mu; swapped by watchdog on reconnect

	topicNdpi string
	brokers   string
	log       *zap.Logger

	events chan *Event
	quit   chan struct{}

	wg         sync.WaitGroup // tracks drain + watchdog goroutines
	deliveryWg sync.WaitGroup // tracks all handleDeliveryFor goroutines

	healthy  atomic.Bool
	closed   atomic.Bool
	lastOK   atomic.Int64 // Unix timestamp of last confirmed delivery
	errCount atomic.Int64 // consecutive delivery errors; reset on success
}

func newKafkaConfig(brokers string) *kafka.ConfigMap {
	return &kafka.ConfigMap{
		"bootstrap.servers":            brokers,
		"acks":                         "1",
		"retries":                      3,
		"retry.backoff.ms":             100,
		"queue.buffering.max.messages": 100000,
		"queue.buffering.max.kbytes":   1048576,
		"linger.ms":                    5,
		// Fail undelivered messages after 30s so delivery errors surface quickly
		// rather than silently accumulating for the default 5 minutes.
		"delivery.timeout.ms":      30000,
		"allow.auto.create.topics": "true",
	}
}

func NewProducer(brokers, topic string, log *zap.Logger) (*Producer, error) {
	p, err := kafka.NewProducer(newKafkaConfig(brokers))
	if err != nil {
		return nil, fmt.Errorf("kafka producer: %w", err)
	}

	prod := &Producer{
		inner:     p,
		topicNdpi: topic + "-ndpi",
		brokers:   brokers,
		log:       log,
		events:    make(chan *Event, 100000),
		quit:      make(chan struct{}),
	}
	prod.healthy.Store(true)
	prod.lastOK.Store(time.Now().Unix())

	prod.wg.Add(2) // drain + watchdog
	go prod.drain()
	go prod.watchdog()

	prod.deliveryWg.Add(1)
	go prod.handleDeliveryFor(p)

	return prod, nil
}

func (p *Producer) IsHealthy() bool {
	return p.healthy.Load()
}

// LastOK returns the timestamp of the last confirmed Kafka delivery.
func (p *Producer) LastOK() time.Time {
	return time.Unix(p.lastOK.Load(), 0)
}

func (p *Producer) Publish(event *Event) {
	if p.closed.Load() {
		return
	}
	select {
	case p.events <- event:
	default:
		p.log.Warn("kafka buffer cheio, evento ndpi descartado",
			zap.String("flow_id", event.FlowID),
		)
	}
}

func (p *Producer) Close() {
	p.closed.Store(true)
	close(p.events) // drain() exits its for-range after processing buffered events
	close(p.quit)   // watchdog() exits after current tick / reconnect completes
	p.wg.Wait()     // wait for drain + watchdog — no more Produce() calls or reconnects after this

	p.mu.RLock()
	inner := p.inner
	p.mu.RUnlock()

	inner.Flush(5000)
	inner.Close() // closes inner.Events() channel → handleDeliveryFor exits
	p.deliveryWg.Wait()
}

// drain reads from the events channel and sends messages to the current inner producer.
// The RLock is held during Produce() so that reconnect() (which holds the write lock
// while swapping inner) never races with an active Produce() call.
func (p *Producer) drain() {
	defer p.wg.Done()

	for event := range p.events {
		data, err := json.Marshal(event)
		if err != nil {
			p.log.Error("marshal evento kafka ndpi", zap.Error(err))
			continue
		}

		p.mu.RLock()
		err = p.inner.Produce(&kafka.Message{
			TopicPartition: kafka.TopicPartition{
				Topic:     &p.topicNdpi,
				Partition: kafka.PartitionAny,
			},
			Key:   []byte(event.FlowID),
			Value: data,
		}, nil)
		p.mu.RUnlock()

		if err != nil {
			p.log.Error("kafka produce ndpi", zap.Error(err),
				zap.String("flow_id", event.FlowID),
			)
			p.healthy.Store(false)
		}
	}
}

// handleDeliveryFor consumes the Events() channel of a specific kafka.Producer instance,
// updating health metrics on every delivery callback.
func (p *Producer) handleDeliveryFor(inner *kafka.Producer) {
	defer p.deliveryWg.Done()
	for e := range inner.Events() {
		switch ev := e.(type) {
		case *kafka.Message:
			if ev.TopicPartition.Error != nil {
				p.log.Error("kafka delivery error ndpi",
					zap.Error(ev.TopicPartition.Error),
					zap.String("key", string(ev.Key)),
				)
				p.healthy.Store(false)
				p.errCount.Add(1)
			} else {
				p.healthy.Store(true)
				p.errCount.Store(0)
				p.lastOK.Store(time.Now().Unix())
			}
		}
	}
}

// watchdog checks every 30 s whether deliveries have stalled and triggers a reconnect.
func (p *Producer) watchdog() {
	defer p.wg.Done()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-p.quit:
			return
		case <-ticker.C:
			since := time.Since(time.Unix(p.lastOK.Load(), 0))
			errs := p.errCount.Load()
			if since > 90*time.Second && errs > 0 {
				p.log.Warn("kafka watchdog: sem entrega confirmada há >90s, reconectando",
					zap.Duration("since_last_ok", since),
					zap.Int64("consecutive_errors", errs),
				)
				p.reconnect()
			}
			// Escalação final: se reconexões sucessivas falharam por >10 min, encerra o
			// processo para que o K8s reinicie o container com uma conexão completamente nova.
			// Só escalona se houver erros ativos (errs>0) para não sair por idle genuíno.
			if since > 10*time.Minute && errs > 0 {
				p.log.Error("kafka watchdog: sem entrega confirmada há >10min, encerrando para reinicialização pelo K8s",
					zap.Duration("since_last_ok", since),
					zap.Int64("consecutive_errors", errs),
				)
				os.Exit(1)
			}
		}
	}
}

// reconnect creates a new kafka.Producer, swaps it in atomically, and tears down the old one.
func (p *Producer) reconnect() {
	if p.closed.Load() {
		return
	}

	newInner, err := kafka.NewProducer(newKafkaConfig(p.brokers))
	if err != nil {
		p.log.Error("kafka watchdog: falha ao criar novo producer", zap.Error(err))
		return
	}

	// Start delivery handler for the new producer before swapping it in.
	p.deliveryWg.Add(1)
	go p.handleDeliveryFor(newInner)

	// Lock prevents any concurrent Produce() calls against the old inner
	// while we swap — drain() holds RLock during Produce().
	p.mu.Lock()
	old := p.inner
	p.inner = newInner
	p.mu.Unlock()

	// Reset only errCount so the watchdog can detect if the new producer also fails.
	// lastOK is NOT reset here — only a confirmed delivery callback should update it,
	// so the 10-minute escalation threshold correctly measures time since last real delivery.
	p.errCount.Store(0)
	p.healthy.Store(true)

	// Drain and close the old producer — this also unblocks handleDeliveryFor(old).
	old.Flush(3000)
	old.Close()

	p.log.Info("kafka watchdog: novo producer criado, aguardando confirmação de entrega")
}
