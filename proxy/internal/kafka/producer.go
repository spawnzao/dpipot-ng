package kafka

import (
	"encoding/json"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/confluentinc/confluent-kafka-go/v2/kafka"
	"go.uber.org/zap"
)

// Event é o schema do evento publicado no Kafka.
// O ML vai consumir esse evento e adicionar attack_type e cve.
type Event struct {
	FlowID      string    `json:"flow_id"`
	Timestamp   time.Time `json:"timestamp"`
	SrcIP       string    `json:"src_ip"`
	SrcPort     int       `json:"src_port"`
	DstIP       string    `json:"dst_ip"`    // IP de destino original
	DstPort     int       `json:"dst_port"`  // porta original (SO_ORIGINAL_DST)
	NDPIProto   string    `json:"ndpi_proto"`
	NDPIApp     string    `json:"ndpi_app"`
	Honeypot    string    `json:"honeypot"`     // para qual honeypot foi roteado
	HoneypotError string  `json:"honeypot_error"` // erro na conexão ao honeypot (se houver)
	PayloadSrc  []byte    `json:"payload_src"` // bytes atacante → honeypot
	PayloadDst  []byte    `json:"payload_dst"` // bytes honeypot → atacante
	PayloadSize int64     `json:"payload_size"`

	// Preenchido pelo ML depois (começa vazio)
	AttackType string `json:"attack_type,omitempty"`
	CVE        string `json:"cve,omitempty"`
	Severity   string `json:"severity,omitempty"`
}

// Producer publica eventos no Kafka de forma assíncrona.
// Nunca bloqueia o pipe TCP — usa canal interno com buffer.
type Producer struct {
	producer *kafka.Producer
	topic    string
	log      *zap.Logger
	events   chan *Event
	done     chan struct{}
	healthy  atomic.Bool
}

func NewProducer(brokers, topic string, log *zap.Logger) (*Producer, error) {
	p, err := kafka.NewProducer(&kafka.ConfigMap{
		"bootstrap.servers":            brokers,
		"acks":                         "1",        // leader ack — balanço entre durabilidade e velocidade
		"retries":                      3,
		"retry.backoff.ms":             100,
		"queue.buffering.max.messages": 100000,
		"queue.buffering.max.kbytes":   1048576,    // 1GB buffer interno
		"linger.ms":                    5,          // agrupa mensagens por até 5ms
	})
	if err != nil {
		return nil, fmt.Errorf("kafka producer: %w", err)
	}

	prod := &Producer{
		producer: p,
		topic:    topic,
		log:      log,
		events:   make(chan *Event, 10000),
		done:     make(chan struct{}),
	}
	prod.healthy.Store(true)

	go prod.drain()
	go prod.handleDelivery()

	return prod, nil
}

// IsHealthy retorna true se o producer está conectado ao Kafka.
func (p *Producer) IsHealthy() bool {
	return p.healthy.Load()
}

// Publish envia um evento para o canal interno.
// Retorna imediatamente — nunca bloqueia o pipe TCP.
// Se o canal estiver cheio (10k eventos), o evento é descartado com log de warning.
func (p *Producer) Publish(event *Event) {
	select {
	case p.events <- event:
	default:
		p.log.Warn("kafka buffer cheio, evento descartado",
			zap.String("flow_id", event.FlowID),
		)
	}
}

// Close drena o canal e fecha o producer graciosamente.
func (p *Producer) Close() {
	close(p.events)
	<-p.done
	p.producer.Flush(5000) // aguarda até 5s para entregar mensagens pendentes
	p.producer.Close()
}

// drain lê do canal interno e publica no Kafka.
// Roda em goroutine separada.
func (p *Producer) drain() {
	defer close(p.done)

	for event := range p.events {
		data, err := json.Marshal(event)
		if err != nil {
			p.log.Error("marshal evento kafka", zap.Error(err))
			continue
		}

		// usa flow_id como partition key — garante que
		// todos os eventos do mesmo fluxo vão para a mesma partição
		err = p.producer.Produce(&kafka.Message{
			TopicPartition: kafka.TopicPartition{
				Topic:     &p.topic,
				Partition: kafka.PartitionAny,
			},
			Key:   []byte(event.FlowID),
			Value: data,
		}, nil)

		if err != nil {
			p.log.Error("kafka produce", zap.Error(err),
				zap.String("flow_id", event.FlowID),
			)
			p.healthy.Store(false)
		} else {
			p.healthy.Store(true)
		}
	}
}

// handleDelivery processa confirmações e erros de entrega do Kafka.
func (p *Producer) handleDelivery() {
	for e := range p.producer.Events() {
		switch ev := e.(type) {
		case *kafka.Message:
			if ev.TopicPartition.Error != nil {
				p.log.Error("kafka delivery error",
					zap.Error(ev.TopicPartition.Error),
					zap.String("key", string(ev.Key)),
				)
			}
		}
	}
}
