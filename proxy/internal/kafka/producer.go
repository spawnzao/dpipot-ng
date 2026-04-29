package kafka

import (
	"encoding/json"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/confluentinc/confluent-kafka-go/v2/kafka"
	"go.uber.org/zap"
)

type Event struct {
	FlowID        string    `json:"flow_id"`
	Timestamp     time.Time `json:"timestamp"`
	SrcIP         string    `json:"src_ip"`
	SrcPort       int       `json:"src_port"`
	DstIP         string    `json:"dst_ip"`
	DstPort       int       `json:"dst_port"`
	NDPIProto     string    `json:"ndpi_proto"`
	NDPIApp       string    `json:"ndpi_app"`
	Honeypot      string    `json:"honeypot"`
	HoneypotError string    `json:"honeypot_error"`
	PayloadSrc    []byte    `json:"payload_src"`
	PayloadDst    []byte    `json:"payload_dst"`
	PayloadSize   int64     `json:"payload_size"`
	AttackType    string    `json:"attack_type,omitempty"`
	CVE           string    `json:"cve,omitempty"`
	Severity      string    `json:"severity,omitempty"`
	Instance      string    `json:"instance,omitempty"`
}

type Producer struct {
	producer   *kafka.Producer
	topicDebug string
	topicApp   string
	log        *zap.Logger
	events     chan *Event
	done       chan struct{}
	healthy    atomic.Bool
}

func NewProducer(brokers, topic string, log *zap.Logger) (*Producer, error) {
	p, err := kafka.NewProducer(&kafka.ConfigMap{
		"bootstrap.servers":            brokers,
		"acks":                         "1",
		"retries":                      3,
		"retry.backoff.ms":             100,
		"queue.buffering.max.messages": 100000,
		"queue.buffering.max.kbytes":   1048576,
		"linger.ms":                    5,
		"allow.auto.create.topics":     "true",
	})
	if err != nil {
		return nil, fmt.Errorf("kafka producer: %w", err)
	}

	topicDebug := topic + "-debug"
	topicApp := topic + "-application"

	prod := &Producer{
		producer:   p,
		topicDebug: topicDebug,
		topicApp:   topicApp,
		log:        log,
		events:     make(chan *Event, 10000),
		done:       make(chan struct{}),
	}
	prod.healthy.Store(true)

	go prod.drain()
	go prod.handleDelivery()

	return prod, nil
}

func (p *Producer) IsHealthy() bool {
	return p.healthy.Load()
}

func (p *Producer) Publish(event *Event) {
	select {
	case p.events <- event:
	default:
		p.log.Warn("kafka buffer cheio, evento descartado",
			zap.String("flow_id", event.FlowID),
		)
	}
}

func (p *Producer) Close() {
	close(p.events)
	<-p.done
	p.producer.Flush(5000)
	p.producer.Close()
}

func (p *Producer) drain() {
	defer close(p.done)

	for event := range p.events {
		data, err := json.Marshal(event)
		if err != nil {
			p.log.Error("marshal evento kafka", zap.Error(err))
			continue
		}

		topic := p.topicApp
		if event.Instance == "debug" {
			topic = p.topicDebug
		}

		err = p.producer.Produce(&kafka.Message{
			TopicPartition: kafka.TopicPartition{
				Topic:     &topic,
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
