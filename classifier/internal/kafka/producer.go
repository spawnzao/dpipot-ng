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
	FlowID       string    `json:"flow_id"`
	Timestamp    time.Time `json:"timestamp"`
	SrcIP        string    `json:"src_ip"`
	SrcPort      int       `json:"src_port"`
	DstIP        string    `json:"dst_ip"`
	DstPort      int       `json:"dst_port"`
	NDPIProto    string    `json:"ndpi_proto"`
	NDPIApp      string    `json:"ndpi_app"`
	Category     uint32    `json:"category,omitempty"`
	TCPFlags     string    `json:"tcp_flags,omitempty"`
	PayloadLen   int       `json:"payload_len,omitempty"`
	EtherType    string    `json:"ethertype,omitempty"`
	IPProto      uint8     `json:"ip_proto,omitempty"`
	Transport    string    `json:"transport,omitempty"`
	Instance     string    `json:"instance"`
}

type Producer struct {
	producer  *kafka.Producer
	topicNdpi string
	log       *zap.Logger
	events    chan *Event
	done      chan struct{}
	healthy   atomic.Bool
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

	topicNdpi := topic + "-ndpi"

	prod := &Producer{
		producer:  p,
		topicNdpi: topicNdpi,
		log:       log,
		events:    make(chan *Event, 10000),
		done:      make(chan struct{}),
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
		p.log.Warn("kafka buffer cheio, evento ndpi descartado",
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
			p.log.Error("marshal evento kafka ndpi", zap.Error(err))
			continue
		}

		err = p.producer.Produce(&kafka.Message{
			TopicPartition: kafka.TopicPartition{
				Topic:     &p.topicNdpi,
				Partition: kafka.PartitionAny,
			},
			Key:   []byte(event.FlowID),
			Value: data,
		}, nil)

		if err != nil {
			p.log.Error("kafka produce ndpi", zap.Error(err),
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
				p.log.Error("kafka delivery error ndpi",
					zap.Error(ev.TopicPartition.Error),
					zap.String("key", string(ev.Key)),
				)
			}
		}
	}
}
