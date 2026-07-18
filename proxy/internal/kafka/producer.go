package kafka

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/confluentinc/confluent-kafka-go/v2/kafka"
	"go.uber.org/zap"
)

type Event struct {
	FlowID        string    `json:"flow_id,omitempty"`  // UUID do classifier; ausente se FlowTracker não respondeu
	TupleID       string    `json:"tuple_id,omitempty"` // 5-tupla normalizada; correlaciona com classifier
	Timestamp     time.Time `json:"timestamp"`
	SrcIP         string    `json:"src_ip"`
	SrcPort       int       `json:"src_port"`
	DstIP         string    `json:"dst_ip"`
	DstPort       int       `json:"dst_port"`
	NDPIProto     string    `json:"ndpi_proto"`
	NDPIApp       string    `json:"ndpi_app"`
	Honeypot      string    `json:"honeypot"`
	HoneypotError string    `json:"honeypot_error"`
	PayloadSrc    []byte    `json:"-"`
	PayloadDst    []byte    `json:"-"`
	PayloadSrcHex string    `json:"payload_src_hex,omitempty"` // hex do payload cliente→honeypot (regex no ES)
	PayloadDstHex string    `json:"payload_dst_hex,omitempty"` // hex do payload honeypot→cliente
	PayloadSrcB64 string    `json:"payload_src_b64,omitempty"` // base64 explícito; compatível com decode_base64 do ES
	PayloadDstB64 string    `json:"payload_dst_b64,omitempty"` // base64 explícito
	PayloadSize   int64     `json:"payload_size"`
	DurationMs    float64   `json:"duration_ms,omitempty"`
	AttackType    string    `json:"attack_type,omitempty"`
	CVE           string    `json:"cve,omitempty"`
	Severity      string    `json:"severity,omitempty"`
	Instance      string    `json:"instance,omitempty"`
	PortMismatch  bool      `json:"port_mismatch,omitempty"`  // true: ndpi_proto ≠ protocolo esperado para dst_port
	ExpectedProto string    `json:"expected_proto,omitempty"` // protocolo esperado pela porta (ex: "SSH" para 22)
	TrackerFound  bool      `json:"tracker_found,omitempty"`  // true: FlowTracker respondeu com protocolo conhecido

	// campos de rede extraídos via FlowTracker (origem: cabeçalhos IP/TCP do atacante)
	TTL       uint8  `json:"ttl,omitempty"`        // IP TTL / IPv6 Hop Limit do cliente
	TOS       uint8  `json:"tos,omitempty"`        // IP TOS / Traffic Class
	TCPWindow uint16 `json:"tcp_window,omitempty"` // TCP window size inicial
	IPVersion uint8  `json:"ip_version,omitempty"` // 4 ou 6

	// telemetria de capacidade — preenchido em eventos de fluxo, rejected e heartbeat
	SlotsUsed   int     `json:"slots_used,omitempty"`
	SlotsMax    int     `json:"slots_max,omitempty"`
	PerIPActive int     `json:"per_ip_active,omitempty"`

	// tipo do evento — "flow" | "heartbeat" | "rejected"
	EventType string `json:"event_type,omitempty"`

	// campos exclusivos de eventos internos (event_type = "heartbeat")
	KafkaDrops  int64   `json:"kafka_drops,omitempty"`
	KafkaStatus string  `json:"kafka_status,omitempty"` // "ok" | "error"
	UptimeSec   float64 `json:"uptime_sec,omitempty"`

	// telemetria do FlowTracker — preenchido no heartbeat
	FlowTrackerTimeouts  int64 `json:"flowtracker_timeouts,omitempty"`
	FlowTrackerNotFound  int64 `json:"flowtracker_not_found,omitempty"`
	FlowTrackerUnknown   int64 `json:"flowtracker_unknown,omitempty"`

	// identificação da instância — preenchido em todos os eventos
	NodeName string `json:"node_name,omitempty"` // spec.nodeName via Downward API
	PodName  string `json:"pod_name,omitempty"`  // metadata.name via Downward API
}

// enrichPayload preenche os campos *Hex e *B64 a partir dos bytes brutos,
// respeitando os toggles PAYLOAD_HEX_ENABLED e PAYLOAD_B64_ENABLED.
func (p *Producer) enrichPayload(e *Event) {
	if p.payloadHexEnabled && len(e.PayloadSrc) > 0 {
		e.PayloadSrcHex = hex.EncodeToString(e.PayloadSrc)
	}
	if p.payloadB64Enabled && len(e.PayloadSrc) > 0 {
		e.PayloadSrcB64 = base64.StdEncoding.EncodeToString(e.PayloadSrc)
	}
	if p.payloadHexEnabled && len(e.PayloadDst) > 0 {
		e.PayloadDstHex = hex.EncodeToString(e.PayloadDst)
	}
	if p.payloadB64Enabled && len(e.PayloadDst) > 0 {
		e.PayloadDstB64 = base64.StdEncoding.EncodeToString(e.PayloadDst)
	}
}

type Producer struct {
	mu    sync.RWMutex
	inner *kafka.Producer // guarded by mu; swapped by watchdog on reconnect

	topicDebug string
	topicApp   string
	brokers    string
	log        *zap.Logger

	events chan *Event
	quit   chan struct{}

	wg         sync.WaitGroup // tracks drain + watchdog goroutines
	deliveryWg sync.WaitGroup // tracks all handleDeliveryFor goroutines

	healthy  atomic.Bool
	closed   atomic.Bool
	lastOK   atomic.Int64 // Unix timestamp of last confirmed delivery
	errCount atomic.Int64 // consecutive delivery errors; reset on success
	dropped  atomic.Int64 // eventos descartados por buffer cheio; reportado no heartbeat

	payloadB64Enabled bool
	payloadHexEnabled bool
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

func NewProducer(brokers, topic string, log *zap.Logger, payloadB64, payloadHex bool) (*Producer, error) {
	p, err := kafka.NewProducer(newKafkaConfig(brokers))
	if err != nil {
		return nil, fmt.Errorf("kafka producer: %w", err)
	}

	prod := &Producer{
		inner:             p,
		topicDebug:        topic + "-debug",
		topicApp:          topic + "-application",
		brokers:           brokers,
		log:               log,
		events:            make(chan *Event, 100000),
		quit:              make(chan struct{}),
		payloadB64Enabled: payloadB64,
		payloadHexEnabled: payloadHex,
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
	if p == nil {
		return true // disabled = not a health failure
	}
	return p.healthy.Load()
}

// LastOK returns the timestamp of the last confirmed Kafka delivery.
func (p *Producer) LastOK() time.Time {
	return time.Unix(p.lastOK.Load(), 0)
}

// DroppedAndReset atomically returns the number of events dropped since the last call
// and resets the counter to zero. Using Swap(0) avoids the TOCTOU race that would occur
// with a separate Load() + Store(0): any drop that arrives between those two operations
// would be silently lost from the heartbeat report.
func (p *Producer) DroppedAndReset() int64 {
	if p == nil {
		return 0
	}
	return p.dropped.Swap(0)
}

func (p *Producer) Publish(event *Event) {
	if p == nil || p.closed.Load() {
		return
	}
	select {
	case p.events <- event:
	default:
		p.log.Warn("kafka buffer cheio, evento descartado",
			zap.String("flow_id", event.FlowID),
		)
		p.dropped.Add(1)
	}
}

func (p *Producer) Close() {
	if p == nil {
		return
	}
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
		p.enrichPayload(event)
		data, err := json.Marshal(event)
		if err != nil {
			p.log.Error("marshal evento kafka", zap.Error(err))
			continue
		}

		topic := p.topicApp
		if event.Instance == "debug" {
			topic = p.topicDebug
		}

		p.mu.RLock()
		err = p.inner.Produce(&kafka.Message{
			TopicPartition: kafka.TopicPartition{
				Topic:     &topic,
				Partition: kafka.PartitionAny,
			},
			Key:   []byte(event.FlowID),
			Value: data,
		}, nil)
		p.mu.RUnlock()

		if err != nil {
			p.log.Error("kafka produce", zap.Error(err),
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
				p.log.Error("kafka delivery error",
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
	// so the liveness probe can detect persistent failures even across reconnects.
	p.errCount.Store(0)
	p.healthy.Store(true)

	// Drain and close the old producer — this also unblocks handleDeliveryFor(old).
	old.Flush(3000)
	old.Close()

	p.log.Info("kafka watchdog: novo producer criado, aguardando confirmação de entrega")
}
