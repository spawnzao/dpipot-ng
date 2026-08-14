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
	Honeypot      string    `json:"honeypot,omitempty"`
	HoneypotError string    `json:"honeypot_error,omitempty"`
	PayloadSrc    []byte    `json:"-"`
	PayloadDst    []byte    `json:"-"`
	PayloadSrcHex string    `json:"payload_src_hex,omitempty"` // hex do payload cliente→honeypot (regex no ES)
	PayloadDstHex string    `json:"payload_dst_hex,omitempty"` // hex do payload honeypot→cliente
	PayloadSrcB64 string    `json:"payload_src_b64,omitempty"` // base64 explícito; compatível com decode_base64 do ES
	PayloadDstB64 string    `json:"payload_dst_b64,omitempty"` // base64 explícito
	DurationMs    float64   `json:"duration_ms,omitempty"`
	AttackType    string    `json:"attack_type,omitempty"`
	SSHResponse   string    `json:"ssh_response,omitempty"` // output do servidor SSH capturado pelo MITM (resposta ao comando do atacante)
	Severity      string    `json:"severity,omitempty"`
	Instance      string    `json:"instance,omitempty"`
	PortMismatch  bool      `json:"port_mismatch,omitempty"`  // true: ndpi_proto ≠ protocolo esperado para dst_port
	ExpectedProto string    `json:"expected_proto,omitempty"` // protocolo esperado pela porta (ex: "SSH" para 22)
	TrackerFound  bool      `json:"tracker_found,omitempty"`  // true: FlowTracker respondeu com protocolo conhecido

	// campos de rede extraídos via FlowTracker (origem: cabeçalhos IP/TCP do atacante)
	TTL       uint8   `json:"ttl,omitempty"`        // IP TTL / IPv6 Hop Limit do cliente
	TOS       *uint8  `json:"tos,omitempty"`         // IP TOS / Traffic Class; ponteiro para serializar 0
	TCPWindow *uint16 `json:"tcp_window,omitempty"`  // TCP window size; ponteiro para serializar 0
	IPVersion uint8   `json:"ip_version,omitempty"`  // 4 ou 6
	Category  uint32 `json:"category,omitempty"`   // nDPI category ID
	TCPFlags  string `json:"tcp_flags,omitempty"`  // flags legíveis: "SYN ACK PSH …"
	Transport string `json:"transport,omitempty"`  // "tcp" ou "udp"
	PayloadLen *int  `json:"payload_len,omitempty"` // tamanho do pacote IP; nil=omitido (proxy), 0+=sempre enviado (nDPI)
	Ethertype string `json:"ethertype,omitempty"`  // "0x0800" (IPv4) | "0x86DD" (IPv6)
	IPProto   int    `json:"ip_proto,omitempty"`   // 6=TCP 17=UDP

	// métricas TCP da conexão cliente→proxy (getsockopt TCP_INFO)
	RttMs          float64 `json:"rtt_ms,omitempty"`          // RTT suavizado (µs→ms)
	RttVarMs       float64 `json:"rtt_var_ms,omitempty"`      // variância do RTT (µs→ms)
	TCPRetransmits uint8   `json:"tcp_retransmits,omitempty"` // retransmissões não recuperadas

	// telemetria de capacidade — preenchido em eventos de fluxo, rejected e heartbeat
	SlotsUsed   *int `json:"slots_used,omitempty"`
	SlotsMax    int  `json:"slots_max,omitempty"`
	PerIPActive int     `json:"per_ip_active,omitempty"`

	// tipo do evento — "flow" | "heartbeat" | "rejected"
	EventType string `json:"event_type,omitempty"`

	// campos exclusivos de eventos internos (event_type = "heartbeat")
	// Todos usam ponteiro para aparecerem mesmo quando zero — diagnóstico requer visibilidade completa.
	KafkaDrops    *int64  `json:"kafka_drops,omitempty"`
	KafkaStatus   string  `json:"kafka_status,omitempty"` // "ok" | "error"
	UptimeSec     float64 `json:"uptime_sec,omitempty"`
	KafkaChanLen  *int    `json:"kafka_chan_len,omitempty"`  // eventos no canal Go aguardando drain
	KafkaQueueLen *int    `json:"kafka_queue_len,omitempty"` // mensagens no librdkafka aguardando entrega

	// erros de entrega librdkafka — preenchido no heartbeat; reset por intervalo
	// kafka_delivery_errors: callbacks com qualquer erro (broker indisponível, auth, etc.)
	// kafka_delivery_dropped: subconjunto — perdas definitivas por delivery.timeout.ms expirado
	KafkaDeliveryErrors  *int64 `json:"kafka_delivery_errors,omitempty"`
	KafkaDeliveryDropped *int64 `json:"kafka_delivery_dropped,omitempty"`
	KafkaMarshalErrors   *int64 `json:"kafka_marshal_errors,omitempty"`  // eventos perdidos por json.Marshal falhou
	KafkaProduceErrors   *int64 `json:"kafka_produce_errors,omitempty"`  // eventos perdidos por Produce() rejeitou (fila librdkafka cheia)

	// telemetria do classifier (AF_PACKET + nDPI) — preenchido no heartbeat via ClassifierTelemetry
	AFPacketKernelDrops *int64 `json:"afpacket_drops,omitempty"`           // drops no kernel (PACKET_STATISTICS); auto-reset pelo kernel
	AFPacketChanDrops   *int64 `json:"afpacket_chan_drops,omitempty"`      // drops no canal Go interno (1.000 slots)
	NDPIPackets         *int64 `json:"ndpi_packets_processed,omitempty"`   // pacotes processados pelo nDPI no intervalo
	NDPIFlowsActive     *int   `json:"ndpi_flows_active,omitempty"`        // flows ativos no sync.Map do nDPI (snapshot)
	NDPICleanupEvicted  *int64 `json:"ndpi_cleanup_evicted,omitempty"`     // flows removidos pelo cleanup no intervalo

	// tamanho atual da flow table in-process — preenchido no heartbeat
	FlowTableSize     *int   `json:"flow_table_size,omitempty"`
	FlowTableNotFound *int64 `json:"flow_table_not_found,omitempty"` // lookups sem entrada (nDPI ainda não classificou)
	FlowTableUnknown  *int64 `json:"flow_table_unknown,omitempty"`   // entrada existe mas protocolo é Unknown

	// qualidade de link — preenchido no heartbeat; permite calcular retransmits/fluxo por direção
	TCPRetransmitsClientTotal   *int64 `json:"tcp_retransmits_client_total,omitempty"`
	TCPRetransmitsHoneypotTotal *int64 `json:"tcp_retransmits_honeypot_total,omitempty"`
	FlowsClientTotal            *int64 `json:"flows_client_total,omitempty"`
	FlowsHoneypotTotal          *int64 `json:"flows_honeypot_total,omitempty"`

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
	topicNdpi  string
	brokers    string
	log        *zap.Logger

	events chan *Event
	quit   chan struct{}

	wg         sync.WaitGroup // tracks drain + watchdog goroutines
	deliveryWg sync.WaitGroup // tracks all handleDeliveryFor goroutines

	healthy          atomic.Bool
	closed           atomic.Bool
	lastOK           atomic.Int64 // Unix timestamp of last confirmed delivery
	errCount         atomic.Int64 // consecutive delivery errors; reset on success
	dropped          atomic.Int64 // eventos descartados por buffer cheio; reportado no heartbeat
	deliveryErrors   atomic.Int64 // callbacks de entrega com erro (qualquer tipo); reset por heartbeat
	deliveryDropped  atomic.Int64 // mensagens perdidas definitivamente (ErrMsgTimedOut); reset por heartbeat
	marshalErrors    atomic.Int64 // falhas de json.Marshal em drain(); reset por heartbeat
	produceErrors    atomic.Int64 // falhas de Produce() (fila librdkafka cheia); reset por heartbeat

	payloadB64Enabled bool
	payloadHexEnabled bool
}

func newKafkaConfig(brokers string) *kafka.ConfigMap {
	return &kafka.ConfigMap{
		"bootstrap.servers":            brokers,
		// enable.idempotence garante exactly-once na entrega ao broker:
		// librdkafka atribui (epoch, sequence_number) a cada mensagem e o broker
		// rejeita duplicatas com o mesmo número de sequência, mesmo sob retries.
		// Requer acks=all; com Kafka single-node (min.insync.replicas=1) a
		// performance é equivalente a acks=1.
		"enable.idempotence":           "true",
		"acks":                         "all",
		"retry.backoff.ms":             100,
		"queue.buffering.max.messages": 100000,
		"queue.buffering.max.kbytes":   1048576,
		"linger.ms":                    5,
		// Fail undelivered messages after 30s so delivery errors surface quickly
		// rather than silently accumulating for the default 5 minutes.
		"delivery.timeout.ms":      60000,
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
		topicNdpi:         topic + "-ndpi",
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

// ChanLen retorna quantos eventos estão no canal Go aguardando ser drenados para o librdkafka.
func (p *Producer) ChanLen() int {
	if p == nil {
		return 0
	}
	return len(p.events)
}

// QueueLen retorna quantas mensagens estão na fila interna do librdkafka aguardando entrega.
func (p *Producer) QueueLen() int {
	if p == nil {
		return 0
	}
	p.mu.RLock()
	n := p.inner.Len()
	p.mu.RUnlock()
	return n
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
			p.marshalErrors.Add(1)
			continue
		}

		topic := p.topicApp
		switch event.Instance {
		case "debug":
			topic = p.topicDebug
		}
		if event.EventType == "ndpi" {
			topic = p.topicNdpi
		}

		// flow events usam flow_id como key; para heartbeat/rejected sem flow_id,
		// usa pod_name|event_type para key estável — permite dedup no ES via _id.
		key := event.FlowID
		if key == "" {
			key = event.PodName + "|" + event.EventType
		}

		p.mu.RLock()
		err = p.inner.Produce(&kafka.Message{
			TopicPartition: kafka.TopicPartition{
				Topic:     &topic,
				Partition: kafka.PartitionAny,
			},
			Key:   []byte(key),
			Value: data,
		}, nil)
		p.mu.RUnlock()

		if err != nil {
			p.log.Error("kafka produce", zap.Error(err),
				zap.String("flow_id", event.FlowID),
			)
			p.healthy.Store(false)
			p.produceErrors.Add(1)
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
				p.deliveryErrors.Add(1)
				isTimeout := false
				if kerr, ok := ev.TopicPartition.Error.(kafka.Error); ok && kerr.Code() == kafka.ErrMsgTimedOut {
					isTimeout = true
					p.deliveryDropped.Add(1)
					p.log.Warn("kafka: mensagem perdida definitivamente (delivery.timeout.ms expirou)",
						zap.String("key", string(ev.Key)),
					)
				} else {
					p.log.Error("kafka delivery error",
						zap.Error(ev.TopicPartition.Error),
						zap.String("key", string(ev.Key)),
					)
				}
				p.healthy.Store(false)
				if !isTimeout {
					p.errCount.Add(1)
				}
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

// DeliveryErrorsAndReset retorna o número de callbacks de entrega com erro desde o último reset
// e zera o contador atomicamente. Conta qualquer tipo de erro de entrega do librdkafka.
func (p *Producer) DeliveryErrorsAndReset() int64 {
	if p == nil {
		return 0
	}
	return p.deliveryErrors.Swap(0)
}

// MarshalErrorsAndReset retorna o número de eventos perdidos por falha de json.Marshal
// desde o último reset e zera o contador.
func (p *Producer) MarshalErrorsAndReset() int64 {
	if p == nil {
		return 0
	}
	return p.marshalErrors.Swap(0)
}

// ProduceErrorsAndReset retorna o número de eventos perdidos por falha de Produce()
// (fila interna do librdkafka cheia) desde o último reset e zera o contador.
func (p *Producer) ProduceErrorsAndReset() int64 {
	if p == nil {
		return 0
	}
	return p.produceErrors.Swap(0)
}

// DeliveryDroppedAndReset retorna o número de mensagens perdidas definitivamente por timeout
// (delivery.timeout.ms expirou no librdkafka) desde o último reset e zera o contador.
// Essas perdas NÃO aparecem em kafka_drops (que cobre apenas overflow do canal Go).
func (p *Producer) DeliveryDroppedAndReset() int64 {
	if p == nil {
		return 0
	}
	return p.deliveryDropped.Swap(0)
}

// IntPtr, Int64Ptr, Uint8Ptr e Uint16Ptr retornam ponteiros para os valores.
// Usados em campos com omitempty que precisam aparecer no JSON mesmo quando zero.
func IntPtr(n int) *int         { return &n }
func Int64Ptr(n int64) *int64   { return &n }
func Uint8Ptr(n uint8) *uint8   { return &n }
func Uint16Ptr(n uint16) *uint16 { return &n }
