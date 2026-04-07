package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/confluentinc/confluent-kafka-go/v2/kafka"
)

type Event struct {
	FlowID      string `json:"flow_id"`
	Timestamp   string `json:"timestamp"`
	SrcIP       string `json:"src_ip"`
	SrcPort     int    `json:"src_port"`
	DstPort     int    `json:"dst_port"`
	NDPIProto   string `json:"ndpi_proto"`
	NDPIApp     string `json:"ndpi_app"`
	Honeypot    string `json:"honeypot"`
	PayloadSrc  []byte `json:"payload_src"`
	PayloadDst  []byte `json:"payload_dst"`
	PayloadSize int64  `json:"payload_size"`
	AttackType  string `json:"attack_type,omitempty"`
	CVE         string `json:"cve,omitempty"`
	Severity    string `json:"severity,omitempty"`
}

func main() {
	brokers := os.Getenv("KAFKA_BROKERS")
	if brokers == "" {
		brokers = "localhost:9092"
	}
	topic := os.Getenv("KAFKA_TOPIC")
	if topic == "" {
		topic = "dpipot.payloads"
	}
	groupID := os.Getenv("KAFKA_GROUP_ID")
	if groupID == "" {
		groupID = "dpipot-consumer"
	}

	config := &kafka.ConfigMap{
		"bootstrap.servers":  brokers,
		"group.id":           groupID,
		"auto.offset.reset":  "earliest",
		"enable.auto.commit": true,
	}

	consumer, err := kafka.NewConsumer(config)
	if err != nil {
		log.Fatalf("Falha ao criar consumer: %v", err)
	}
	defer consumer.Close()

	err = consumer.Subscribe(topic, nil)
	if err != nil {
		log.Fatalf("Falha ao subscrever no topic: %v", err)
	}

	fmt.Println("═══════════════════════════════════════════════════════════")
	fmt.Println("  Kafka Consumer - dpipot.payloads")
	fmt.Println("═══════════════════════════════════════════════════════════")
	fmt.Printf("  Brokers: %s\n", brokers)
	fmt.Printf("  Topic:   %s\n", topic)
	fmt.Printf("  Group:   %s\n", groupID)
	fmt.Println("═══════════════════════════════════════════════════════════")
	fmt.Println()

	sigchan := make(chan os.Signal, 1)
	signal.Notify(sigchan, syscall.SIGINT, syscall.SIGTERM)

	run := true
	for run {
		select {
		case sig := <-sigchan:
			fmt.Printf("\nRecebido sinal %v, encerrando...\n", sig)
			run = false
		default:
			msg, err := consumer.ReadMessage(1)
			if err != nil {
				if err.(kafka.Error).Code() == kafka.ErrTimedOut {
					continue
				}
				log.Printf("Erro lendo mensagem: %v", err)
				continue
			}

			var event Event
			if err := json.Unmarshal(msg.Value, &event); err != nil {
				log.Printf("Erro decodificando JSON: %v", err)
				continue
			}

			fmt.Println("─────────────────────────────────────────────────────────────────")
			fmt.Println("📊 EVENTO RECEBIDO")
			fmt.Println("─────────────────────────────────────────────────────────────────")
			fmt.Printf("  Flow ID:     %s\n", event.FlowID)
			fmt.Printf("  Timestamp:   %s\n", event.Timestamp)
			fmt.Println()
			fmt.Println("  🌐 INFORMAÇÕES DE REDE")
			fmt.Printf("  ├── Src IP:       %s\n", event.SrcIP)
			fmt.Printf("  ├── Src Port:     %d\n", event.SrcPort)
			fmt.Printf("  └── Dst Port:     %d\n", event.DstPort)
			fmt.Println()
			fmt.Println("  🔍 CLASSIFICAÇÃO nDPI")
			fmt.Printf("  ├── Protocol:      %s\n", event.NDPIProto)
			fmt.Printf("  └── App:           %s\n", event.NDPIApp)
			fmt.Println()
			fmt.Printf("  🎯 Honeypot:      %s\n", event.Honeypot)
			fmt.Println()
			fmt.Println("  📦 PAYLOADS")
			payloadSrcStr := string(event.PayloadSrc)
			if len(payloadSrcStr) > 200 {
				payloadSrcStr = payloadSrcStr[:200] + "..."
			}
			payloadDstStr := string(event.PayloadDst)
			if len(payloadDstStr) > 200 {
				payloadDstStr = payloadDstStr[:200] + "..."
			}
			fmt.Printf("  ├── Src (%d bytes): %q\n", len(event.PayloadSrc), payloadSrcStr)
			fmt.Printf("  ├── Dst (%d bytes): %q\n", len(event.PayloadDst), payloadDstStr)
			fmt.Printf("  └── Total Size:     %d bytes\n", event.PayloadSize)
			if event.AttackType != "" || event.CVE != "" {
				fmt.Println()
				fmt.Println("  ⚠️  ML ANALYSIS")
				fmt.Printf("  ├── Attack Type: %s\n", event.AttackType)
				fmt.Printf("  ├── CVE:         %s\n", event.CVE)
				fmt.Printf("  └── Severity:    %s\n", event.Severity)
			}
			fmt.Println("─────────────────────────────────────────────────────────────────")
			fmt.Println()
		}
	}
}
