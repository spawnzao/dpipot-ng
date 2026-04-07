# Kafka Consumer - dpipot

Consumer simples para visualizar eventos do Kafka no terminal.

## Variáveis de Ambiente

| Variável | Padrão | Descrição |
|----------|--------|-----------|
| `KAFKA_BROKERS` | `localhost:9092` | Endereço do Kafka |
| `KAFKA_TOPIC` | `dpipot.payloads` | Topic para consumir |
| `KAFKA_GROUP_ID` | `dpipot-consumer` | Group ID do consumer |

## Build

```bash
# Build local
cd tools/kafka-consumer
go build -o consumer .

# Build Docker
docker build -t dpipot-consumer:latest -f tools/kafka-consumer/Dockerfile .
```

## Uso

### Local (via port-forward)

```bash
# Forward do Kafka para localhost
kubectl port-forward svc/kafka-svc 9092:9092 -n dpipot &

# Executar consumer
KAFKA_BROKERS=localhost:9092 ./consumer
```

### Via kubectl exec (no pod do kafka)

```bash
kubectl exec -it kafka-0 -n dpipot -- \
  /opt/kafka/bin/kafka-console-consumer.sh \
  --bootstrap-server localhost:9092 \
  --topic dpipot.payloads \
  --from-beginning
```

### Docker (standalone)

```bash
docker run --rm -it \
  -e KAFKA_BROKERS=kafka-svc.dpipot.svc.cluster.local:9092 \
  dpipot-consumer:latest
```

## Exemplo de Saída

```
═══════════════════════════════════════════════════════════
  Kafka Consumer - dpipot.payloads
═══════════════════════════════════════════════════════════
  Brokers: kafka-svc:9092
  Topic:   dpipot.payloads
  Group:   dpipot-consumer
═══════════════════════════════════════════════════════════

─────────────────────────────────────────────────────────────────
📊 EVENTO RECEBIDO
─────────────────────────────────────────────────────────────────
  Flow ID:     abc123-def456
  Timestamp:   2024-01-15T10:30:45Z

  🌐 INFORMAÇÕES DE REDE
  ├── Src IP:       192.168.1.100
  ├── Src Port:     54321
  └── Dst Port:     22

  🔍 CLASSIFICAÇÃO nDPI
  ├── Protocol:      SSH
  └── App:           OpenSSH

  🎯 Honeypot:      cowrie-svc:22

  📦 PAYLOADS
  ├── Src (15 bytes): "root\n"
  ├── Dst (0 bytes): ""
  └── Total Size:     15 bytes
─────────────────────────────────────────────────────────────────
```
