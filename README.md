# DPIot-NG

**A Kubernetes-native honeypot system with deep packet inspection and transparent traffic interception.**

DPIot-NG intercepts all TCP connections arriving at a node — without touching firewall rules on the attacker's path — routes each connection to the appropriate honeypot service based on the detected application protocol (nDPI), and emits structured events to Kafka for ingestion into Elasticsearch/Kibana. The system operates completely transparently: attackers connect to the real node IP and port, unaware they are being redirected.

---

## Architecture

```
                        ┌────────────────────────────────────────────────┐
                        │             Kubernetes Node (DaemonSet)        │
                        │                                                │
  Internet              │  ┌───────────────┐     ┌──────────────────┐    │
  TCP :22 / :80         │  │ init-container│     │   Classifier     │    │
  :443 / :3389 / ...    │  │  iptables     │     │  (AF_PACKET +    │    │
         │              │  │   TPROXY      │     │    nDPI 4.12)    │    │
         │              │  └──────┬────────┘     └────────┬─────────┘    │
         │              │         │ marks pkts 0x1        │ flow labels  │
         ▼              │         ▼                       │              │
 ┌──────────────┐       │  ┌──────────────┐ ◄─────────────┘              │
 │  iptables    │       │  │    Proxy     │                              │
 │  TPROXY rule │─────▶│  │  :8080       │                              │
 │  (mangle)    │       │  │              │                             │
 └──────────────┘       │  └──────┬───────┘                             │
                        │         │ route by protocol                   │
                        │         ├──── SSH  ──────▶ cowrie-svc:22      │
                        │         ├──── HTTP ──────▶ wordpot-svc:80     │
                        │         ├──── FTP/SMTP ──▶ heralding:21/25    │
                        │         ├──── MySQL ─────▶ heralding:3306     │
                        │         ├──── RDP  ──────▶ heralding:3389     │
                        │         └──── * ─────────▶ default honeypot   │
                        │                                                │
                        └───────────────────┬────────────────────────────┘
                                            │
                                            ▼
                                     ┌──────────────┐
                                     │    Kafka     │  dpipot.events
                                     └──────┬───────┘
                                            │
                              ┌─────────────┴─────────────┐
                              ▼                           ▼
                       ┌─────────────┐           ┌─────────────┐
                       │  Logstash   │           │  Filebeat   │
                       └──────┬──────┘           └──────┬──────┘
                              │                         │
                              └────────────┬────────────┘
                                           ▼
                                   ┌──────────────┐
                                   │Elasticsearch │
                                   │   + Kibana   │
                                   └──────────────┘
```

### How Traffic Interception Works

The **init container** runs on every node before the main containers start. It configures `iptables` with a `TPROXY` rule in the `mangle` table that:

1. Marks all inbound TCP packets with mark `0x1`
2. Adds a custom routing rule (`ip rule`) that sends marked packets to routing table 100
3. Routing table 100 has a local route that delivers the packet to the proxy on `0.0.0.0:8080`

The proxy retrieves the original destination IP and port via `SO_ORIGINAL_DST` (Linux socket option), making the interception completely transparent. The attacker always connects to the real node address.

---

## The Two Modules

### Module 1 — Proxy (`/proxy`)

The proxy is a Go TCP server that listens on port 8080 and handles every connection intercepted by TPROXY. For each connection it:

1. **Identifies the original destination** using `SO_ORIGINAL_DST`
2. **Reads the first bytes** from the client to aid protocol detection
3. **Classifies the protocol** — either via the local FlowTracker (which gets labels from the Classifier) or by heuristic banner parsing
4. **Routes the connection** to the correct honeypot service based on detected protocol
5. **Optionally performs MITM** for protocols like SSH, RDP, HTTP, and TLS — intercepting credentials and commands before relaying them to the honeypot
6. **Publishes structured events** to Kafka (credentials, commands, banners, raw payloads)

**MITM capabilities:**

| Protocol | What is captured |
|----------|-----------------|
| SSH | Credentials (username + password/key), commands, shell session |
| RDP | NLA/CredSSP NTLM credentials (half-TLS relay, Go↔heralding TLS incompatibility bypass) |
| HTTP/HTTPS | Full request headers, Basic Auth credentials, URI, user-agent |
| FTP | USER/PASS plaintext credentials |
| SMTP | AUTH LOGIN/PLAIN credentials (base64 decoded), EHLO, MAIL FROM/RCPT TO |
| MySQL | Login username, auth response |
| IMAP/POP3 | LOGIN command username and password |
| Telnet | Commands (after stripping IAC control sequences) |

**RDP MITM detail:** The proxy sends a synthetic X.224 Connection Confirm with `PROTOCOL_HYBRID` (NLA) to the client, which forces mstsc.exe to use a single TCP connection (no reconnect after certificate warning). After the client completes TLS (and accepts the proxy's certificate), the proxy dials heralding, replays the X.224 handshake, and relays decrypted CredSSP/NTLM data directly — bypassing Go's TLS incompatibility with heralding's Python SSL server.

**TLS certificates:** The proxy generates realistic-looking TLS certificates at startup (`TLS_USE_REALISTIC=true`), randomizing organization names, domain names, and key sizes to mimic real production services.

---

### Module 2 — Classifier (`/classifier`)

The classifier runs as a sidecar container in the same pod as the proxy. It:

1. **Captures raw packets** directly from the network interface via `AF_PACKET` (raw socket, `ETH_P_ALL`, promiscuous mode, 32 MB kernel ring buffer)
2. **Classifies each flow** using [nDPI 4.12](https://github.com/ntop/nDPI) — a compiled C library wrapped with CGO bindings (`gondpi`)
3. **Builds a flow table** keyed by 5-tuple (src IP, dst IP, src port, dst port, protocol)
4. **Serves the flow table** over a local gRPC endpoint (FlowTracker) that the proxy queries to get the nDPI application protocol label for each connection
5. **Publishes flow events** to Kafka with the detected application protocol and metadata

The combination of both modules means that every new TCP connection the proxy receives is cross-referenced against the classifier's nDPI flow table, giving accurate protocol labels even for protocols that don't have obvious banner signatures.

---

## Deployment

The system is deployed as a **DaemonSet** — one pod per node — and has been tested on **MicroK8s** but should run on any standard Kubernetes distribution (k3s, kubeadm, EKS, GKE, etc.) that supports:
- `NET_ADMIN` and `NET_RAW` capabilities
- `hostNetwork: true` or TPROXY-compatible CNI
- `iptables` available in init containers

Infrastructure is managed with **Kustomize**. The repository ships a `base` layer and a `prod` overlay:

```
k8s/
├── base/                   # Base manifests (namespace, configmap, DaemonSet, services)
│   ├── kustomization.yaml
│   ├── namespace.yaml
│   ├── configmap.yaml      # All env vars for proxy + classifier
│   ├── daemonset-proxy.yaml
│   ├── services.yaml
│   ├── honeypots.yaml      # cowrie, wordpot, heralding, galah deployments
│   ├── kafka.yaml          # Kafka (KRaft, no Zookeeper)
│   ├── logstash.yaml
│   └── filebeat.yaml
└── overlays/
    └── prod/               # Production: PVCs, image pull policy, secrets
        ├── kustomization.yaml
        └── secrets/
            └── proxy-secrets.yaml  # PUBLIC_IP, PUBLIC_PORT
```

### Quick Deploy

```bash
# Apply base (dev/lab)
kubectl apply -k k8s/base/

# Apply production overlay
kubectl apply -k k8s/overlays/prod/

# Watch rollout
kubectl rollout status daemonset/dpipot-proxy -n dpipot
```

**Note:** The network interface used by TPROXY defaults to `ens192`. Change `CLASSIFIER_INTERFACE` and the `iptables` script in `daemonset-proxy.yaml` to match your node's interface name before deploying.

---

## Configuration Reference

All configuration is done via environment variables, loaded from the `dpipot-config` ConfigMap. Below is the complete reference for both modules.

### Proxy

| Variable | Default | Description |
|----------|---------|-------------|
| `PROXY_LISTEN_ADDR` | `0.0.0.0:8080` | Address and port the proxy listens on |
| `PROXY_TIMEOUT` | `60s` | Maximum connection lifetime (supports Go duration strings: `30s`, `2m`) |
| `HONEYPOT_ROUTES` | `HTTP=wordpot-svc:80,SSH=cowrie-svc:22,...` | Comma-separated `PROTOCOL=host:port` routing table |
| `DEFAULT_ROUTE` | `dionaea-svc:4444` | Fallback honeypot for unclassified traffic |
| `MAX_CONNECTIONS` | `10000` | Global concurrent connection limit |
| `MAX_CONNECTIONS_PER_IP` | `50` | Per-source-IP concurrent connection limit |
| `MAX_PAYLOAD_BYTES` | `65536` | Maximum bytes captured per session for Kafka events |
| `LOG_LEVEL` | `info` | Log verbosity: `debug`, `info`, `warn`, `error` |
| `CLASSIFIER_ENABLED` | `false` | Enable FlowTracker integration with the Classifier sidecar |
| `SERVER_FIRST_PORTS` | `21:FTP_CONTROL,23:TELNET,...` | Ports where the server sends the first bytes (proxy waits before reading client) |
| `SERVER_FIRST_PORTS_TLS` | `993:MAIL_IMAPS,995:MAIL_POPS,...` | Same, but for TLS-wrapped server-first protocols |
| `HTTP_AUTH_PORTS` | `8161,8080,4848,...` | Ports that trigger HTTP Basic Auth challenge capture |
| `HTTP_AUTH_PORTS_TLS` | `8443,7687,5601,...` | Same, for HTTPS endpoints |
| `TLS_USE_REALISTIC` | `true` | Generate realistic TLS certificates (randomized org/domain). Set to `false` for a generic self-signed cert |
| `TLS_CERT_ORG` | _(random)_ | Override the organization name in the TLS certificate |
| `TLS_CERT_DOMAIN` | _(random)_ | Override the domain/CN in the TLS certificate |
| `HTTP_CLASSIFIER_CONFIG` | `/etc/dpipot/legitimate_paths.yaml` | Path to the HTTP whitelist file (known-good paths that skip honeypot routing) |
| `SSH_INPUT_BUF_SIZE` | `4096` | SSH input buffer size in bytes |
| `SSH_OUTPUT_BUF_SIZE` | `65536` | SSH output buffer size in bytes |

**Kafka (Proxy)**

| Variable | Default | Description |
|----------|---------|-------------|
| `KAFKA` | `true` | Enable Kafka publishing. Set to `false` to disable entirely |
| `KAFKA_BROKERS` | `kafka-svc:9092` | Comma-separated Kafka broker addresses |
| `KAFKA_TOPIC` | `dpipot.events` | Topic where honeypot events are published |

**FlowTracker (Proxy)**

| Variable | Default | Description |
|----------|---------|-------------|
| `FLOWTRACKER_PORT` | `9090` | Port of the Classifier's FlowTracker gRPC service |
| `FLOWTRACKER_TTL` | `15s` | How long to cache a flow label before re-querying |

---

### Classifier

| Variable | Default | Description |
|----------|---------|-------------|
| `CLASSIFIER_INTERFACE` | `ens192` | Network interface for AF_PACKET raw capture |
| `FLOWTRACKER_PORT` | `9090` | Port the FlowTracker gRPC server listens on |
| `FLOWTRACKER_TTL` | `60s` | Flow entry TTL in the nDPI flow table |
| `LOG_LEVEL` | `info` | Log verbosity |
| `PORT_PROTOCOL_MAP` | _(empty)_ | Override protocol for specific ports: `port:proto,...` (e.g. `8080:HTTP,2222:SSH`) |
| `SERVER_FIRST_PORTS` | _(empty)_ | Comma-separated list of ports where server sends first |

**Kafka (Classifier)**

| Variable | Default | Description |
|----------|---------|-------------|
| `KAFKA` | `true` | Enable Kafka publishing |
| `KAFKA_BROKERS` | `kafka-svc:9092` | Kafka broker addresses |
| `KAFKA_TOPIC` | `dpipot.events` | Topic for nDPI flow events |

---

## Deployment Scenarios

### Full Stack (Default)

All components running: proxy + classifier + Kafka + Logstash + Filebeat + Elasticsearch + Kibana.

```yaml
# k8s/base/configmap.yaml
KAFKA: "true"
KAFKA_BROKERS: "kafka-svc.dpipot.svc.cluster.local:9092"
CLASSIFIER_ENABLED: "true"
```

Events flow: `proxy/classifier → Kafka → Logstash → Elasticsearch → Kibana`

---

### Lightweight Mode (No Kafka / No Elasticsearch)

If you want to run the honeypot without the Kafka+Elasticsearch stack — for example in a resource-constrained lab node — simply disable Kafka. When `KAFKA=false`, neither the proxy nor the classifier attempt to connect to any broker. Events are logged to stdout only.

```yaml
# k8s/base/configmap.yaml
KAFKA: "false"
```

With `KAFKA=false` you can **remove or scale to zero** the following workloads to save resources:

| Workload | Can be removed? |
|----------|----------------|
| `kafka` Deployment | ✅ Yes |
| `logstash` Deployment | ✅ Yes |
| `filebeat` DaemonSet | ✅ Yes |
| `elasticsearch` StatefulSet | ✅ Yes |
| `kibana` Deployment | ✅ Yes |
| `proxy` container | ❌ Required |
| `classifier` container | ❌ Required (if `CLASSIFIER_ENABLED=true`) |
| Honeypot services | ❌ Required |

You can still observe events via `kubectl logs` or the included `kafka-consumer` tool (when Kafka is enabled).

---

### Classifier-Only Mode

If you want nDPI classification without the proxy's credential capture (e.g., passive monitoring):

```yaml
CLASSIFIER_ENABLED: "false"  # Proxy operates without FlowTracker
```

The proxy will use heuristic protocol detection only (banner parsing, port-based fallback).

---

### Honeypot Route Customization

`HONEYPOT_ROUTES` maps nDPI protocol labels to `host:port` targets. You can point any protocol at any service:

```yaml
HONEYPOT_ROUTES: >-
  HTTP=wordpot-svc:80,
  TLS=wordpot-svc:443,
  SSH=cowrie-svc:22,
  TELNET=cowrie-svc:23,
  FTP=heralding:21,
  SMTP=heralding:25,
  MAIL_SMTP=heralding:25,
  POP=heralding:110,
  IMAP=heralding:143,
  MySQL=heralding:3306,
  RDP=heralding:3389,
  VNC=heralding:5900,
  HTTP_AUTH=heralding:80
```

Any protocol not listed falls back to `DEFAULT_ROUTE`.

---

## Event Schema

Every event published to Kafka has the following structure:

```json
{
  "flow_id":     "550e8400-e29b-41d4-a716-446655440000",
  "tuple_id":    "192.168.1.10:54321->10.0.0.5:22",
  "timestamp":   "2024-01-15T14:32:01.123Z",
  "src_ip":      "192.168.1.10",
  "src_port":    54321,
  "dst_ip":      "10.0.0.5",
  "dst_port":    22,
  "ndpi_proto":  "SSH",
  "ndpi_app":    "SSH",
  "attack_type": "ssh_password",
  "honeypot":    "cowrie-svc:22",
  "instance":    "proxy",
  "duration_ms": 4821
}
```

Credential events include additional fields: `username`, `password`, `command`, `banner`, `raw_payload`.

---

## Supported Protocols

| Protocol | nDPI Label | Honeypot | MITM |
|----------|-----------|----------|------|
| SSH | `SSH` | cowrie | ✅ credentials + commands |
| HTTP | `HTTP` | wordpot / galah | ✅ headers + auth |
| HTTPS/TLS | `TLS` | wordpot | ✅ certificate + HTTPS |
| FTP | `FTP_CONTROL` | heralding | ✅ USER/PASS |
| SMTP | `MAIL_SMTP`, `SMTP` | heralding | ✅ AUTH credentials |
| IMAP | `MAIL_IMAP`, `IMAP` | heralding | ✅ LOGIN |
| POP3 | `MAIL_POP`, `POP3` | heralding | ✅ USER/PASS |
| MySQL | `MySQL` | heralding | ✅ login |
| RDP | `RDP` | heralding | ✅ NLA/NTLM (half-TLS) |
| Telnet | `TELNET` | cowrie | ✅ commands (IAC stripped) |
| VNC | `VNC` | heralding | raw relay |
| SMB | `SMB` | default | raw relay |
| Everything else | — | default honeypot | raw relay |

---

## Requirements

- Kubernetes ≥ 1.25 (tested on **MicroK8s 1.29**, expected to work on k3s, kubeadm, EKS, GKE, AKS)
- Nodes running Linux with `iptables` support (TPROXY target in `mangle` table)
- Kustomize ≥ 5.0 (`kubectl kustomize` or standalone `kustomize` binary)
- Container registry access to `ghcr.io/spawnzao` (or rebuild images locally)
- `NET_ADMIN` + `NET_RAW` capabilities allowed by the cluster's PSA/PSP policy

---

## Build

Images are built automatically by GitHub Actions on every push to `main` and pushed to `ghcr.io`.

To build locally:

```bash
# Proxy
docker build -t dpipot-proxy:local ./proxy

# Classifier (compiles nDPI 4.12 from source — takes ~5 min)
docker build -t dpipot-classifier:local ./classifier
```

Both images use multi-stage builds. The final runtime image is based on `debian:bookworm-slim` with only the required shared libraries (`librdkafka1`, `libpcap0.8`, `libjson-c5`, `libndpi.so`).

---

## Repository Layout

```
dpipot-ng/
├── proxy/                  # TCP honeypot proxy (Go)
│   ├── cmd/proxy/          # main.go
│   └── internal/
│       ├── config/         # Environment variable loader
│       ├── mitm/           # MITM handlers: SSH, RDP, HTTP, TLS, parsers
│       ├── proxy/          # TCP server, connection handler
│       ├── router/         # Protocol→honeypot routing table
│       ├── flowtracker/    # gRPC client for Classifier
│       ├── httpclassifier/ # HTTP path whitelist
│       └── kafka/          # Kafka producer
├── classifier/             # AF_PACKET + nDPI classifier (Go + CGO)
│   ├── cmd/                # main.go
│   └── internal/
│       ├── capture/        # AF_PACKET raw socket implementation
│       ├── ndpi/           # nDPI 4.12 CGO bindings (gondpi)
│       ├── flow/           # Flow table management
│       ├── flowtracker/    # gRPC server (serves proxy)
│       └── kafka/          # Kafka producer
├── k8s/                    # Kubernetes manifests (Kustomize)
│   ├── base/               # Base resources
│   └── overlays/prod/      # Production overlay (PVCs, secrets)
└── tools/
    └── kafka-consumer/     # CLI tool to tail dpipot.events from Kafka
```
