# DPIpot-NG

**A Kubernetes-native honeypot orchestrator that uses Deep Packet Inspection to intelligently classify traffic at the network layer and steer it to diverse honeypot backends based on flexible protocol rules, with transparent MITM for capturing credentials, commands, and full session activity.**

DPIpot-NG intercepts all TCP connections arriving at a node — without touching firewall rules on the attacker's path — classifies each flow at Layer 2 using nDPI deep packet inspection, routes the connection to the appropriate honeypot service, and emits structured events to Kafka for ingestion into Elasticsearch/Kibana. The system operates completely transparently: attackers connect to the real node IP and port, unaware they are being redirected.

---

## Architecture

```
                        ┌────────────────────────────────────────────────┐
                        │             Kubernetes Node (DaemonSet)        │
                        │                                                │
  Internet              │  ┌──────────────────────────────────────────┐  │
  TCP :22 / :80         │  │  init-container: iptables TPROXY setup   │  │
  :443 / :3389 / ...    │  └──────────────────────┬───────────────────┘  │
         │              │                         │ marks TCP pkts 0x1   │
         │              │  ┌──────────────────┐   │                      │
         │              │  │   Classifier     │   │                      │
         │              │  │  (Module 1)      │   │                      │
         │              │  │                  │   │                      │
         │              │  │  AF_PACKET       │   │                      │
         │              │  │  Layer 2 capture │   │                      │
         │              │  │  nDPI 4.12       │   │                      │
         │              │  │  FlowTracker     │   │                      │
         │              │  └────────┬─────────┘   │                      │
         │              │           │ flow labels  │                      │
         ▼              │           ▼              ▼                      │
  ┌──────────────┐      │  ┌──────────────────────────┐                  │
  │  iptables    │      │  │         Proxy            │                  │
  │  TPROXY rule │─────▶│  │        (Module 2)        │                  │
  │  (mangle)    │      │  │         :8080            │                  │
  └──────────────┘      │  └────────────┬─────────────┘                  │
                        │               │ route by nDPI label            │
                        │               ├──── SSH  ──────▶ cowrie:22     │
                        │               ├──── HTTP ──────▶ wordpot:80    │
                        │               ├──── FTP/SMTP ──▶ heralding:21  │
                        │               ├──── MySQL ─────▶ heralding:3306│
                        │               ├──── RDP  ──────▶ heralding:3389│
                        │               └──── *  ────────▶ default       │
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
3. Routing table 100 delivers the marked packets to the proxy on `0.0.0.0:8080`

The proxy retrieves the original destination IP and port via `SO_ORIGINAL_DST` (Linux socket option), making the interception completely transparent. The attacker always connects to the real node address.

---

## The Two Modules

### Module 1 — Classifier (`/classifier`)

The classifier is responsible for **identifying what protocol each connection is using**, at the network layer, before the proxy ever reads application data. It runs as a sidecar container in the same pod as the proxy.

**How it works:**

1. Opens a raw `AF_PACKET` socket on the configured network interface (`ETH_P_ALL`, promiscuous mode, 32 MB kernel ring buffer) — this captures all frames at **Layer 2**, including packets that have not yet reached any userspace listener
2. Feeds the raw packet stream to **nDPI 4.12** (a C library compiled from source, wrapped with CGO bindings) which performs stateful deep packet inspection across the full flow lifecycle
3. Maintains a **flow table** keyed by 5-tuple (src IP, dst IP, src port, dst port, protocol), updating the nDPI classification for each packet
4. Exposes the flow table via a local **gRPC endpoint** (FlowTracker) on port 9090 — the proxy queries this endpoint for every new connection to get the nDPI application protocol label
5. Publishes classified flow events to Kafka

Because AF_PACKET operates at Layer 2, the classifier sees every packet on the wire — including the TCP SYN and the first data segments — and can classify a flow to a specific application protocol (e.g., `SSH`, `RDP`, `MySQL`) with high confidence, even without inspecting the payload inside the proxy.

---

### Module 2 — Proxy (`/proxy`)

The proxy is a Go TCP server that accepts every connection redirected by TPROXY and uses the **Classifier's nDPI labels** to decide where to send each connection. For each incoming connection it:

1. **Identifies the original destination** using `SO_ORIGINAL_DST`
2. **Reads the first bytes** from the client
3. **Queries the Classifier** (via FlowTracker gRPC) to get the nDPI application protocol label for that 5-tuple
4. **Looks up `HONEYPOT_ROUTES`** — the env var that maps protocol labels to honeypot addresses — and forwards the connection to the correct honeypot
5. **Performs MITM** where applicable — intercepting credentials and commands in clear text before relaying them to the honeypot
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

**RDP MITM detail:** The proxy sends a synthetic X.224 Connection Confirm with `PROTOCOL_HYBRID` (NLA) to the client, forcing mstsc.exe to keep the certificate display and CredSSP/NTLM auth on a single TCP connection (no reconnect). After the client completes TLS, the proxy dials heralding, replays the X.224 handshake, and relays decrypted CredSSP/NTLM data raw — bypassing Go's TLS incompatibility with heralding's Python SSL server.

**TLS termination for encrypted protocols:** For all encrypted protocols except SSH and RDP, the proxy terminates TLS with the attacker using its own generated certificate, then forwards the decrypted traffic to the honeypot in plain text. This means, for example, that an HTTPS connection becomes HTTP on the honeypot side. The honeypots included in this repository have already been configured to accept plain-text connections on their respective ports, so no additional honeypot-side changes are needed.

**TLS certificates:** The proxy generates realistic-looking TLS certificates at startup (`TLS_USE_REALISTIC=true`), randomizing organization names, domain names, and key sizes to mimic real production services.

---

## Deployment

The system is deployed as a **DaemonSet** — one pod per node — and has been tested on **MicroK8s 1.29**, but should run on any standard Kubernetes distribution (k3s, kubeadm, EKS, GKE, AKS, etc.) that supports:
- `NET_ADMIN` and `NET_RAW` capabilities
- `hostNetwork: true` or a TPROXY-compatible CNI
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
            ├── proxy-secrets.yaml.example       ← copy → proxy-secrets.yaml
            ├── logstash-secrets.yaml.example    ← copy → logstash-secrets.yaml
            └── galah-secrets.yaml.example       ← copy → galah-secrets.yaml
```

### Configuring Secrets Before Deploying

The `secrets/` directory contains three `.example` files. You must copy and fill them before applying the production overlay:

```bash
# 1. Proxy secrets — public IP and port exposed to attackers
cp k8s/overlays/prod/secrets/proxy-secrets.yaml.example \
   k8s/overlays/prod/secrets/proxy-secrets.yaml
# Edit: set PUBLIC_IP and PUBLIC_PORT to your node's real address

# 2. Logstash → Elasticsearch credentials
cp k8s/overlays/prod/secrets/logstash-secrets.yaml.example \
   k8s/overlays/prod/secrets/logstash-secrets.yaml
# Edit: ELASTICSEARCH_HOST, ELASTICSEARCH_USER, ELASTIC_PASSWORD, ca.crt (base64)

# 3. Galah (LLM-powered HTTP honeypot) API key
cp k8s/overlays/prod/secrets/galah-secrets.yaml.example \
   k8s/overlays/prod/secrets/galah-secrets.yaml
# Edit: api_key
```

After creating the files, **add them as resources in `k8s/overlays/prod/kustomization.yaml`** so Kustomize picks them up:

```yaml
# k8s/overlays/prod/kustomization.yaml
resources:
  - ../../base
  - kafka-pvc.yaml
  - pvc-cache.yaml
  - secrets/proxy-secrets.yaml        # ← add
  - secrets/logstash-secrets.yaml     # ← add
  - secrets/galah-secrets.yaml        # ← add
```

> The `.example` files are committed to the repository as templates. The real secret files (`proxy-secrets.yaml`, `logstash-secrets.yaml`, `galah-secrets.yaml`) are listed in `.gitignore` and must never be committed.

### Quick Deploy

```bash
# Apply base (dev/lab — no secrets required)
kubectl apply -k k8s/base/

# Apply production overlay (secrets must be configured first — see above)
kubectl apply -k k8s/overlays/prod/

# Watch rollout
kubectl rollout status daemonset/dpipot-proxy -n dpipot
```

**Note:** The network interface used by TPROXY defaults to `ens192`. Change `CLASSIFIER_INTERFACE` and the `iptables` init script in `daemonset-proxy.yaml` to match your node's interface name before deploying.

---

## Configuration Reference

All configuration is done via environment variables, loaded from the `dpipot-config` ConfigMap (`k8s/base/configmap.yaml`). Below is the complete reference for both modules.

### Classifier

| Variable | Default | Description |
|----------|---------|-------------|
| `CLASSIFIER_INTERFACE` | `ens192` | Network interface for AF_PACKET raw capture |
| `FLOWTRACKER_PORT` | `9090` | Port the FlowTracker gRPC server listens on |
| `FLOWTRACKER_TTL` | `60s` | Flow entry TTL in the nDPI flow table |
| `LOG_LEVEL` | `info` | Log verbosity: `debug`, `info`, `warn`, `error` |
| `PORT_PROTOCOL_MAP` | _(empty)_ | Override protocol for specific ports: `port:proto,...` (e.g. `8080:HTTP,2222:SSH`) |
| `SERVER_FIRST_PORTS` | _(empty)_ | Comma-separated list of ports where the server sends the first bytes |

**Kafka (Classifier)**

| Variable | Default | Description |
|----------|---------|-------------|
| `KAFKA` | `true` | Enable Kafka publishing. Set to `false` to disable entirely |
| `KAFKA_BROKERS` | `kafka-svc:9092` | Comma-separated Kafka broker addresses |
| `KAFKA_TOPIC` | `dpipot.events` | Topic for nDPI flow events |

---

### Proxy

| Variable | Default | Description |
|----------|---------|-------------|
| `PROXY_LISTEN_ADDR` | `0.0.0.0:8080` | Address and port the proxy listens on |
| `PROXY_TIMEOUT` | `60s` | Maximum connection lifetime (supports Go duration strings: `30s`, `2m`) |
| `HONEYPOT_ROUTES` | `HTTP=wordpot-svc:80,SSH=cowrie-svc:22,...` | Comma-separated `PROTOCOL=host:port` routing table (see [Honeypot Route Customization](#honeypot-route-customization)) |
| `DEFAULT_ROUTE` | `dionaea-svc:4444` | Fallback honeypot for unclassified traffic |
| `CLASSIFIER_ENABLED` | `false` | Enable FlowTracker integration with the Classifier sidecar |
| `MAX_CONNECTIONS` | `10000` | Global concurrent connection limit |
| `MAX_CONNECTIONS_PER_IP` | `50` | Per-source-IP concurrent connection limit |
| `MAX_PAYLOAD_BYTES` | `65536` | Maximum bytes captured per session for Kafka events |
| `LOG_LEVEL` | `info` | Log verbosity: `debug`, `info`, `warn`, `error` |
| `SERVER_FIRST_PORTS` | `21:FTP_CONTROL,23:TELNET,...` | Ports where the server sends first (proxy waits before reading client data) |
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

**FlowTracker (Proxy → Classifier)**

| Variable | Default | Description |
|----------|---------|-------------|
| `FLOWTRACKER_PORT` | `9090` | Port of the Classifier's FlowTracker gRPC service |
| `FLOWTRACKER_TTL` | `15s` | How long the proxy caches a flow label before re-querying |

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

To run the honeypot without the Kafka+Elasticsearch stack — for example on a resource-constrained lab node — simply disable Kafka. When `KAFKA=false`, neither the proxy nor the classifier attempt to connect to any broker. Events are logged to stdout only.

```yaml
# k8s/base/configmap.yaml
KAFKA: "false"
```

With `KAFKA=false` you can **remove or scale to zero** the following workloads, freeing significant memory and CPU:

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

You can still inspect events in real time via `kubectl logs -f` on the proxy or classifier containers.

---

### Honeypot Route Customization

`HONEYPOT_ROUTES` maps nDPI protocol labels (as returned by the Classifier) to `host:port` honeypot targets. Every protocol can point to a different service, and you can replace any honeypot with your own:

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

Any protocol label not present in `HONEYPOT_ROUTES` is forwarded to `DEFAULT_ROUTE`. Protocol labels come directly from nDPI — you can use `PORT_PROTOCOL_MAP` in the Classifier to override the label for specific ports if needed.

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

| Protocol | nDPI Label | Default Honeypot | MITM |
|----------|-----------|-----------------|------|
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
| Everything else | — | `DEFAULT_ROUTE` | raw relay |

---

## Requirements

- Kubernetes ≥ 1.25 (tested on **MicroK8s 1.29**, expected to work on k3s, kubeadm, EKS, GKE, AKS)
- Nodes running Linux with `iptables` support (TPROXY target in `mangle` table)
- Kustomize ≥ 5.0 (`kubectl kustomize` or standalone `kustomize` binary)
- Container registry access to `ghcr.io/spawnzao` (or rebuild images locally)
- `NET_ADMIN` + `NET_RAW` capabilities allowed by the cluster's admission policy

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
├── classifier/             # AF_PACKET + nDPI classifier (Go + CGO)  [Module 1]
│   ├── cmd/                # main.go
│   └── internal/
│       ├── capture/        # AF_PACKET raw socket implementation
│       ├── ndpi/           # nDPI 4.12 CGO bindings (gondpi)
│       ├── flow/           # Flow table management
│       ├── flowtracker/    # gRPC server (serves the proxy)
│       └── kafka/          # Kafka producer
├── proxy/                  # TCP honeypot proxy (Go)                  [Module 2]
│   ├── cmd/proxy/          # main.go
│   └── internal/
│       ├── config/         # Environment variable loader
│       ├── mitm/           # MITM handlers: SSH, RDP, HTTP, TLS, parsers
│       ├── proxy/          # TCP server, connection handler
│       ├── router/         # Protocol→honeypot routing table
│       ├── flowtracker/    # gRPC client for Classifier
│       ├── httpclassifier/ # HTTP path whitelist
│       └── kafka/          # Kafka producer
└── k8s/                    # Kubernetes manifests (Kustomize)
    ├── base/               # Base resources
    └── overlays/prod/      # Production overlay (PVCs, image pull policy, secrets)
        └── secrets/        # .example files — copy and fill before deploying
```
