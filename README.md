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

Infrastructure is managed with **Helm**. The chart lives in `k8s/chart/` and ships four deployment profiles as values override files:

```
k8s/
├── chart/
│   ├── Chart.yaml
│   ├── values.yaml           # Defaults: all components enabled, tag latest
│   ├── values-prod.yaml      # Pinned tags, kafka PVC 100Gi, higher requests
│   ├── values-sensor.yaml    # kafka=true, filebeat=false
│   ├── values-light.yaml     # kafka=false, filebeat=false (no pipeline stack)
│   ├── values-debug.yaml     # kafka=false, filebeat=true
│   └── templates/
│       ├── configmap.yaml    # dpipot-config — all env vars for proxy + classifier
│       ├── daemonset-proxy.yaml
│       ├── kafka.yaml        # Kafka (KRaft) + optional PVC
│       ├── logstash.yaml     # Only deployed when kafka or filebeat is enabled
│       ├── filebeat.yaml
│       ├── cowrie.yaml
│       ├── wordpot.yaml
│       ├── heralding.yaml
│       ├── galah.yaml
│       ├── services.yaml
│       └── network-policy.yaml
└── secrets/
    ├── logstash-secrets.yaml.example    ← copy → logstash-secrets.yaml
    └── galah-secrets.yaml.example       ← copy → galah-secrets.yaml
```

### Configuring Secrets Before Deploying

`k8s/secrets/` contains two `.example` files. Copy and fill them before installing the chart:

```bash
# 1. Logstash → Elasticsearch credentials
cp k8s/secrets/logstash-secrets.yaml.example k8s/secrets/logstash-secrets.yaml
# Edit: ELASTICSEARCH_HOST, ELASTICSEARCH_USER, ELASTIC_PASSWORD, ca.crt (base64)

# 2. Galah (LLM-powered HTTP honeypot) API key
cp k8s/secrets/galah-secrets.yaml.example k8s/secrets/galah-secrets.yaml
# Edit: api_key
```

Then apply them to the cluster:

```bash
kubectl apply -f k8s/secrets/logstash-secrets.yaml
kubectl apply -f k8s/secrets/galah-secrets.yaml
```

`elastic-certs` (the Elasticsearch CA cert) is already embedded as a second YAML document inside `logstash-secrets.yaml` — the `kubectl apply` above creates both secrets at once. The only secret that requires manual creation is `ghcr-secret` (GitHub Container Registry pull secret), which is cluster-specific.

> The `.example` files are committed to the repository as templates. The real secret files are listed in `k8s/secrets/.gitignore` and must never be committed.

### Quick Deploy

```bash
# Production (pinned tags, persistent Kafka, higher resource requests)
microk8s helm upgrade --install dpipot k8s/chart/ \
  -f k8s/chart/values-prod.yaml \
  --namespace dpipot --create-namespace

# Watch rollout
kubectl rollout status daemonset/dpipot-proxy -n dpipot
kubectl get pods -n dpipot
```

**Note:** The network interface used by TPROXY defaults to `ens192`. Change `CLASSIFIER_INTERFACE` in `values.yaml` (or override per profile) to match your node's interface name before deploying.

### Per-Node Overrides (required for multi-node deployments)

Each physical node in the cluster likely has different hardware and a different network interface. **Do not adjust `values-prod.yaml` for node-specific settings** — it is shared across all nodes. Instead, create a local override file on each node and never commit it:

```bash
# On each node, create k8s/chart/values-<hostname>.yaml
# This file is intentionally local — it is NOT committed to the repository.
```

```yaml
# Example: k8s/chart/values-vps.yaml (node with 4 cores / 8 GB RAM / 60 GB disk)
network:
  interface: "ens18"          # use `ip link show` to find your interface

kafka:
  persistence:
    size: "10Gi"              # must fit within the node's available disk

resources:
  proxy:
    requests: { cpu: 200m, memory: 256Mi }
    limits:   { cpu: 1000m, memory: 512Mi }
  kafka:
    requests: { cpu: 200m, memory: 512Mi }
    limits:   { cpu: 1000m, memory: 1Gi }
  # ... other components sized to match actual node capacity
```

Then always pass both files when deploying on that node:

```bash
microk8s helm upgrade --install dpipot k8s/chart/ \
  -f k8s/chart/values-prod.yaml \
  -f k8s/chart/values-<hostname>.yaml \
  --namespace dpipot --create-namespace
```

Settings you almost always need to override per node:

| Setting | Why it varies | How to find the right value |
|---|---|---|
| `network.interface` | Interface name differs by hypervisor/OS | `ip link show` |
| `kafka.persistence.size` | Must fit in available disk | `df -h /` |
| `resources.*` | requests/limits must fit in actual RAM/CPU | `nproc`, `free -h` |

Deploying `values-prod.yaml` alone on an undersized node will cause `kafka.persistence.size` to exceed available disk and `resources.limits` to exceed physical RAM — both fail silently until Kafka crashes or the node runs OOM.

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

The chart ships four profiles selectable via `-f values-<profile>.yaml`. Each profile is a minimal override on top of `values.yaml` — only differences are listed.

| Profile | Kafka | Filebeat | Logstash | Image tags | Kafka PVC |
|---------|-------|----------|----------|------------|-----------|
| _(default)_ | ✅ | ✅ | ✅ | `latest` | emptyDir |
| `prod` | ✅ | ✅ | ✅ | `release-0.3` | 100Gi |
| `sensor` | ✅ | ❌ | kafka only | `latest` | emptyDir |
| `light` | ❌ | ❌ | ❌ | `latest` | — |
| `debug` | ❌ | ✅ | filebeat only | `latest` | — |

**Logstash is only deployed when at least one pipeline is active** (kafka or filebeat enabled). With both disabled (`light`), the entire Kafka+Logstash+Filebeat stack is absent, freeing significant CPU and memory.

```bash
# Sensor node (Kafka + honeypots, no Filebeat)
microk8s helm upgrade --install dpipot k8s/chart/ -f k8s/chart/values-sensor.yaml

# Light node (honeypots only, no pipeline stack)
microk8s helm upgrade --install dpipot k8s/chart/ -f k8s/chart/values-light.yaml

# Debug (Filebeat only, inspect honeypot container logs in Elasticsearch)
microk8s helm upgrade --install dpipot k8s/chart/ -f k8s/chart/values-debug.yaml
```

- Events flow: `proxy/classifier → Kafka → Logstash → Elasticsearch` (when kafka enabled)
- Honeypot logs: `container stdout → Filebeat → Logstash → Elasticsearch` (when filebeat enabled)

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

## Guides

Step-by-step deployment guides for specific platforms and configurations:

| Guide | Description | Language |
|---|---|---|
| [Rocky Linux 9 — Full Setup](docs/en/rocky-linux-setup.md) | k3s, SELinux, networking, iptables TPROXY, secrets, Helm install | English |
| [Rocky Linux 9 — Full Setup](docs/pt-br/rocky-linux-setup.md) | k3s, SELinux, networking, iptables TPROXY, secrets, Helm install | Português |

---

## Requirements

- Kubernetes ≥ 1.25 (tested on **MicroK8s 1.29**, expected to work on k3s, kubeadm, EKS, GKE, AKS)
- Nodes running Linux with `iptables` support (TPROXY target in `mangle` table)
- Helm ≥ 3.0
- Container registry access to `ghcr.io/spawnzao` (or rebuild images locally)
- `NET_ADMIN` + `NET_RAW` capabilities allowed by the cluster's admission policy

> **Local testing:** The proxy requires `IP_TRANSPARENT` socket option, which needs `NET_ADMIN` and is blocked in nested container environments (LXC/Docker-in-Docker). Test in a real VM or a bare-metal node with `--privileged` (Docker) or equivalent.

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
└── k8s/                    # Kubernetes manifests (Helm)
    ├── chart/              # Helm chart (Chart.yaml, values*.yaml, templates/)
    └── secrets/            # .example files — copy and fill before helm install
```
