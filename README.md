# DPIpot-NG

**A Kubernetes-native honeypot orchestrator that uses Deep Packet Inspection to intelligently classify traffic at the network layer and steer it to diverse honeypot backends based on flexible protocol rules, with transparent MITM for capturing credentials, commands, and full session activity.**

DPIpot-NG intercepts all TCP connections arriving at a node — without touching firewall rules on the attacker's path — classifies each flow at Layer 2 using nDPI deep packet inspection, routes the connection to the appropriate honeypot service, and emits structured events to Kafka for ingestion into Elasticsearch/Kibana. The system operates completely transparently: attackers connect to the real node IP and port, unaware they are being redirected.

> **Branch status:**
> - `main` (v0.3 — stable): two-container design — `dpipot-proxy` + `dpipot-classifier` sidecar communicating via FlowTracker gRPC
> - `dev` (current): **unified binary** — AF_PACKET capture and TPROXY proxy run in the same process, sharing an in-memory flow table (no IPC)

---

## Architecture

### dev branch — Unified binary (`dpipot`)

```
                        ┌────────────────────────────────────────────────────┐
                        │              Kubernetes Node (DaemonSet)           │
                        │                                                    │
  Internet              │  ┌────────────────────────────────────────────┐    │
  TCP :22 / :80         │  │  init-container: iptables TPROXY setup     │    │
  :443 / :3389 / ...    │  └──────────────────────┬─────────────────────┘    │
         │              │                         │ marks TCP pkts 0x1       │
         │              │  ┌──────────────────────▼─────────────────────┐    │
         │              │  │              dpipot (single binary)         │    │
         │              │  │                                             │    │
         │              │  │  ┌───────────────────┐                     │    │
         │              │  │  │  AF_PACKET capture │  Layer 2, all pkts │    │
         │              │  │  │  nDPI 4.12 (CGO)  │  stateful DPI      │    │
         │              │  │  │  In-memory table  │  keyed by 5-tuple  │    │
         │              │  │  └─────────┬─────────┘                     │    │
         │              │  │            │ direct lookup (~100 ns)        │    │
         ▼              │  │  ┌─────────▼─────────┐                     │    │
  ┌──────────────┐      │  │  │  TPROXY listener  │ :8080               │    │
  │  iptables    │─────▶│  │  │  (Go TCP server)  │                     │    │
  │  TPROXY rule │      │  │  └─────────┬─────────┘                     │    │
  └──────────────┘      │  │            │ route by nDPI label            │    │
                        │  │            ├──── SSH  ──────▶ cowrie:22     │    │
                        │  │            ├──── HTTP ──────▶ wordpot:80    │    │
                        │  │            ├──── FTP/SMTP ──▶ heralding:21  │    │
                        │  │            ├──── MySQL ─────▶ heralding:3306│    │
                        │  │            ├──── RDP  ──────▶ heralding:3389│    │
                        │  │            └──── *  ────────▶ default       │    │
                        │  └─────────────────────────────────────────────┘    │
                        └─────────────────────┬──────────────────────────────┘
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

## The dpipot Binary

The `dev` branch merges the former classifier and proxy into a **single Go binary** that runs both responsibilities in the same process.

**AF_PACKET goroutine** — opens a raw `AF_PACKET` socket on the configured network interface (`ETH_P_ALL`, promiscuous mode) and feeds every frame to **nDPI 4.12** (C library compiled from source, wrapped with CGO). nDPI performs stateful deep packet inspection across the full flow lifecycle and writes the result to an **in-memory flow table** keyed by 5-tuple (src IP, dst IP, src port, dst port, protocol).

**TPROXY listener** — a Go TCP server that accepts every connection redirected by TPROXY. For each connection it:

1. **Identifies the original destination** using `SO_ORIGINAL_DST`
2. **Reads the first bytes** from the client
3. **Looks up the flow table directly** (shared memory, ~100 ns — no TCP round-trip) to get the nDPI application protocol label
4. **Routes to the correct honeypot** via `HONEYPOT_ROUTES`
5. **Performs MITM** where applicable — intercepting credentials and commands before relaying them
6. **Publishes structured events** to Kafka

**Why one process?** The former design used a FlowTracker gRPC service (TCP round-trip, ~1–5 ms per lookup). The unified binary eliminates that IPC entirely: both goroutines share a `*flow.Table` directly. Classification latency drops to ~100 ns, and there is no separate container to crash independently.

**MITM capabilities:**

| Protocol | What is captured |
|----------|-----------------|
| SSH | Credentials (username + password/key), commands, shell session |
| RDP | NLA/CredSSP NTLM credentials (half-TLS relay) |
| HTTP/HTTPS | Full request headers, Basic Auth credentials, URI, user-agent |
| FTP | USER/PASS plaintext credentials |
| SMTP | AUTH LOGIN/PLAIN credentials (base64 decoded), EHLO, MAIL FROM/RCPT TO |
| MySQL | Login username, auth response |
| IMAP/POP3 | LOGIN command username and password |
| Telnet | Commands (after stripping IAC control sequences) |

**TLS termination:** For all encrypted protocols except SSH and RDP, the binary terminates TLS with the attacker using its own generated certificate, then forwards decrypted traffic to the honeypot in plain text.

**TLS certificates:** Generated at startup with `TLS_USE_REALISTIC=true`, randomizing organization names, domain names, and key sizes to mimic real production services.

---

## Deployment

The system is deployed as a **DaemonSet** — one pod per node — and has been tested on **MicroK8s 1.29** and **k3s**, but should run on any standard Kubernetes distribution that supports:
- `NET_ADMIN` and `NET_RAW` capabilities
- `hostNetwork: true` or a TPROXY-compatible CNI
- `iptables` available in init containers

Infrastructure is managed with **Helm**. The chart lives in `k8s/chart/`:

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
│       ├── configmap.yaml    # dpipot-config — all env vars
│       ├── daemonset-proxy.yaml
│       ├── kafka.yaml        # Kafka (KRaft) + optional PVC
│       ├── logstash.yaml
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

### Quick Deploy

```bash
# Production (pinned tags, persistent Kafka, higher resource requests)
helm upgrade --install dpipot k8s/chart/ \
  -f k8s/chart/values-prod.yaml \
  --namespace dpipot --create-namespace

# Watch rollout
kubectl rollout status daemonset/dpipot-proxy -n dpipot
kubectl get pods -n dpipot
```

**Note:** The network interface used by TPROXY defaults to `ens192`. Change `CLASSIFIER_INTERFACE` in `values.yaml` (or override per profile) to match your node's interface name before deploying.

### Per-Node Values File (required for multi-node deployments)

Each node must have its own local values file named `k8s/chart/values-$(hostname -s).yaml`. This file is **intentionally not committed to the repository** — `k8s/chart/.gitignore` excludes all `values-*.yaml` except the named profiles (`prod`, `sensor`, `light`, `debug`).

**Creating the file on a new node:**

```bash
hostname -s   # e.g. "my-node"

cat > k8s/chart/values-my-node.yaml << 'EOF'
network:
  interface: "ens18"          # use `ip link show` to find your interface name

kafka:
  persistence:
    enabled: true
    size: "10Gi"              # must fit within available disk: df -h /
    storageClass: "local-path"  # k3s default; use "microk8s-hostpath" for MicroK8s

resources:
  dpipot:
    requests: { cpu: 500m, memory: 256Mi }
    limits:   { cpu: 2000m, memory: 1Gi }
  kafka:
    requests: { cpu: 200m, memory: 512Mi }
    limits:   { cpu: 1000m, memory: 1Gi }
  # size all components to match actual node capacity (nproc, free -h)
EOF
```

Settings you almost always need to override per node:

| Setting | Why it varies | How to find the right value |
|---|---|---|
| `network.interface` | Interface name differs by hypervisor/OS | `ip link show` |
| `kafka.persistence.size` | Must fit in available disk | `df -h /` |
| `kafka.persistence.storageClass` | Differs between k3s (`local-path`) and MicroK8s (`microk8s-hostpath`) | `kubectl get storageclass` |
| `resources.*` | requests/limits must fit in actual RAM/CPU | `nproc`, `free -h` |

**Manual deploy:**

```bash
# MicroK8s
microk8s helm upgrade --install dpipot k8s/chart/ \
  -f k8s/chart/values-$(hostname -s).yaml \
  --namespace dpipot --create-namespace

# k3s
helm upgrade --install dpipot k8s/chart/ \
  -f k8s/chart/values-$(hostname -s).yaml \
  --namespace dpipot --create-namespace
```

### CI/CD (GitHub Actions)

The repository includes a self-hosted GitHub Actions runner workflow that builds and deploys automatically:

- **`main` branch** → builds `dpipot-proxy` + `dpipot-classifier` images → deploys automatically via `workflow_run`
- **`dev` branch** → builds unified `dpipot` image → deploys automatically (triggered from the build job via `gh workflow run`)

**Orchestrator detection:** the workflow detects whether the host runs k3s or MicroK8s and selects the right commands automatically.

**Values file resolution:** the workflow runs `hostname -s` and looks for `k8s/chart/values-$(hostname -s).yaml`. If the file exists it is used; if not, it falls back to `values.yaml` and prints a warning in the CI log.

---

## Configuration Reference

All configuration is done via environment variables, loaded from the `dpipot-config` ConfigMap.

### dpipot (unified binary — dev branch)

| Variable | Default | Description |
|----------|---------|-------------|
| `PROXY_LISTEN_ADDR` | `0.0.0.0:8080` | Address and port the TPROXY listener binds to |
| `PROXY_TIMEOUT` | `60s` | Maximum connection lifetime |
| `CLASSIFIER_INTERFACE` | `ens192` | Network interface for AF_PACKET raw capture |
| `FLOWTRACKER_TTL` | `60s` | Flow entry TTL in the in-memory nDPI flow table |
| `HONEYPOT_ROUTES` | `HTTP=wordpot-svc:80,SSH=cowrie-svc:22,...` | Comma-separated `PROTOCOL=host:port` routing table |
| `DEFAULT_ROUTE` | `heralding:80` | Fallback honeypot for unclassified traffic |
| `MAX_CONNECTIONS` | `10000` | Global concurrent connection limit |
| `MAX_CONNECTIONS_PER_IP` | `50` | Per-source-IP concurrent connection limit |
| `MAX_PAYLOAD_BYTES` | `65536` | Maximum bytes captured per session for Kafka events |
| `LOG_LEVEL` | `info` | Log verbosity: `debug`, `info`, `warn`, `error` |
| `SERVER_FIRST_PORTS` | `21:FTP_CONTROL,23:TELNET,...` | Ports where server sends first (proxy waits before reading client data) |
| `SERVER_FIRST_PORTS_TLS` | `993:MAIL_IMAPS,995:MAIL_POPS,...` | Same, for TLS-wrapped server-first protocols |
| `HTTP_AUTH_PORTS` | `8161,8080,...` | Ports that trigger HTTP Basic Auth challenge capture |
| `HTTP_AUTH_PORTS_TLS` | `8443,7687,...` | Same, for HTTPS endpoints |
| `TLS_USE_REALISTIC` | `true` | Generate realistic TLS certificates (randomized org/domain) |
| `HTTP_CLASSIFIER_CONFIG` | `/etc/dpipot/legitimate_paths.yaml` | Path to the HTTP whitelist file |
| `PORT_PROTOCOL_MAP` | _(empty)_ | Override protocol for specific ports: `port:proto,...` |
| `SSH_INPUT_BUF_SIZE` | `4096` | SSH input buffer size in bytes |
| `SSH_OUTPUT_BUF_SIZE` | `65536` | SSH output buffer size in bytes |

**Kafka**

| Variable | Default | Description |
|----------|---------|-------------|
| `KAFKA` | `true` | Enable Kafka publishing |
| `KAFKA_BROKERS` | `kafka-svc:9092` | Comma-separated Kafka broker addresses |
| `KAFKA_TOPIC` | `dpipot.events` | Topic for flow events |
| `PAYLOAD_B64_ENABLED` | `true` | Include base64-encoded payload in events |
| `PAYLOAD_HEX_ENABLED` | `true` | Include hex-encoded payload in events |

---

## Deployment Scenarios

| Profile | Kafka | Filebeat | Logstash | Image tags | Kafka PVC |
|---------|-------|----------|----------|------------|-----------|
| _(default)_ | ✅ | ✅ | ✅ | `latest` | emptyDir |
| `prod` | ✅ | ✅ | ✅ | `release-0.3` | 100Gi |
| `sensor` | ✅ | ❌ | kafka only | `latest` | emptyDir |
| `light` | ❌ | ❌ | ❌ | `latest` | — |
| `debug` | ❌ | ✅ | filebeat only | `latest` | — |

```bash
# Sensor node (Kafka + honeypots, no Filebeat)
helm upgrade --install dpipot k8s/chart/ -f k8s/chart/values-sensor.yaml

# Light node (honeypots only, no pipeline stack)
helm upgrade --install dpipot k8s/chart/ -f k8s/chart/values-light.yaml

# Debug (Filebeat only)
helm upgrade --install dpipot k8s/chart/ -f k8s/chart/values-debug.yaml
```

---

### Honeypot Route Customization

`HONEYPOT_ROUTES` maps nDPI protocol labels to `host:port` honeypot targets:

```yaml
HONEYPOT_ROUTES: >-
  HTTP=wordpot-svc:80,
  TLS=wordpot-svc:443,
  SSH=cowrie-svc:22,
  TELNET=cowrie-svc:23,
  FTP_CONTROL=heralding:21,
  MAIL_SMTP=heralding:25,
  MAIL_POP=heralding:110,
  MAIL_IMAP=heralding:143,
  MySQL=heralding:3306,
  RDP=heralding:3389,
  VNC=heralding:5900,
  HTTP_AUTH=heralding:80
```

Any protocol label not in `HONEYPOT_ROUTES` is forwarded to `DEFAULT_ROUTE`.

---

## Event Schema

```json
{
  "flow_id":              "550e8400-e29b-41d4-a716-446655440000",
  "tuple_id":             "192.168.1.10:54321->10.0.0.5:22",
  "timestamp":            "2024-01-15T14:32:01.123Z",
  "src_ip":               "192.168.1.10",
  "src_port":             54321,
  "dst_ip":               "10.0.0.5",
  "dst_port":             22,
  "ndpi_proto":           "SSH",
  "ndpi_app":             "SSH",
  "attack_type":          "ssh_password",
  "honeypot":             "cowrie-svc:22",
  "event_type":           "flow",
  "ttl":                  64,
  "tcp_window":           65535,
  "rtt_ms":               12.4,
  "duration_ms":          4821,
  "node_name":            "dpipot",
  "pod_name":             "dpipot-proxy-whv5w"
}
```

**Heartbeat events** (`event_type: "heartbeat"`, emitted every 60 s) include:

| Field | Description |
|---|---|
| `flow_table_size` | Current number of entries in the in-memory nDPI flow table |
| `flow_table_not_found` | Lookups where the flow wasn't in the table yet (nDPI hadn't classified) |
| `flow_table_unknown` | Lookups where the entry existed but the protocol was still Unknown |
| `kafka_drops` | Events dropped since last heartbeat (buffer full) |
| `uptime_sec` | Process uptime in seconds |

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
| Everything else | — | `DEFAULT_ROUTE` | raw relay |

---

## Guides

Step-by-step deployment guides for specific platforms:

| Guide | Description | Language |
|---|---|---|
| [Rocky Linux 9 — Full Setup](docs/en/rocky-linux-setup.md) | k3s, SELinux, networking, iptables TPROXY, secrets, Helm install | English |
| [Rocky Linux 9 — Full Setup](docs/pt-br/rocky-linux-setup.md) | k3s, SELinux, networking, iptables TPROXY, secrets, Helm install | Português |
| [Ubuntu 24.04 — Full Setup](docs/en/ubuntu-linux-setup.md) | k3s, AppArmor, ufw, SSH socket-activation, secrets, Helm install | English |
| [Ubuntu 24.04 — Full Setup](docs/pt-br/ubuntu-linux-setup.md) | k3s, AppArmor, ufw, SSH socket-activation, secrets, Helm install | Português |

---

## Requirements

- Kubernetes ≥ 1.25 (tested on **MicroK8s 1.29** and **k3s**)
- Nodes running Linux with `iptables` support (TPROXY target in `mangle` table)
- Helm ≥ 3.0
- Container registry access to `ghcr.io/spawnzao` (or rebuild images locally)
- `NET_ADMIN` + `NET_RAW` capabilities allowed by the cluster's admission policy

> **Local testing:** The proxy requires `IP_TRANSPARENT` socket option, which needs `NET_ADMIN` and is blocked in nested container environments (LXC/Docker-in-Docker). Test in a real VM or bare-metal node.

---

## Build

Images are built automatically by GitHub Actions on every push and pushed to `ghcr.io`:

- **`main`** → `ghcr.io/spawnzao/dpipot-proxy:latest` + `ghcr.io/spawnzao/dpipot-classifier:latest`
- **`dev`** → `ghcr.io/spawnzao/dpipot:latest` (unified binary)

To build locally:

```bash
# Unified binary — dev branch (compiles nDPI 4.12 from source, ~5 min)
docker build -t dpipot:local .

# Legacy — main branch
docker build -t dpipot-proxy:local ./proxy
docker build -t dpipot-classifier:local ./classifier
```

All images use multi-stage builds. The final runtime image is based on `debian:bookworm` with only the required shared libraries (`librdkafka1`, `libpcap0.8`, `libjson-c5`, `libndpi.so`).

---

## Repository Layout

```
dpipot-ng/
├── cmd/dpipot/             # Unified binary entry point (dev branch)
│   └── main.go
├── internal/               # Shared packages (dev branch)
│   ├── capture/            # AF_PACKET raw socket
│   ├── config/             # Merged environment variable loader
│   ├── flow/               # In-memory flow table (shared between goroutines)
│   ├── httpclassifier/     # HTTP path whitelist
│   ├── kafka/              # Kafka producer
│   ├── mitm/               # MITM handlers: SSH, RDP, HTTP, TLS, parsers
│   ├── ndpi/               # nDPI 4.12 CGO bindings (gondpi)
│   ├── proxy/              # TCP server, connection handler, health server
│   └── router/             # Protocol→honeypot routing table
├── classifier/             # Legacy: standalone classifier module (main branch)
│   ├── cmd/
│   └── internal/
├── proxy/                  # Legacy: standalone proxy module (main branch)
│   ├── cmd/proxy/
│   └── internal/
├── Dockerfile              # Unified dpipot image (dev branch)
├── go.mod                  # Root module: github.com/spawnzao/dpipot-ng
├── go.work                 # Workspace: root + classifier + proxy modules
└── k8s/                    # Kubernetes manifests (Helm)
    ├── chart/              # Helm chart
    └── secrets/            # .example files — copy and fill before helm install
```
