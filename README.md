# DPIpot-NG

**A Kubernetes-native honeypot orchestrator that uses Deep Packet Inspection to intelligently classify traffic at the network layer and steer it to diverse honeypot backends based on flexible protocol rules, with transparent MITM for capturing credentials, commands, and full session activity.**

DPIpot-NG intercepts all TCP connections arriving at a node — without touching firewall rules on the attacker's path — classifies each flow at Layer 2 using nDPI deep packet inspection, routes the connection to the appropriate honeypot service, and emits structured events to Kafka for ingestion into Elasticsearch/Kibana. The system operates completely transparently: attackers connect to the real node IP and port, unaware they are being redirected.

> **Branch status:**
> - `main` (v0.4 — stable): unified binary — AF_PACKET capture and TPROXY proxy run in the same process, sharing an in-memory flow table (no IPC). Tested in production and approved.
> - `dev`: active development — next improvements in progress

---

## Architecture

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

The proxy and classifier run as a **single Go binary** in the same process.

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

The system is deployed as a **DaemonSet** — one pod per node — and has been tested on **MicroK8s 1.29**, **k3s**, and **kubeadm** (Debian 13 trixie), but should run on any standard Kubernetes distribution that supports:
- `NET_ADMIN` and `NET_RAW` capabilities
- `hostNetwork: true` or a TPROXY-compatible CNI
- `iptables` available in init containers

### Operating modes

Two deployment modes are available depending on whether a node exposes services to the internet or not:

| Mode | Chart | Use case |
|---|---|---|
| **Standard** | `k8s/chart/` | Proxy + classifier + honeypots on the same node. The `dpipot-proxy` captures all inbound TCP via TPROXY, classifies it with nDPI, and routes it to honeypots running as `ClusterIP` services on the same cluster. All production nodes today run this mode. |
| **Standalone honeypots** | `k8s/chart-standalone/` (`dpipotProxy.enabled=false`) | Honeypots only — no local proxy, no TPROXY, no nDPI. A remote `dpipot-ng` node (running the proxy/classifier) forwards already-classified connections here via an isolated WireGuard network. The node has no data interface exposed to the internet. Useful to separate the public attack surface from honeypot execution, limiting blast radius if a honeypot is compromised. |
| **Standalone proxy** | `k8s/chart-standalone/` (`dpipotProxy.enabled=true`) | Proxy + classifier only — no local honeypots. Captures and classifies internet traffic (TPROXY + nDPI) and forwards connections to a remote honeypot node. Set `config.HONEYPOT_ROUTES` to the remote host. Useful when the capture node must be physically close to the traffic source but honeypot execution should be isolated elsewhere. |

The two charts are **completely independent** — they share no templates. Installing or uninstalling the standalone chart never affects a standard node, and vice versa.

Infrastructure is managed with **Helm**. The charts live in `k8s/chart/` (standard) and `k8s/chart-standalone/` (standalone):

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
├── chart-standalone/       # Standalone chart — honeypots-only OR proxy-only
│   ├── Chart.yaml
│   ├── values.yaml              # Defaults: all honeypots enabled, Groq LLM
│   ├── values-honeypots.yaml    # Tracked example for honeypot-only mode
│   ├── values-proxy-only.yaml   # Tracked example for proxy-only mode
│   └── templates/
│       ├── configmap.yaml       # dpipot-proxy env vars (proxy-only mode)
│       ├── daemonset-proxy.yaml # dpipot-proxy + TPROXY init container
│       ├── kafka.yaml           # Kafka (KRaft) for proxy pipeline
│       ├── logstash.yaml        # Logstash: Kafka→ES + Filebeat→ES pipelines
│       ├── filebeat.yaml        # Filebeat: Kubernetes pod log collection
│       ├── services.yaml        # ClusterIP services (proxy-only mode)
│       ├── cowrie.yaml
│       ├── galah.yaml           # Includes WireGuard tunnel initContainer
│       ├── heralding.yaml
│       ├── wordpot.yaml
│       └── network-policy.yaml  # Full isolation: deny all, except allowedIngressCIDR
└── secrets/
    ├── logstash-secrets.yaml.example    ← copy → logstash-secrets.yaml
    ├── galah-secrets.yaml.example       ← copy → galah-secrets.yaml
    ├── galah-llm-api-key.yaml.example   ← standalone chart: LLM API key
    └── galah-wg-secret.yaml.example     ← standalone chart: WireGuard tunnel config
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
microk8s helm3 upgrade --install dpipot k8s/chart/ \
  -f k8s/chart/values-prod.yaml \
  --namespace dpipot --create-namespace

# Watch rollout
kubectl rollout status daemonset/dpipot-proxy -n dpipot
kubectl get pods -n dpipot
```

**Note:** The network interface used by TPROXY defaults to `ens192`. Change `CLASSIFIER_INTERFACE` in `values.yaml` (or override per node) to match your node's interface name before deploying.

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

**Manual deploy (standard mode):**

```bash
# MicroK8s
microk8s helm3 -n dpipot upgrade --install dpipot k8s/chart/ \
  -f k8s/chart/values-$(hostname -s).yaml --create-namespace

# k3s / kubeadm
helm upgrade --install dpipot k8s/chart/ \
  -f k8s/chart/values-$(hostname -s).yaml \
  --namespace dpipot --create-namespace
```

### Standalone honeypot node

A standalone node runs only the honeypots — no proxy, no TPROXY, no nDPI — and is reached by a remote `dpipot-proxy` over an isolated WireGuard network. The standalone chart (`k8s/chart-standalone/`) is independent of the main chart and requires its own setup:

**1. Secrets (standalone chart only):**

```bash
# LLM API key used by galah (Groq or your own backend)
kubectl -n dpipot create secret generic galah-llm-api-key \
  --from-literal=api_key=<your-key>

# WireGuard config for galah's isolated LLM tunnel (if wgTunnel.enabled=true)
kubectl -n dpipot create secret generic galah-wg-secret \
  --from-file=wg-llm.conf=<path-to-your-galah-wg.conf>
```

See `k8s/secrets/galah-llm-api-key.yaml.example` and `k8s/secrets/galah-wg-secret.yaml.example` for the expected format.

**2. Pre-build the WireGuard tools image** (standalone chart requires it; the honeypot network has no internet):

```bash
# Build on any machine with internet access, then import on the honeypot host
mkdir wg-tools-image && cd wg-tools-image
cat > Dockerfile <<'EOF'
FROM alpine:3.19
RUN apk add --no-cache wireguard-tools iproute2
EOF
docker build -t dpipot/wg-tools:3.19 .
docker save dpipot/wg-tools:3.19 -o wg-tools.tar
scp wg-tools.tar user@<honeypot-host>:~/

# On the honeypot host (k3s):
sudo k3s ctr images import ~/wg-tools.tar
```

**3. Host-specific values file** (copy `values-honeypots.yaml` and fill in the placeholders):

```yaml
# k8s/chart-standalone/values-<hostname>.yaml  (local only, not committed)
hostExpose:
  ip: "<HONEYPOT_WG_IFACE_IP>"        # WireGuard interface IP on the honeypot network

honeypotIsolation:
  allowedIngressCIDR: "<HONEYPOT_CIDR>"   # only the remote dpipot-proxy may connect in
  galahWgEndpoint:
    ip: "<PUBLIC_IP_OF_LLM_WG_ENDPOINT>"  # WireGuard endpoint for galah's LLM tunnel
    port: 51820

honeypots:
  galah:
    model: "<LLM_MODEL>"
    llmApiBase: "http://<TUNNEL_INTERNAL_IP>:8000/v1"  # or Groq URL if using cloud
```

**4. Deploy:**

```bash
cd k8s/chart-standalone/
helm lint . -f values.yaml -f values-$(hostname -s).yaml
helm install dpipot-standalone . \
  -f values.yaml -f values-$(hostname -s).yaml \
  -n dpipot --create-namespace
```

> **Note:** The standalone chart uses `hostPort` + `hostIP` (not `ClusterIP`) to expose honeypot ports on the isolated WireGuard interface. `NetworkPolicy` is in full-deny mode — the only allowed inbound traffic is from `allowedIngressCIDR`, and the only allowed outbound is galah's WireGuard tunnel egress. See [the standalone guide](docs/en/honeypot-standalone-k3s-cilium.md) for the full walkthrough including k3s + Cilium setup.

### Standalone proxy node

A standalone **proxy-only** node captures and classifies internet traffic (TPROXY + nDPI) and forwards connections to a remote honeypot node. It uses the same `k8s/chart-standalone/` chart with `dpipotProxy.enabled=true` and all honeypots disabled.

**1. Secrets:**

```bash
# Elasticsearch credentials for the Logstash pipeline
kubectl -n dpipot create secret generic logstash-elasticsearch-secrets \
  --from-literal=ES_HOST="https://<ES_HOST>:9200" \
  --from-literal=ES_API_KEY="<ES_API_KEY>"

# Elasticsearch CA certificate (if using HTTPS)
kubectl -n dpipot create secret generic elastic-certs \
  --from-file=ca.crt=/path/to/ca.crt
```

**2. Host-specific values file** (copy `values-proxy-only.yaml` and fill in the placeholders):

```yaml
# k8s/chart-standalone/values-<hostname>.yaml  (local only, not committed)
network:
  interface: "<DATA_IFACE>"           # internet-facing interface (e.g. ens192)

dpipotProxy:
  enabled: true

kafka:
  enabled: true

filebeat:
  enabled: true

honeypots:
  cowrie:    { enabled: false }
  wordpot:   { enabled: false }
  heralding: { enabled: false }
  galah:     { enabled: false }

config:
  HONEYPOT_ROUTES: "<HONEYPOT_WG_IP>:<PORT>"
```

**3. Deploy:**

```bash
cd k8s/chart-standalone/
helm lint . -f values.yaml -f values-$(hostname -s).yaml
helm install dpipot-standalone . \
  -f values.yaml -f values-$(hostname -s).yaml \
  -n dpipot --create-namespace
```

> **Note:** The proxy node uses k3s with Flannel (no Cilium). Two kernel fixes are
> required before deploying: set `rp_filter=0` **on the named data interface** (not
> just on `all`) and configure a WireGuard `FwMark` + routing table 200 if the
> WireGuard endpoint IP shares a subnet with the data interface. See
> [the proxy standalone guide](docs/en/dpipot-proxy-standalone-k3s.md) for the
> full walkthrough.

### CI/CD (GitHub Actions)

The repository includes a self-hosted GitHub Actions runner workflow that builds and deploys automatically:

- **`main` branch** → builds `ghcr.io/spawnzao/dpipot:main` (stable)
- **`dev` branch** → builds `ghcr.io/spawnzao/dpipot:dev` → triggers deploy automatically via `gh workflow run deploy.yml`

**Orchestrator detection:** the workflow detects whether the host runs k3s or MicroK8s and selects the right commands automatically.

**Values file resolution:** the workflow runs `hostname -s` and looks for `k8s/chart/values-$(hostname -s).yaml`. If the file exists it is used; if not, it falls back to `values.yaml` and prints a warning in the CI log.

---

## Configuration Reference

All configuration is done via environment variables, loaded from the `dpipot-config` ConfigMap.

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
| `NDPI_EVENTS_ENABLED` | `false` | Publish per-packet nDPI classification events to Kafka |

**Kafka**

| Variable | Default | Description |
|----------|---------|-------------|
| `KAFKA` | `true` | Enable Kafka publishing |
| `KAFKA_BROKERS` | `kafka-svc:9092` | Comma-separated Kafka broker addresses |
| `KAFKA_TOPIC` | `dpipot.events` | Base topic for flow events |
| `PAYLOAD_B64_ENABLED` | `true` | Include base64-encoded payload in events |
| `PAYLOAD_HEX_ENABLED` | `true` | Include hex-encoded payload in events |

---

## Deployment Scenarios

| Profile | Kafka | Filebeat | Logstash | Image tags | Kafka PVC |
|---------|-------|----------|----------|------------|-----------|
| _(default)_ | ✅ | ✅ | ✅ | `latest` | emptyDir |
| `prod` | ✅ | ✅ | ✅ | `main` | 100Gi |
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
  "event_type":           "flow",
  "src_ip":               "192.168.1.10",
  "src_port":             54321,
  "dst_ip":               "10.0.0.5",
  "dst_port":             22,
  "ndpi_proto":           "SSH",
  "ndpi_app":             "SSH",
  "attack_type":          "ssh_password",
  "honeypot":             "cowrie-svc:22",
  "ttl":                  64,
  "tos":                  0,
  "tcp_window":           65535,
  "ip_version":           4,
  "rtt_ms":               12.4,
  "rtt_var_ms":           1.2,
  "duration_ms":          4821,
  "payload_size":         1024,
  "node_name":            "dpipot",
  "pod_name":             "dpipot-proxy-whv5w"
}
```

**nDPI events** (`event_type: "ndpi"`, published per-packet when `NDPI_EVENTS_ENABLED=true`, topic `dpipot.events-ndpi`) additionally include:

| Field | Description |
|---|---|
| `transport` | `"tcp"` or `"udp"` |
| `tcp_flags` | Decoded TCP flags: `"SYN ACK PSH ..."` |
| `payload_len` | Application-layer bytes in this packet |
| `ethertype` | `"0x0800"` (IPv4) or `"0x86DD"` (IPv6) |
| `ip_proto` | `6` (TCP) or `17` (UDP) |
| `category` | nDPI category ID |

**Heartbeat events** (`event_type: "heartbeat"`, emitted every 60 s) include:

| Field | Description |
|---|---|
| `flow_table_size` | Current entries in the in-memory nDPI flow table |
| `flow_table_not_found` | Lookups where flow wasn't in the table yet |
| `flow_table_unknown` | Lookups where entry existed but protocol was still Unknown |
| `afpacket_drops` | Packets dropped by the kernel AF_PACKET buffer since last heartbeat |
| `afpacket_chan_drops` | Packets dropped by the internal Go channel (100k slots) |
| `ndpi_packets_processed` | Packets processed by nDPI in the interval |
| `ndpi_flows_active` | Active flows in the nDPI sync.Map (snapshot) |
| `kafka_drops` | Events dropped since last heartbeat (channel full) |
| `kafka_delivery_errors` | librdkafka delivery callbacks with errors |
| `kafka_delivery_dropped` | Messages definitively lost (delivery.timeout.ms expired) |
| `kafka_chan_len` | Events queued in Go channel awaiting drain |
| `kafka_queue_len` | Messages queued in librdkafka awaiting delivery |
| `uptime_sec` | Process uptime in seconds |

**SSH MITM response events** include `ssh_response` (server output captured during the session) alongside `attack_type` (the command typed by the attacker).

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
| [Debian 13 (trixie) — kubeadm + Calico](docs/en/debian-kubeadm-setup.md) | kubeadm, Calico CNI, containerd, nftables, control/data plane separation, k3s vs kubeadm differences | English |
| [Debian 13 (trixie) — kubeadm + Calico](docs/pt-br/debian-kubeadm-setup.md) | kubeadm, Calico CNI, containerd, nftables, separação plano de controle/dados, diferenças k3s vs kubeadm | Português |
| [Standalone Honeypots — k3s + Cilium](docs/en/honeypot-standalone-k3s-cilium.md) | standalone mode (honeypots only, no local proxy), k3s, Cilium CNI + kube-proxy replacement, WireGuard isolation, full-deny NetworkPolicy, galah LLM tunnel, chart-standalone | English |
| [Honeypots Standalone — k3s + Cilium](docs/pt-br/honeypot-standalone-k3s-cilium.md) | modo standalone (só honeypots, sem proxy local), k3s, Cilium CNI + substituição do kube-proxy, isolamento WireGuard, NetworkPolicy full-deny, túnel LLM do galah, chart-standalone | Português |
| [Standalone Proxy — k3s + Flannel](docs/en/dpipot-proxy-standalone-k3s.md) | standalone proxy-only mode (dpipot-proxy + Kafka + Logstash), k3s, Flannel, TPROXY, rp_filter per-interface fix, WireGuard leakage fix (FwMark + table 200), remote honeypot routing | English |
| [Proxy Standalone — k3s + Flannel](docs/pt-br/dpipot-proxy-standalone-k3s.md) | modo standalone somente proxy (dpipot-proxy + Kafka + Logstash), k3s, Flannel, TPROXY, correção rp_filter por interface, correção de vazamento WireGuard (FwMark + tabela 200), encaminhamento para honeypots remotos | Português |

---

## Requirements

- Kubernetes ≥ 1.25 (tested on **MicroK8s 1.29**, **k3s**, and **kubeadm** on Debian 13 trixie)
- Nodes running Linux with `iptables` support (TPROXY target in `mangle` table)
- Helm ≥ 3.0
- Container registry access to `ghcr.io/spawnzao` (or rebuild images locally)
- `NET_ADMIN` + `NET_RAW` capabilities allowed by the cluster's admission policy

> **Local testing:** The proxy requires `IP_TRANSPARENT` socket option, which needs `NET_ADMIN` and is blocked in nested container environments (LXC/Docker-in-Docker). Test in a real VM or bare-metal node.

### kubeadm / Debian 13 (trixie) particularities

When deploying on a kubeadm cluster, a few extra steps are required compared to k3s or MicroK8s:

| Topic | Detail |
|---|---|
| **Swap** | Must be disabled before `kubeadm init` (`swapoff -a` + remove from `/etc/fstab`) |
| **Kernel modules** | `br_netfilter` and `overlay` must be loaded manually and added to `/etc/modules-load.d/` |
| **CNI** | No bundled CNI — install Calico (or another CNI) after `kubeadm init` |
| **StorageClass** | No default StorageClass — install [local-path-provisioner](https://github.com/rancher/local-path-provisioner) for PVC support |
| **apiserver / kubelet bind** | Bind to the node's main IP, not `0.0.0.0`, to avoid conflicts with the data-plane interface (`--apiserver-advertise-address`, `--node-ip`) |
| **Control-plane taint** | On single-node clusters, remove the taint so workloads can schedule: `kubectl taint nodes --all node-role.kubernetes.io/control-plane-` |
| **containerd `bin_dir`** | Debian 13 ships containerd without the CNI bin dir — create `/opt/cni/bin` and fix the path in `/etc/containerd/config.toml` |
| **nftables** | Debian 13 uses nftables by default; no firewalld/ufw needed — configure rules directly with `nft` |
| **`software-properties-common`** | Not available on Debian 13 minimal — add the Kubernetes apt repository manually via `gpg` + `echo "deb ..."` |

See the [Debian 13 setup guide](docs/en/debian-kubeadm-setup.md) for a complete step-by-step walkthrough.

---

## Build

Images are built automatically by GitHub Actions on every push and pushed to `ghcr.io`:

- **`main`** → `ghcr.io/spawnzao/dpipot:main`
- **`dev`** → `ghcr.io/spawnzao/dpipot:dev` (triggers automatic deploy)

To build locally:

```bash
# Compiles nDPI 4.12 from source (~5 min on first run)
docker build -t dpipot:local .
```

To build and run directly without Docker:

```bash
CGO_ENABLED=1 go build -o dpipot ./cmd/dpipot
```

All images use multi-stage builds. The final runtime image is based on `debian:bookworm` with only the required shared libraries (`librdkafka1`, `libpcap0.8`, `libjson-c5`, `libndpi.so`).

---

## Repository Layout

```
dpipot-ng/
├── cmd/dpipot/             # Unified binary entry point
│   ├── main.go
│   └── sysctl_check.go     # rmem_max startup check with interactive sysctl fix
├── internal/               # All shared packages
│   ├── capture/            # AF_PACKET raw socket (100k-slot Go channel)
│   ├── config/             # Environment variable loader
│   ├── flow/               # In-memory flow table (shared between goroutines)
│   ├── httpclassifier/     # HTTP path whitelist
│   ├── kafka/              # Kafka producer with self-healing watchdog
│   ├── mitm/               # MITM handlers: SSH, RDP, HTTP, TLS, parsers
│   ├── ndpi/               # nDPI 4.12 CGO bindings (gondpi) + handler
│   ├── proxy/              # TCP server, connection handler, health server
│   └── router/             # Protocol→honeypot routing table
├── tools/
│   ├── debug_afpacket/     # Standalone AF_PACKET debug tool
│   └── kafka-consumer/     # Standalone Kafka consumer tool
├── Dockerfile              # Multi-stage build; compiles nDPI from source
├── go.mod                  # Root module: github.com/spawnzao/dpipot-ng
├── go.work                 # Workspace: root + tools modules
├── k8s/                    # Kubernetes manifests (Helm)
│   ├── chart/              # Helm chart
│   └── secrets/            # .example files — copy and fill before helm install
└── docs/                   # Deployment guides (en + pt-br)
```
