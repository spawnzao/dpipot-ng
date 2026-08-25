# dpipot-proxy Standalone Node — k3s + Flannel

This guide sets up a standalone **proxy-only** node: it captures internet traffic
(TPROXY + nDPI), classifies it, and forwards connections to a remote honeypot node
instead of running honeypots locally.

```
Internet → [proxy node] ──WireGuard──> [honeypot node]
              TPROXY + nDPI              cowrie/heralding/galah/wordpot
              dpipot-proxy
              Kafka + Logstash → ES
```

The proxy node runs k3s with Flannel (no Cilium required — TPROXY works with vanilla
kube-proxy). The honeypot node is set up separately; see
[honeypot-standalone-k3s-cilium.md](honeypot-standalone-k3s-cilium.md).

---

## Prerequisites

- Debian 12+, Ubuntu 22.04+, or Rocky Linux 9 on the proxy node
- Two network interfaces:
  - **control/admin interface** (`<ADMIN_IFACE>`): SSH, WireGuard admin mesh, cluster traffic
  - **data interface** (`<DATA_IFACE>`): faces internet traffic to be captured
- Helm 3 installed on your workstation
- Remote honeypot node already deployed and reachable via an isolated WireGuard network
- Access to the Elasticsearch cluster (endpoint + API key)

---

## 1. Install k3s (Flannel, no kube-proxy replacement)

```bash
curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC=" \
  --node-ip=<ADMIN_IFACE_IP> \
  --advertise-address=<ADMIN_IFACE_IP> \
  --bind-address=<ADMIN_IFACE_IP> \
  --flannel-iface=<ADMIN_IFACE> \
  --disable=traefik \
" sh -
```

> **Note:** No `--disable-kube-proxy` here — standard kube-proxy works fine for the
> proxy pipeline. Cilium is used on the honeypot node only.

Wait for the node to be ready:

```bash
sudo k3s kubectl get nodes
```

---

## 2. Fix `rp_filter` on the data interface

> **Important:** `net.ipv4.conf.all.rp_filter=0` alone is **not** sufficient.
> The kernel uses the **stricter** of `all` and the specific interface setting.
> On a data interface without its own default gateway (asymmetric routing), strict
> `rp_filter` on the interface silently drops all inbound packets — including ICMP
> — even when the `all` setting is relaxed.

Set both:

```bash
# Persist across reboots
cat >> /etc/sysctl.d/99-dpipot.conf << 'EOF'
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.<DATA_IFACE>.rp_filter = 0
net.ipv4.conf.all.forwarding = 1
net.ipv4.ip_forward = 1
EOF

sysctl -p /etc/sysctl.d/99-dpipot.conf
```

Verify:

```bash
sysctl net.ipv4.conf.all.rp_filter net.ipv4.conf.<DATA_IFACE>.rp_filter
# Both should be 0
```

---

## 3. Fix WireGuard data-plane traffic leakage

> **Background:** If the WireGuard peer `Endpoint` IP is in the same /25 (or
> similar subnet) as your data interface IP, the kernel may route WireGuard UDP
> packets through the data interface via a connected route — which takes precedence
> over any explicit route via the control interface. This causes WireGuard handshakes
> to leak out the wrong interface and fail silently.
>
> **Fix:** Use a `FwMark` on the WireGuard interface and a dedicated routing table
> that forces all WireGuard packets through the control interface.

Edit `/etc/wireguard/<ADMIN_WG_IFACE>.conf` (your admin WireGuard interface):

```ini
[Interface]
PrivateKey = <ADMIN_WG_PRIVATE_KEY>
Address = <ADMIN_WG_ADDR>/24
FwMark = 0x64
Table = off          # do not install routes into the main table

PostUp = ip rule add fwmark 0x64 table 200 priority 100
PostUp = ip route add default via <ADMIN_IFACE_GW> dev <ADMIN_IFACE> table 200
PostDown = ip rule del fwmark 0x64 table 200 priority 100
PostDown = ip route del default via <ADMIN_IFACE_GW> dev <ADMIN_IFACE> table 200

[Peer]
PublicKey = <HONEYPOT_NODE_WG_PUBLIC_KEY>
Endpoint = <HONEYPOT_NODE_PUBLIC_IP>:51820
AllowedIPs = <HONEYPOT_WG_CIDR>
PersistentKeepalive = 25
```

> `FwMark = 0x64` marks outgoing WireGuard UDP packets. The `ip rule` sends those
> marked packets to table 200, which has a forced route via the control interface
> — ensuring WireGuard traffic never touches the data interface.

Apply:

```bash
wg-quick down <ADMIN_WG_IFACE> 2>/dev/null || true
wg-quick up <ADMIN_WG_IFACE>
```

---

## 4. Create the namespace and secrets

```bash
sudo k3s kubectl create namespace dpipot
```

**Elasticsearch credentials** (Logstash pipeline):

```bash
sudo k3s kubectl -n dpipot create secret generic logstash-elasticsearch-secrets \
  --from-literal=ES_HOST="https://<ES_HOST>:9200" \
  --from-literal=ES_API_KEY="<ES_API_KEY>"
```

**Elasticsearch CA certificate** (if using HTTPS):

```bash
sudo k3s kubectl -n dpipot create secret generic elastic-certs \
  --from-file=ca.crt=/path/to/ca.crt
```

---

## 5. Configure `values-proxy-only.yaml`

Copy the example file and fill in your values:

```bash
cp k8s/chart-standalone/values-proxy-only.yaml \
   k8s/chart-standalone/values-<hostname>.yaml
```

Key fields to set:

```yaml
network:
  interface: "<DATA_IFACE>"    # e.g. ens192, eth1

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
  LOG_LEVEL: "info"
```

---

## 6. Deploy with Helm

```bash
cd /path/to/dpipot-ng

helm install dpipot-standalone k8s/chart-standalone/ \
  -n dpipot \
  -f k8s/chart-standalone/values-<hostname>.yaml
```

Check pod status:

```bash
sudo k3s kubectl -n dpipot get pods -w
```

---

## 7. Verify TPROXY rules

After `dpipot-proxy` starts, check that the init container applied the iptables rules:

```bash
sudo iptables -t mangle -L PREROUTING -n -v | grep TPROXY
# Expected: rule redirecting TCP on <DATA_IFACE> to 127.0.0.1:8080

sudo ip rule show
# Expected: fwmark 0x1 lookup 100

sudo ip route show table 100
# Expected: local 0.0.0.0/0 dev lo
```

---

## 8. Verify Kafka connectivity

```bash
sudo k3s kubectl -n dpipot exec -it deploy/kafka -- \
  /opt/kafka/bin/kafka-topics.sh \
  --bootstrap-server localhost:9092 \
  --list
```

Topics `dpipot.events.proxy` and `dpipot.events.classifier` should appear after
the first connections flow through the proxy.

---

## 9. Verify the Logstash → Elasticsearch pipeline

Check Logstash logs:

```bash
sudo k3s kubectl -n dpipot logs deploy/logstash -f
```

Look for `Pipeline started` for both `kafka-to-elasticsearch` and `kubernetes-logs`.

Verify index creation in Elasticsearch:

```bash
curl -s -u ":" -H "Authorization: ApiKey <ES_API_KEY>" \
  "https://<ES_HOST>:9200/_cat/indices/dpipot-proxy-*?v"
```

---

## 10. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| All inbound packets on `<DATA_IFACE>` silently dropped | `rp_filter` set only on `all`, not on the named interface | Set `net.ipv4.conf.<DATA_IFACE>.rp_filter=0` explicitly |
| WireGuard handshake to honeypot node fails | WireGuard packets routed via data interface (connected route wins) | Add `FwMark` + table 200 route via control interface |
| `dpipot-proxy` not capturing traffic | TPROXY rules missing or wrong interface | Check init container logs; confirm `network.interface` in values |
| Logstash not writing to ES | Wrong `ES_HOST` or `ES_API_KEY`, missing CA cert | Verify secret contents and `elastic-certs` secret |
| Topics not appearing in Kafka | `dpipot-proxy` not reaching Kafka | Check `KAFKA: "true"` in ConfigMap and `kafka-svc` Service |
