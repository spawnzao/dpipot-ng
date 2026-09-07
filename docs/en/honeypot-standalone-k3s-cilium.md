# Standalone honeypots (no dpipot-ng) on k3s + Cilium, isolated by WireGuard

This guide documents how to set up a host that runs **only the
honeypots** (`cowrie`, `heralding`, `wordpot`, `galah`) — no
`dpipot-proxy`, no TPROXY, no local nDPI. A remote `dpipot-ng` (running
on another host, with the proxy/classifier) forwards already-classified
traffic here.

This is useful when you want to separate the real attack surface (the
TPROXY host, exposed to the internet) from the host that actually runs
the honeypots — shrinking the blast radius if a honeypot is compromised,
and letting you test different orchestration/CNI combinations without
touching production.

Unlike the other guides in this repository (Rocky, Ubuntu, Debian), this
host has **no data interface exposed to the internet at all** — it only
exists inside private (WireGuard) networks. If you're looking for the
guide for a full node (proxy + honeypots), see
[ubuntu-linux-setup.md](ubuntu-linux-setup.md) or
[rocky-linux-setup.md](rocky-linux-setup.md).

> [!NOTE]
> This mode uses a **separate Helm chart** (`k8s/chart-standalone/`), not
> the main chart (`k8s/chart/`) used in the other guides. This is
> deliberate: instead of adding conditional flags (`dpipotProxy.enabled`,
> `hostExpose.enabled`, etc.) to the production chart to support both
> modes, the standalone mode lives in its own isolated chart — zero risk
> of regressing the chart used by normal production nodes.

## Conventions used in this guide

This host has (at least) 4 interfaces, each with a very specific role —
**none of them is "the data interface"**, since there's no TPROXY here:

- **External egress** (`<EXT_IFACE>`, e.g. `ens18`): only used by the
  host itself to reach the internet (package updates, etc.) — **no
  administrative service listens on it**.
- **Primary admin** (`<ADMIN_WG_IFACE>` / `<ADMIN_CIDR>`, e.g. `wg0`,
  `10.X.X.0/24`): WireGuard management mesh — SSH, k3s API, Cilium
  agent.
- **Backup admin** (`<ADMIN_BACKUP_WG_IFACE>` / `<ADMIN_BACKUP_CIDR>`,
  e.g. `wg1`, `10.Y.Y.0/24`): a second, independent administration mesh
  (redundancy — if one mesh's WireGuard server goes down, the other
  keeps working). Treated with the same trust level as the primary
  admin mesh.
- **Honeypot network** (`<HONEYPOT_WG_IFACE>` / `<HONEYPOT_CIDR>`, e.g.
  `wg2`, `10.Z.Z.0/24`): an isolated network, **no internet route, no
  DNS**. This is how the remote `dpipot-proxy` reaches this host's
  honeypots. No other interface has visibility into it.

> [!CAUTION]
> **The 3 WireGuard meshes must never see each other through the host's
> routing.** This isn't automatic to break — WireGuard doesn't bridge
> different interfaces by default (each is isolated by nature) — but if
> anyone adds a static route or a "temporary debugging" `FORWARD` rule
> linking two of them, isolation breaks silently. No such rule is
> required anywhere in this guide — if you plan to let the admin mesh
> **initiate** connections into the honeypot network (e.g. to
> investigate a compromised honeypot), that needs a stateful
> (`conntrack`) firewall rule, out of scope for this guide.

Replace every placeholder (`<...>`) with the real values from your
environment.

---

## Step 1 — Initial survey

Before touching anything, confirm what already exists:

```bash
hostname
ip -br a
ip route
sudo wg show          # confirm the 3 WireGuard interfaces already exist
ss -tulpn             # ports already in use — we'll bind 21/22/23/25/80/
                       # 110/143/3306/3389/5432/5900/2222 next
df -h /
```

> [!NOTE]
> This guide assumes the 3 WireGuard interfaces (`<ADMIN_WG_IFACE>`,
> `<ADMIN_BACKUP_WG_IFACE>`, `<HONEYPOT_WG_IFACE>`) are **already
> configured and up** before you start — creating them is out of scope
> here (it depends on your WireGuard provider/topology).

---

## Step 2 — Temporary sudo (if needed)

If your user's `sudo` prompts for an interactive password and you'll run
this guide's commands via automation (script, agent, CI), unlock it
temporarily and **remove it at the end**:

```bash
echo "<your-user> ALL=(ALL) NOPASSWD:ALL" | sudo tee /etc/sudoers.d/90-temp
sudo chmod 440 /etc/sudoers.d/90-temp
sudo visudo -c                          # validate syntax before trusting it

# at the very end:
# sudo rm /etc/sudoers.d/90-temp
```

---

## Step 3 — SSH hardening: admin interfaces only

Nothing administrative should listen on the external-egress interface or
on the honeypot network.

```bash
sudo tee /etc/ssh/sshd_config.d/90-listen-admin-only.conf > /dev/null <<EOF
ListenAddress <ADMIN_WG_IFACE_IP>
ListenAddress <ADMIN_BACKUP_WG_IFACE_IP>
EOF
sudo sshd -t && echo OK    # validate syntax BEFORE restarting
```

> [!CAUTION]
> **Known bug (`sshd` vs `wg-quick` boot race)**: by default the `ssh`
> unit doesn't depend on WireGuard — on some boots `sshd` tries to bind
> `ListenAddress` before the WireGuard interface exists yet, and gets
> stuck listening only on whatever interface was already up (can take
> minutes until someone restarts the service manually). Fix this
> **before** restarting SSH:
> ```bash
> sudo mkdir -p /etc/systemd/system/ssh.service.d
> sudo tee /etc/systemd/system/ssh.service.d/90-wait-wireguard.conf > /dev/null <<EOF
> [Unit]
> After=wg-quick@<ADMIN_WG_IFACE>.service wg-quick@<ADMIN_BACKUP_WG_IFACE>.service
> Wants=wg-quick@<ADMIN_WG_IFACE>.service wg-quick@<ADMIN_BACKUP_WG_IFACE>.service
> EOF
> sudo systemctl daemon-reload
> ```

Restart with a safety net (auto-revert if you lose access):

```bash
sudo bash -c '
  (sleep 45 && ! systemctl is-active --quiet ssh && \
    rm -f /etc/ssh/sshd_config.d/90-listen-admin-only.conf && \
    systemctl restart ssh) &
  systemctl restart ssh
'
# confirm you reconnected BEFORE continuing:
ssh <user>@<ADMIN_WG_IFACE_IP> "echo RECONNECT_OK"
```

---

## Step 4 — Install k3s (no kube-proxy, no default CNI)

```bash
curl -sfL https://get.k3s.io | sudo sh -s - server \
  --flannel-backend=none \
  --disable-kube-proxy \
  --disable-network-policy \
  --disable=traefik \
  --disable=servicelb \
  --bind-address=<ADMIN_WG_IFACE_IP> \
  --node-ip=<ADMIN_WG_IFACE_IP> \
  --advertise-address=<ADMIN_WG_IFACE_IP> \
  --tls-san=<ADMIN_BACKUP_WG_IFACE_IP> \
  --write-kubeconfig-mode 644
```

> [!CAUTION]
> **`--disable-kube-proxy` is not optional if you're going to use Cilium
> with `kubeProxyReplacement=true`** (next step). Without this flag,
> k3s's embedded kube-proxy and Cilium fight over the same network
> rules — symptom: `coredns`/`local-path-provisioner`/`metrics-server`
> stuck in `CrashLoopBackOff` with `i/o timeout` errors trying to reach
> the API's `ClusterIP` (`10.43.0.1:443` or equivalent). This only
> affects **pods**, not the host — `curl`-ing the `ClusterIP` from the
> host itself works fine, which can hide the problem if you don't test
> from inside a pod.

```bash
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
kubectl get nodes -o wide   # NotReady is expected, no CNI yet
```

---

## Step 5 — Helm + Cilium

```bash
curl -sfL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | sudo bash

helm repo add cilium https://helm.cilium.io/
helm repo update

helm install cilium cilium/cilium --version 1.16.5 --namespace kube-system \
  --set kubeProxyReplacement=true \
  --set k8sServiceHost=<ADMIN_WG_IFACE_IP> \
  --set k8sServicePort=6443 \
  --set operator.replicas=1 \
  --set devices='{<ADMIN_WG_IFACE>,<ADMIN_BACKUP_WG_IFACE>}'
```

> [!WARNING]
> **`devices` must explicitly list the admin interfaces** — without this
> option, Cilium auto-detects **every** interface on the host (including
> the external-egress one and the honeypot network), which confuses the
> `kubeProxyReplacement` datapath (same symptom as the bug above:
> `ClusterIP` unreachable from inside pods). If you have two admin
> meshes (like in this guide), list both — `devices` accepts a list.

```bash
# wait for cilium to become ready (can take 1-2min):
kubectl -n kube-system rollout status daemonset/cilium
kubectl get nodes -o wide   # should now be Ready
```

---

## Step 6 — `ufw`: disable or allow routed traffic

Many Ubuntu images ship with `ufw` pre-enabled, defaulting to
`deny (routed)`/`deny (incoming)`.

```bash
sudo ufw status verbose
```

> [!CAUTION]
> **`ufw` with a `deny` policy on `FORWARD` breaks any CNI** — all
> pod↔host traffic gets blocked, even with Cilium fully correct.
> Identical symptom to the two previous bugs (pods can't reach the
> `ClusterIP`/API), so it's easy to misdiagnose if you already touched
> k3s/Cilium before checking `ufw`. If the only existing rule is SSH —
> and `sshd` is already restricted via `ListenAddress` (Step 3) — that
> `ufw` rule is redundant:
> ```bash
> sudo ufw disable
> ```
> If you need to keep `ufw` active for another reason, explicitly allow
> the Cilium pod CIDR and the WireGuard interfaces in `FORWARD`/`INPUT`
> — more rules to maintain, redundant with what Cilium already does.

Validate from inside a pod (not just the host — the host will always
succeed, even with the bug present):

```bash
kubectl run debugtest --image=busybox:stable --restart=Never --rm -i \
  --timeout=15s -- wget -T3 -O- https://<ADMIN_WG_IFACE_IP>:6443/healthz
```

---

## Step 7 — Clone the repository

```bash
git clone https://github.com/spawnzao/dpipot-ng.git ~/dpipot-ng
cd ~/dpipot-ng/k8s/chart-standalone
```

> [!NOTE]
> Note it's `k8s/chart-standalone/`, **not** `k8s/chart/` (used in the
> other guides). It's an independent Helm chart, with its own
> `Chart.yaml`/`values.yaml`/`templates/` — it shares nothing with the
> production chart, so installing/uninstalling here never affects a full
> node.

---

## Step 8 — `galah`'s WireGuard tunnel image (build-time, not runtime)

`galah` brings up its **own WireGuard tunnel** (`wg-llm`), isolated, only
to talk to the LLM backend — the other honeypots don't have this
capability. Since the honeypot network has no internet (Step 10), the
`initContainer` that brings up this tunnel **cannot install packages at
runtime**.

Build the image on a machine **with** internet (it doesn't have to be
the honeypot host):

```bash
mkdir wg-tools-image && cd wg-tools-image
cat > Dockerfile <<'EOF'
FROM alpine:3.19
RUN apk add --no-cache wireguard-tools iproute2
EOF
docker build -t dpipot/wg-tools:3.19 .
docker save dpipot/wg-tools:3.19 -o wg-tools.tar
scp wg-tools.tar <user>@<ADMIN_WG_IFACE_IP>:~/
```

On the honeypot host, import it straight into k3s's containerd (no
registry needed):

```bash
sudo k3s ctr images import ~/wg-tools.tar
sudo k3s ctr images ls | grep wg-tools
rm ~/wg-tools.tar
```

---

## Step 9 — `galah`'s secrets (WireGuard tunnel + LLM API key)

Generate the WireGuard `.conf` on the LLM backend side (out of scope for
this guide — depends on how you provision the peer, and is only needed
if `honeypots.galah.wgTunnel.enabled: true`, this chart's default).
Create the Secret **directly in the cluster**, without routing the
private key through any unnecessary intermediate file:

```bash
kubectl create namespace dpipot --dry-run=client -o yaml | kubectl apply -f -
kubectl -n dpipot create secret generic galah-wg-secret \
  --from-file=wg-llm.conf=<path-to-your-galah-wg.conf>
```

> [!NOTE]
> The filename inside the Secret (`wg-llm.conf`) matters — it becomes
> the interface name (`wg-llm`) when the `initContainer` runs `wg-quick
> up /etc/wireguard-secret/wg-llm.conf`.

`galah` also needs the API key for the LLM provider configured in
`honeypots.galah.llmApiBase` (see
`k8s/secrets/galah-llm-api-key.yaml.example` for the format):

```bash
kubectl -n dpipot create secret generic galah-llm-api-key \
  --from-literal=api_key=<your-key-or-fixed-value-for-your-backend>
```

---

## Step 10 — Host-specific values override

`k8s/chart-standalone/values.yaml` already ships standalone mode as the
only mode (no on/off flags — unlike the main chart, there's no other way
to run this one), and `galah` already defaults to a generic external
provider (Groq) — same as the main chart, so no infrastructure of ours
ships as the repository's "default". Copy `values-honeypots.yaml` (the
tracked example) to `values-<host-name>.yaml` and replace the
placeholders:

```yaml
hostExpose:
  ip: "<HONEYPOT_WG_IFACE_IP>"

honeypotIsolation:
  allowedIngressCIDR: "<HONEYPOT_CIDR>"   # only the remote dpipot-proxy
  galahWgEndpoint:
    ip: "<LLM_WG_ENDPOINT_PUBLIC_IP>"
    port: 51820

honeypots:
  galah:
    # only override model/llmApiBase if you're using your own LLM
    # backend via tunnel - the default (Groq) already works without this
    model: "<YOUR_LLM_BACKEND_MODEL>"
    llmApiBase: "http://<LLM_TUNNEL_INTERNAL_IP>:8000/v1"
```

> [!WARNING]
> **Port 80 conflict between `heralding` and `wordpot`**: both have an
> HTTP module on port 80. This never causes trouble on nodes with a
> local `dpipot-proxy` (each honeypot has its own `ClusterIP`), but here
> both would try to bind the **same** `hostIP:80` — whichever pod loses
> the scheduling race stays `Pending` with `didn't have free ports for
> the requested pod ports`. This chart's default `values.yaml` already
> ships with `honeypots.heralding.disableHttpModule: true` for exactly
> this reason — `wordpot` covers generic HTTP. If your remote
> `dpipot-proxy` distinguishes `HTTP` from `HTTP_AUTH` in classification,
> both need to point at `wordpot` on this specific host (losing that
> distinction only here). Only flip it to `false` if you're sure there's
> no conflict in your case (e.g. `wordpot` disabled).

Every honeypot already binds via `hostPort` + `hostIP` (keeping the pod
in its own network namespace — unlike `hostNetwork: true`, which would
share the entire host network and make `NetworkPolicy` stop applying to
that pod). This is fixed behavior in this chart, not an option.

---

## Step 11 — Deploy

```bash
helm lint . -f values.yaml -f values-<host-name>.yaml
helm template . -f values.yaml -f values-<host-name>.yaml | less   # review before applying
helm install dpipot-standalone . -f values.yaml -f values-<host-name>.yaml -n dpipot
```

```bash
kubectl -n dpipot get pods -o wide
kubectl -n dpipot get pvc
```

---

## Step 12 — Verification

Confirm `galah` brings up the tunnel:

```bash
POD=$(kubectl -n dpipot get pod -l app=galah -o jsonpath='{.items[0].metadata.name}')
kubectl -n dpipot logs $POD -c wg-tunnel --tail=10
# expected: "ip link set mtu ... up dev wg-llm"
```

Force a response via the LLM (a path that doesn't match any static rule)
and confirm in the logs:

```bash
POD_IP=$(kubectl -n dpipot get pod -l app=galah -o jsonpath='{.items[0].status.podIP}')
curl -s -m 30 http://$POD_IP:8080/admin/config.php -o /dev/null
kubectl -n dpipot logs $POD -c galah --tail=5
# expected: "generated HTTP response: ..." and "sent the response to ... (source: llm)"
```

> [!NOTE]
> Testing with `curl` straight from the **host itself** to the
> `hostIP:hostPort` (e.g. `<HONEYPOT_WG_IFACE_IP>:8080`) can return
> "empty reply" even when everything is working — it's a self-test
> artifact (the traffic becomes local loopback instead of going through
> the real ingress path). The only conclusive validation comes from
> **another host** on the honeypot network (the real remote
> `dpipot-proxy`).

Confirm DNS/internet isolation is actually in effect — `galah` attempts
a reverse-DNS enrichment lookup by default; it **should fail**:

```bash
kubectl -n dpipot logs $POD -c galah --tail=10 | grep -i "lookup"
# expected: "i/o timeout" — if it resolves, the NetworkPolicy isn't applying
```

---

## Quick reference — differences vs. a full node (proxy + honeypots)

| Item | Full node (Rocky/Ubuntu/Debian) | Standalone honeypot (this guide) |
|---|---|---|
| `dpipotProxy` | Enabled (DaemonSet, `hostNetwork: true`) | Disabled |
| CNI | Flannel (k3s default) or Calico | Cilium (`kubeProxyReplacement`) |
| Honeypot exposure | `ClusterIP`, consumed by the local `dpipot-proxy` | `hostPort`+`hostIP`, consumed by a remote `dpipot-proxy` via WireGuard |
| `NetworkPolicy` | `honeypots-isolation` (allows general DNS + external LLM) | `honeypot-full-isolation` (denies everything, exception only for galah's tunnel) |
| `galah`'s LLM backend | Direct via the admin mesh (`OPENAI_API_BASE` points at the LLM's IP) | Via its own WireGuard tunnel `wg-llm`, inside the pod (`wgTunnel.enabled`) |
| `heralding` port 80 | Always enabled, no conflict (own ClusterIP) | Disabled if `wordpot` also shares the same `hostIP` |

---

## Troubleshooting checklist (symptom → likely cause)

| Symptom | Likely cause | Where to check |
|---|---|---|
| `coredns`/`local-path-provisioner`/`metrics-server` in `CrashLoopBackOff`, `i/o timeout` reaching the API's `ClusterIP` | k3s installed without `--disable-kube-proxy` (fights Cilium's `kubeProxyReplacement`) | Step 4 |
| Same symptom above, but already with `--disable-kube-proxy` | Cilium auto-detected too many interfaces (`devices`) | Step 5 |
| Same symptom above, but Cilium's `devices` is correct | `ufw` with a `deny` policy on `FORWARD` | Step 6 |
| `galah`'s PVC stays `Pending` forever | Wrong `storageClass` (`microk8s-hostpath` only exists on MicroK8s) — use `local-path` on k3s | Step 10 |
| `heralding` or `wordpot` pod stuck `Pending` with `didn't have free ports` | Port 80 conflict between the two on the same `hostIP` | Step 10 |
| `galah`'s `initContainer` hangs on `apk add`/stuck `ContainerCreating` | Pod already under a no-internet `NetworkPolicy` — `apk` never resolves | Step 8 |
| `galah` only ever responds with static rules, never via the LLM | Tested path matches the `^/$`/another static rule in `rules.yaml` — try a different path | Step 12 |
| `curl` from the host itself to the honeypot's `hostIP:hostPort` gives "empty reply" but the pod's log shows it responded | Loopback self-test, not the real ingress path — test from another host on the honeypot network | Step 12 (note) |
| `galah` can resolve DNS (lookup succeeds) when it shouldn't | `honeypot-full-isolation` NetworkPolicy wasn't applied, or wrong `podSelector`/namespace | Step 10, Step 12 |
