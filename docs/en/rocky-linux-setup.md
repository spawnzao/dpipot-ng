# Installing dpipot-ng on Rocky Linux (k3s)

This guide documents installing dpipot-ng on a **Rocky Linux / RHEL 9** node
using **k3s** instead of MicroK8s, incorporating the fixes discovered during
distro-compatibility testing. Following this order, the bugs described below
**should not occur** — every step is already fixed up front instead of being
patched after the fact.

If you're migrating from an Ubuntu/MicroK8s node, check the differences
table at the end of this document before starting.

## Conventions used in this guide

The host has (at least) two network interfaces with different roles:

- **Data plane** (`<DATA_IFACE>`, e.g. `eth0`/`ens18`): the interface exposed
  to the internet, where attacker/scanner traffic arrives. This is the
  interface dpipot's TPROXY intercepts.
- **Control plane** (`<CTRL_IFACE>` / `<CTRL_CIDR>`, e.g. `wg0`, range
  `10.X.X.0/24`): the management/VPN network — administrative access (SSH),
  cluster traffic (API server, kubelet), and, if applicable, the path to a
  central Elasticsearch/observability stack outside the cluster.

Replace `<DATA_IFACE>`, `<CTRL_IFACE>`, `<CTRL_CIDR>`, and the example IPs
with the real values for your environment in every command below.

---

## Step 1 — Trim the OS (optional, recommended on small VMs)

Do this **before** installing anything else, because removing `kdump`
requires a reboot.

```bash
# kdump reserves a fixed chunk of memory for the crashkernel (200-500MB
# depending on RAM size) — not needed on a honeypot VM.
sudo systemctl disable --now kdump.service
sudo dnf remove -y kexec-tools

# Check the CURRENT crashkernel string before removing anything — removing
# kexec-tools can regenerate the grub config and CHANGE the string, which
# would invalidate a --remove-args call made with the old value.
cat /proc/cmdline | grep -o 'crashkernel=[^ ]*'
sudo grubby --remove-args="crashkernel=<value-found-above>" --update-kernel=ALL

# sssd is usually unused (no domain/realm configured) on this kind of host —
# avoids unnecessary boot overhead.
sudo systemctl disable sssd

sudo reboot
```

After the reboot, confirm:
```bash
cat /proc/cmdline   # should no longer contain "crashkernel="
free -h              # total RAM should have gone up
```

> [!TIP]
> Use this moment to take an inventory of what's running on the host before
> moving forward: `systemctl list-units --type=service --state=running`
> and `sudo ss -tlnp`. You'll use this list again in Step 7 to confirm
> nothing beyond what's necessary ended up exposed.

---

## Step 2 — SELinux: install the policies **before** k3s

RHEL/Rocky runs with SELinux **Enforcing** by default. Installing k3s
without the correct policies already in place causes failures in common
container operations (not just TPROXY).

```bash
sudo dnf install -y container-selinux

sudo dnf config-manager --add-repo=https://rpm.rancher.io/k3s/stable/common/centos/9/noarch/
sudo rpm --import https://rpm.rancher.io/public.key
sudo dnf install -y k3s-selinux
```

**Do not disable SELinux.** Across every test performed, SELinux Enforcing
**never** was the cause of any dpipot issue (TPROXY with `privileged: true`/
`NET_ADMIN` and raw `AF_PACKET` capture both work normally under Enforcing,
as long as the policies above are installed). If something looks like an
SELinux problem, confirm it before disabling anything:
```bash
sudo ausearch -m avc -ts recent   # empty output means SELinux isn't the cause
```

---

## Step 3 — Base packages missing from the minimal image

Minimal Rocky/RHEL cloud images ship without `tar` or `git` — both are
needed later on (the Helm installer needs `tar`; cloning the repo needs
`git`).

```bash
sudo dnf install -y tar git
```

---

## Step 4 — sysctls: apply everything *before* the deploy, persistently

This is the step that prevents most of the TPROXY networking problems. Do
this now, instead of fixing it after the deploy has already failed.

### 4.1 — Per-interface `rp_filter`

**Root cause:** Rocky's NetworkManager sets `rp_filter=1` (strict) per
interface, and this is **not overridden** just by setting
`net.ipv4.conf.all.rp_filter`/`net.ipv4.conf.default.rp_filter` (unlike
Ubuntu/netplan, where that's enough). A strict `rp_filter` on the data-plane
interface silently drops packets already marked by TPROXY before they reach
the application's transparent socket — TPROXY appears to "work" for some
ports (any port that also happens to have another real service listening,
like SSH) and silently fails for the rest.

```bash
sudo tee /etc/sysctl.d/98-dpipot-tproxy.conf << 'EOF'
net.ipv4.ip_forward=1
net.ipv4.conf.all.rp_filter=0
net.ipv4.conf.default.rp_filter=0
net.ipv4.conf.<DATA_IFACE>.rp_filter=0
net.ipv4.conf.<CTRL_IFACE>.rp_filter=0
net.ipv4.conf.lo.rp_filter=0
net.ipv4.conf.cni0.rp_filter=0
net.ipv4.conf.flannel.1.rp_filter=0
EOF
sudo sysctl --system
```

### 4.2 — Dynamic interfaces (`veth*`, one per pod)

k3s/containerd creates a new `veth*` interface for every pod, and
NetworkManager applies `rp_filter=1` to each new one — a static entry in
`sysctl.d` (step 4.1) doesn't cover interfaces that don't exist yet. The
robust way to fix this **once and for all**, without manually patching it
for every new pod, is to tell NetworkManager not to manage these interfaces:

```bash
sudo tee /etc/NetworkManager/conf.d/99-k3s-cni-unmanaged.conf << 'EOF'
[keyfile]
unmanaged-devices=interface-name:cni0;interface-name:flannel.1;interface-name:veth*
EOF
sudo systemctl reload NetworkManager
```

With this in place, these interfaces inherit `net.ipv4.conf.default.rp_filter`
(already zeroed in step 4.1) instead of getting NetworkManager's default
override.

**Debug command to confirm** (run this if you suspect TPROXY is only
partially working):
```bash
for i in /proc/sys/net/ipv4/conf/*/rp_filter; do echo "$i: $(cat $i)"; done | grep -v ': 0'
```
If this command prints nothing, every interface has `rp_filter=0`. Any
printed line is an interface that's still strict.

### 4.3 — `src_valid_mark`

Leave it at `0` (default). Explicitly setting it to `1` was tested during
this setup's diagnosis and it **broke** connections that were previously
working, without fixing anything — it is not required for dpipot's TPROXY to
work.

---

## Step 5 — Install k3s, already bound to the control plane

Install k3s pinning the apiserver, the kubelet, and the network overlay
(flannel) to the **control-plane** interface from the start. This keeps any
of these cluster management services from being reachable through the
data/internet interface — which, in turn, removes the need for firewall
rules to block ports 6443/10250 later (Step 8).

dpipot doesn't use Ingress or LoadBalancer — disable both to save resources:

```bash
curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC="\
  --disable=traefik --disable=servicelb \
  --bind-address=<CTRL_IFACE_IP> \
  --advertise-address=<CTRL_IFACE_IP> \
  --node-ip=<CTRL_IFACE_IP> \
  --flannel-iface=<CTRL_IFACE> \
  --kubelet-arg=address=<CTRL_IFACE_IP> \
" sh -

sudo k3s kubectl get nodes   # confirm Ready
```

> [!NOTE]
> `--flannel-iface` must point at the **control-plane** interface, not the
> data-plane one — this is the interface the cluster's node-to-node overlay
> traffic (VXLAN) travels over, and it has no reason to cross the
> internet-facing interface. If this cluster is single-node (no other
> workers), this doesn't affect functionality, but it's already correct for
> when you scale out.
>
> If this node ever needs to accept **other nodes** (workers) joining the
> cluster through the data-plane interface (a rare, generally discouraged
> scenario), don't apply `--bind-address`/`--advertise-address` — in that
> case, use firewall rules (Step 8) as the only line of defense.

### 5.1 — kubeconfig

**Unlike MicroK8s:** k3s's `kubectl` is a symlink to the `k3s` binary
itself, which by default always tries to read
`/etc/rancher/k3s/k3s.yaml` (readable only by root), ignoring
`~/.kube/config` even if it exists with the right permissions.

```bash
mkdir -p ~/.kube
sudo cp /etc/rancher/k3s/k3s.yaml ~/.kube/config
sudo chown $(id -u):$(id -g) ~/.kube/config
chmod 600 ~/.kube/config

echo 'export KUBECONFIG=$HOME/.kube/config' >> ~/.bashrc
export KUBECONFIG=$HOME/.kube/config
```

Since the apiserver now only listens on the control-plane IP (step 5), the
generated kubeconfig (which defaults to `127.0.0.1:6443`) needs adjusting:
```bash
sed -i "s/127.0.0.1/<CTRL_IFACE_IP>/" ~/.kube/config
kubectl get nodes   # confirm it still works with the new address
```

### 5.2 — Install Helm (not bundled with k3s)

```bash
curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
```

---

## Step 6 — Clone the repository

```bash
git clone --branch release/0.3 https://github.com/spawnzao/dpipot-ng.git ~/dpipot-ng
cd ~/dpipot-ng
```

---

## Step 7 — Hardening: no management surface exposed on the data plane

> [!CAUTION]
> **Opening firewall rules without first confirming which ports/services
> are actually listening on the server is a serious security hole.** Step 8
> of this guide opens TCP broadly on the data-plane interface — that's only
> safe once you've guaranteed, as we do here, that **no real management
> service** (administrative SSH, cluster API, kubelet) responds on that
> interface. Skipping this step and opening the firewall broadly would
> expose those services directly to the internet.

This step embodies the principle "don't expose what doesn't need to be
exposed," instead of relying only on edge blocking (which is fragile: a
badly written rule, a `firewalld --reload`, or a future reinstall can remove
the protection without warning).

### 7.1 — Confirm k3s is already restricted (done in Step 5)

```bash
sudo ss -tlnp | grep -E ':6443|:10250'
```
Both should only show up on the control-plane IP, never on `0.0.0.0` and
never on the data-plane IP.

### 7.2 — Restrict the real `sshd` to the control plane

dpipot's SSH honeypot (via TPROXY) and the system's real `sshd` listen on
the same port (22). If the real `sshd` keeps responding on the data-plane
interface, it creates ambiguity: if TPROXY ever goes down for any reason, an
external connection on port 22 could get answered by the real `sshd`
without that being obvious in tests — and, more seriously, it's a real
management port exposed to the internet.

```bash
sudo tee /etc/ssh/sshd_config.d/99-restrict-listen.conf << EOF
ListenAddress <CTRL_IFACE_IP>
ListenAddress <OTHER_MANAGEMENT_IPS_IF_ANY>
EOF

sudo sshd -t && echo "config OK"   # always validate before restarting
sudo systemctl restart sshd

# validate with a NEW connection before closing your current session:
ssh -o ConnectTimeout=5 user@<CTRL_IFACE_IP> "echo ok"
```

Confirm:
```bash
ss -tlnp | grep :22   # 0.0.0.0:22 should NOT appear
```

### 7.3 — Review the service inventory from Step 1

Go back to the list of services/ports you gathered in Step 1
(`systemctl list-units --type=service --state=running` and `ss -tlnp`) and
remove or restrict any other management service still listening broadly
(`cockpit`, admin dashboards, etc.) before moving on to Step 8. The general
rule: **the only traffic that should reach the data-plane interface is what
dpipot's TPROXY is meant to intercept.**

---

## Step 8 — firewalld: open only what the honeypot needs

The default firewalld zone (`public`) has a **default-deny** policy: it
only allows the explicitly listed services (`ssh`, `dhcpv6-client`,
`cockpit` by default). Any port outside that list is **silently rejected**,
even *after* TPROXY has already marked and redirected the packet correctly
in `mangle`. This is fundamentally incompatible with dpipot's architecture,
which needs to accept connections on arbitrary, not-pre-configured ports.

This differs from `ufw` (used in Ubuntu setups), which defaults to
permissive — that's why this bug is specific to firewalld hosts.

### 8.1 — Blocking 6443/10250: optional after Step 7

Since Step 7 already bound the apiserver and the kubelet exclusively to the
control plane, they **don't respond** on the data-plane interface regardless
of the firewall — the block below is an extra layer of defense (redundant,
but recommended as good defense-in-depth practice), not your only line of
protection:

```bash
sudo firewall-cmd --permanent --direct --add-rule ipv4 filter INPUT 0 -i <DATA_IFACE> -p tcp --dport 6443 -j REJECT
sudo firewall-cmd --permanent --direct --add-rule ipv4 filter INPUT 0 -i <DATA_IFACE> -p tcp --dport 10250 -j REJECT
```
Use `--direct` rules, not zone reassignment — moving a "live" interface
(with an active route) between zones makes NetworkManager reconfigure it,
which can break pod-network connectivity.

### 8.2 — Open TCP for the honeypot on the active zone

> [!WARNING]
> Confirm Step 7 (no management service exposed) **before** running the
> command below. It opens **all inbound TCP** on the active zone — if any
> management service is still listening on the data-plane interface at this
> point, this rule exposes it directly to the internet.

```bash
sudo firewall-cmd --permanent --zone=public --add-rich-rule='rule family="ipv4" protocol value="tcp" accept'
```

> **Trade-off:** if `<DATA_IFACE>` and `<CTRL_IFACE>` are in the same
> firewalld zone, this rule opens TCP on both — rich rules don't support
> matching by interface (the interface is what defines the zone, not a
> criterion within it). The `--direct` rules from step 8.1 remain valid and
> are terminal regardless of zone.

### 8.3 — If Logstash/Kafka needs to reach an external service (e.g. a
central Elasticsearch) over a dedicated VPN interface

Routed (*forwarded*) traffic from the host — pod → external service via VPN
— goes through firewalld's native `filter_FORWARD` chain, which is **also**
default-deny. If the VPN interface doesn't belong to any zone, that traffic
gets rejected even though the IP routing itself is working perfectly.

```bash
sudo firewall-cmd --permanent --zone=public --add-interface=<VPN_TO_ES_IFACE>
sudo firewall-cmd --reload
```

This automatically generates an `oifname "<VPN_TO_ES_IFACE>" accept` rule in
the zone's forward chain.

> [!CAUTION]
> A `firewall-cmd --reload` flushes `nft` tables not managed by firewalld
> (this includes the TPROXY `mangle` table created by the proxy's init
> container). **After any `--reload`, restart the proxy pod** to force the
> init container to recreate its setup:
> ```bash
> kubectl delete pod -n dpipot -l app=dpipot-proxy
> ```
> By doing steps 8.1–8.3 **before** the deploy (as this guide proposes), you
> avoid needing that `--reload` after TPROXY is already active.

**Debug command** — if a specific port isn't responding, trace the packet
live through every netfilter table/chain:
```bash
# install a temporary trace rule for a specific port
sudo iptables -t raw -A PREROUTING -i <DATA_IFACE> -p tcp --dport <PORT> -j TRACE
sudo nft monitor trace   # leave this running and generate traffic to that port
# remove the rule afterward:
sudo iptables -t raw -F PREROUTING
```
Look in the output for a `reject` or `drop` — it typically shows up in the
`inet firewalld filter_IN_<zone>` chain (firewalld rejection) or
`inet firewalld filter_FORWARD` (if it's routed traffic).

---

## Step 9 — Node-specific values override

k3s's default `storageClass` is `local-path` (from
`local-path-provisioner`), **different** from MicroK8s's
`microk8s-hostpath` — always override this explicitly.

```yaml
# k8s/chart/values-<node-name>.yaml
kafka:
  enabled: true
  persistence:
    enabled: true
    size: "10Gi"
    storageClass: "local-path"

network:
  interface: "<DATA_IFACE>"

image:
  proxy:
    tag: release-0.3
    pullPolicy: IfNotPresent
  classifier:
    tag: release-0.3
    pullPolicy: IfNotPresent

# Adjust based on available RAM on the VM — k3s has much lower overhead
# than MicroK8s (~670MB vs ~2.4GB measured in side-by-side tests), so more
# RAM is left over for the application even on small VMs.
resources:
  kafka:
    heapOpts: "-Xmx512m -Xms512m"
    requests: { cpu: 200m, memory: 640Mi }
    limits:   { cpu: 500m, memory: 896Mi }
  logstash:
    heapOpts: "-Xmx512m -Xms512m"
```

---

## Step 10 — Namespace, secrets, ghcr-secret

```bash
kubectl create namespace dpipot

# required even with public images (kubelet enforces the secret referenced
# in the chart, even if its content is a dummy):
kubectl create secret generic ghcr-secret --type=kubernetes.io/dockerconfigjson \
  --from-literal=.dockerconfigjson='{"auths":{}}' -n dpipot

kubectl apply -f k8s/secrets/logstash-secrets.yaml -f k8s/secrets/galah-secrets.yaml
```

---

## Step 11 — Deploy

```bash
helm upgrade --install dpipot k8s/chart/ \
  -f k8s/chart/values-<node-name>.yaml \
  --namespace dpipot --create-namespace
```

---

## Step 12 — Final verification

```bash
kubectl get pods -n dpipot -o wide          # all Running/Ready
kubectl logs -n dpipot -l app=dpipot-proxy -c proxy --tail=50
sudo ausearch -m avc -ts recent             # should be empty (no AVC denials)
sudo nft list table ip mangle               # should show the TPROXY chain, counter > 0 as traffic arrives
```

External connectivity test **from another machine** (not from the host
itself — loopback doesn't go through TPROXY's real path):
```bash
# from another machine, one per port configured in the honeypot:
nc -zv <NODE_PUBLIC_IP> 22
nc -zv <NODE_PUBLIC_IP> 80
# (Windows) Test-NetConnection -ComputerName <NODE_PUBLIC_IP> -Port 80
```

If any port doesn't respond, use the trace command from step 8.3 before
suspecting TPROXY itself — in practice, the root cause almost always turned
out to be firewalld, not the proxy.

---

## Quick reference — Ubuntu/MicroK8s vs Rocky/k3s differences

| Item | Ubuntu/MicroK8s | Rocky/k3s |
|---|---|---|
| k8s overhead (measured) | ~2.4GB (MicroK8s+Calico) | ~670MB (k3s+flannel+kube-router) |
| `kubectl` | always uses `~/.kube/config` | needs `export KUBECONFIG=~/.kube/config` |
| Default storageClass | `microk8s-hostpath` | `local-path` |
| Firewall | `ufw`, permissive by default | `firewalld`, **default-deny** per zone |
| SELinux | N/A (AppArmor) | Enforcing — needs `container-selinux`+`k3s-selinux` before k3s |
| `rp_filter` | `all`/`default=0` is enough | overridden per interface by NetworkManager — needs zeroing each interface (or `unmanaged-devices`) |
| Missing base packages | — | `tar`, `git` not included in the minimal cloud image |
| `kdump`/crashkernel | doesn't reserve RAM by default | reserves 200-500MB — remove on small VMs |

---

## Troubleshooting checklist (symptom → likely cause)

| Symptom | Likely cause | Where to check |
|---|---|---|
| Only the port matching a system service (e.g. 22/SSH) responds, everything else times out | firewalld rejecting on the zone (step 8.2) | `sudo nft list chain inet firewalld filter_IN_<zone>_allow`; trace from step 8.3 |
| All honeypot ports stop responding at once, right after a `firewall-cmd --reload` | reload flushed the TPROXY `mangle` table | `sudo nft list table ip mangle` (empty?) → restart the proxy pod |
| TPROXY marks the packet (`iptables -t mangle` counter increments) but it never reaches the app | strict `rp_filter` on some interface along the path | step 4.1/4.2, rp_filter debug command |
| Pod can't reach an external service over the VPN, "no route to host" but the host itself can ping it | firewalld FORWARD rejecting (VPN interface not in any zone) | step 8.3 |
| `kubectl` stops working after Step 5 | kubeconfig still points to `127.0.0.1` after the apiserver was restricted to the control plane | step 5.1 |
| Suspected AVC denial | almost never the actual cause — confirm before disabling SELinux | `sudo ausearch -m avc -ts recent` |
