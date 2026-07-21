# Installing dpipot-ng on Ubuntu Server (k3s)

This guide documents installing dpipot-ng on an **Ubuntu Server 24.04+** node
using **k3s**, incorporating the fixes discovered during distro-compatibility
testing. Following this order, the bugs described below **should not occur**
— every step is already fixed up front instead of being patched after the
fact.

If you're migrating from a Rocky Linux/RHEL node, check the differences
table at the end of this document before starting.

## Conventions used in this guide

The host has (at least) two network interfaces with different roles:

- **Data plane** (`<DATA_IFACE>`, e.g. `eth0`/`ens192`): the interface
  exposed to the internet, where attacker/scanner traffic arrives. This is
  the interface dpipot's TPROXY intercepts.
- **Control plane** (`<CTRL_IFACE>` / `<CTRL_CIDR>`, e.g. `wg0`, range
  `10.X.X.0/24`): the management/VPN network — administrative access (SSH),
  cluster traffic (API server, kubelet), and, if applicable, the path to a
  central Elasticsearch/observability stack outside the cluster.

Replace `<DATA_IFACE>`, `<CTRL_IFACE>`, `<CTRL_CIDR>`, and the example IPs
with the real values for your environment in every command below.

> [!CAUTION]
> **Don't assume which interface has the internet route just from the IP
> type** (public vs. private/RFC1918). In at least one tested environment,
> the interface with the public IP (`<DATA_IFACE>`) **had no default route
> at all** — the "management" interface was the one that reached the
> internet. Always confirm with the command below before writing any
> firewall rule or route, instead of trusting the naming convention:
> ```bash
> ip route get 8.8.8.8
> # the "via ... dev <interface>" line shows the real egress interface
> ```

---

## Step 1 — Trim the OS (optional, recommended on small VMs)

```bash
# inventory of what's running BEFORE changing anything — you'll compare
# against this again in Step 7.
systemctl list-units --type=service --state=running
sudo ss -tlnp
df -h /
free -h

# common candidates to remove on a honeypot VM (confirm each one is
# actually present/active/unused on your specific image before removing):

# snapd: if no snap is installed, the daemon runs idle (~40MB RSS)
snap list                                    # if empty, remove it:
sudo apt-get purge -y snapd lxd-installer

# multipath-tools: only useful with real multipath storage (SAN/iSCSI)
lsblk                                        # if there's a single disk, remove it:
sudo apt-get purge -y multipath-tools

sudo apt-get autoremove -y
```

> [!TIP]
> Take this chance to check whether a newer kernel is available (removing
> the packages above sometimes forces an `initramfs`/kernel update) and
> reboot now, while the VM is still empty — better than finding out later
> with workloads running:
> ```bash
> apt list --upgradable 2>/dev/null | grep linux-image
> sudo reboot   # if a newer kernel is available
> uname -r      # confirm after rebooting
> ```

---

## Step 2 — Permissions and SSH access

```bash
# confirm passwordless sudo (or with password, document which):
sudo -n true && echo "sudo without password" || echo "sudo asks for a password"
```

If it asks for a password, set up a dedicated NOPASSWD entry (avoid running
`visudo` directly over an SSH session with no second backup access open):
```bash
echo '<user> ALL=(ALL) NOPASSWD:ALL' | sudo tee /etc/sudoers.d/90-<user>
```

Generate a dedicated SSH key to administer this host, instead of reusing a
key from another node:
```bash
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519_<node-name> -C "access-<node-name>"
# authorize the public key on the host (console/cloud-init/manual authorized_keys)
```

---

## Step 3 — AppArmor: quick check, no action expected

Ubuntu uses **AppArmor**, not SELinux. Across all tests performed, AppArmor
**never** blocked TPROXY nor the classifier's `AF_PACKET` capture — no
problem is expected here, but it's worth confirming that no
container-related profile is in a restrictive `enforce` mode before moving
on:

```bash
sudo aa-status
```

If something looks like an AppArmor block further along, confirm before
disabling any profile:
```bash
sudo dmesg | grep -i apparmor | grep -i denied
```

---

## Step 4 — Base packages missing from the minimal image

```bash
sudo apt-get update
sudo apt-get install -y tar curl git iptables ufw tcpdump conntrack
```
`tar`/`curl` usually already ship with the base image — still worth
confirming, since other distros taught us not to assume this. `iptables`,
`ufw`, `tcpdump`, and `conntrack` are commonly missing and are needed in the
steps below (k3s expects the `iptables` binary available on the host;
`tcpdump`/`conntrack` are this guide's debugging tools).

---

## Step 5 — sysctls: apply everything *before* the deploy, persistently

### 5.1 — Disable IPv6 (if there's no real IPv6 connectivity)

**Root cause:** the proxy's init container runs `apk add iptables iproute2`
inside an Alpine image. If the host has no real IPv6 route, `apk` tries to
resolve the mirrors over IPv6, gets a `temporary error`, and the package
install fails — leaving the pod stuck in `Init:Error` on a backoff loop.
Confirm you have real IPv6 before disabling it:

```bash
ip -6 addr show | grep -v 'scope link\|scope host'   # empty = no real global IPv6
```

If it comes back empty, disable it:
```bash
sudo tee /etc/sysctl.d/98-dpipot-disable-ipv6.conf << 'EOF'
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 0
EOF
sudo sysctl --system
```

### 5.2 — `rp_filter` and forwarding

Unlike Rocky/NetworkManager (which overrides `rp_filter` per interface,
requiring an interface-by-interface fix), Ubuntu with
`netplan`+`systemd-networkd` typically already ships `rp_filter=2` (loose
mode) by default on every interface — compatible with the asymmetric
routing TPROXY produces. Still, **confirm, don't assume**:

```bash
for i in /proc/sys/net/ipv4/conf/*/rp_filter; do echo "$i: $(cat $i)"; done
```
If any interface shows `1` (strict), zero it explicitly:
```bash
sudo tee /etc/sysctl.d/98-dpipot-tproxy.conf << 'EOF'
net.ipv4.ip_forward=1
net.ipv4.conf.all.rp_filter=0
net.ipv4.conf.default.rp_filter=0
net.ipv4.conf.<DATA_IFACE>.rp_filter=0
net.ipv4.conf.<CTRL_IFACE>.rp_filter=0
EOF
sudo sysctl --system
```

---

## Step 6 — Install k3s, already bound to the control plane

Install k3s pinning the apiserver and kubelet to the **control plane**
interface from the start. This keeps every cluster management service off
the data/internet interface — which in turn makes blocking ports
6443/10250 in the firewall (Step 9) just defense in depth, not the only
protection.

dpipot doesn't use Ingress or LoadBalancer — disable both to save resources:

```bash
curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC="\
  --disable=traefik --disable=servicelb \
  --bind-address=<CTRL_IFACE_IP> \
  --node-ip=<CTRL_IFACE_IP> \
  --tls-san=<CTRL_IFACE_IP> \
" sh -

sudo k3s kubectl get nodes   # confirm Ready
```

### 6.1 — kubeconfig

**Unlike MicroK8s:** k3s's `kubectl` is a symlink to the `k3s` binary
itself, which by default always tries to read `/etc/rancher/k3s/k3s.yaml`
(readable only by root), ignoring `~/.kube/config` even if it exists.

```bash
mkdir -p ~/.kube
sudo cp /etc/rancher/k3s/k3s.yaml ~/.kube/config
sudo chown $(id -u):$(id -g) ~/.kube/config
chmod 600 ~/.kube/config

echo 'export KUBECONFIG=$HOME/.kube/config' >> ~/.bashrc
export KUBECONFIG=$HOME/.kube/config
```

> [!WARNING]
> A `sudo systemctl restart k3s` **recreates** `/etc/rancher/k3s/k3s.yaml`
> with `600` root-only permissions — if you restart the service later,
> you'll need to copy the file to `~/.kube/config` again (hence the copy
> above, instead of just chmod'ing the original file).

Since the apiserver only listens on the control-plane IP, adjust the
kubeconfig:
```bash
sed -i "s/127.0.0.1/<CTRL_IFACE_IP>/" ~/.kube/config
kubectl get nodes
```

### 6.2 — Install Helm (not bundled with k3s)

```bash
curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
```

---

## Step 7 — Clone the repository

```bash
git clone --branch <desired-branch> https://github.com/spawnzao/dpipot-ng.git ~/dpipot-ng
cd ~/dpipot-ng
```

---

## Step 8 — Hardening: nothing management-related exposed on the data plane

> [!CAUTION]
> **Opening firewall rules without first confirming which ports/services
> are actually listening on the server is a serious security hole.** Step 9
> of this guide opens up TCP broadly on the data-plane interface — that's
> only safe once you've confirmed, as we do here, that **no real management
> service** (administrative SSH, cluster API, kubelet) responds on that
> interface.

### 8.1 — Confirm k3s is already restricted (done in Step 6)

```bash
sudo ss -tlnp | grep -E ':6443|:10250'
```
Both should only show up on the control-plane IP, never on `0.0.0.0` nor on
the data-plane IP.

### 8.2 — Restrict the real `sshd` to the control plane

> [!CAUTION]
> **Ubuntu 24.04+ enables socket activation for SSH by default**
> (`ssh.socket`). This means the **socket**, not `sshd`, binds port 22 — and
> the socket **completely ignores** `sshd_config`'s `ListenAddress`. If you
> only edit `sshd_config.d` and restart `ssh.service`, the restriction
> looks applied (`sshd -t` validates without error), but the actual process
> keeps listening on `0.0.0.0` — a false sense of security. **Disable the
> socket first:**

```bash
sudo systemctl disable --now ssh.socket
sudo systemctl enable --now ssh.service

sudo tee /etc/ssh/sshd_config.d/99-restrict-listen.conf << EOF
ListenAddress <CTRL_IFACE_IP>
ListenAddress <OTHER_MANAGEMENT_IPS_IF_ANY>
EOF

sudo sshd -t && echo "config OK"   # always validate before restarting
sudo systemctl restart ssh.service

# validate with a NEW connection before closing the current session:
ssh -o ConnectTimeout=5 user@<CTRL_IFACE_IP> "echo ok"
```

Confirm:
```bash
ss -tlnp | grep :22   # 0.0.0.0:22 should not appear
```

### 8.3 — Review the service inventory from Step 1

Go back to the list of services/ports you gathered in Step 1 and remove or
restrict any other management service still listening broadly before
moving to Step 9. General rule: **the only traffic that should reach the
data-plane interface is what dpipot's TPROXY is going to intercept.**

---

## Step 9 — `ufw`: open up what the honeypot needs

> [!NOTE]
> `ufw` **has no concept of zones** like firewalld, but it **has the same
> default-deny-for-routed-traffic trap** (`routed: deny` by default) —
> which specifically affects traffic that **pods** try to route outward
> (internet, or an external VPN like a central Elasticsearch), not the
> host's own traffic. Without steps 9.2/9.3 below, the deploy will look
> stuck (proxy's init container `Init:Error` trying to `apk add`, Logstash
> unable to reach ES) even with `ufw` "open" for inbound traffic.

### 9.1 — Base policy and opening the data-plane interface

```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing

sudo ufw allow in on <CTRL_IFACE> to any port 22 proto tcp

# optional (defense in depth — Step 6/8 already restricts this at the source):
sudo ufw deny in on <DATA_IFACE> to any port 6443 proto tcp
sudo ufw deny in on <DATA_IFACE> to any port 10250 proto tcp
```

> [!WARNING]
> Confirm Step 8 (no management service exposed) **before** running the
> command below. It opens up **all inbound TCP** on the data-plane
> interface — if any management service is still listening there at this
> point, this rule exposes it directly to the internet.

```bash
sudo ufw allow in on <DATA_IFACE> proto tcp
sudo ufw --force enable
```

### 9.2 — Allow pod-to-internet routing

Needed for the proxy's init container to `apk add` packages, and for any
honeypot/component that needs to resolve DNS or reach the internet.

```bash
# use the interface that ACTUALLY has the default route (confirmed at the
# start of this guide with `ip route get 8.8.8.8`) — don't assume it's the
# data-plane interface:
sudo ufw route allow in on cni0 out on <INTERFACE_WITH_DEFAULT_ROUTE>
sudo ufw route allow in on flannel.1 out on <INTERFACE_WITH_DEFAULT_ROUTE>
sudo ufw reload
```

> [!NOTE]
> The chart already ships a `NetworkPolicy` (`honeypots-isolation`) that
> restricts **honeypot** egress to DNS only (UDP port 53) — this is
> intentional (compromised honeypots shouldn't be able to pivot to the
> internet), not a bug. The `dpipot-proxy`/`kafka`/`logstash`/`filebeat`
> components are excluded from this policy and have unrestricted egress. If
> you're debugging connectivity with a one-off test pod (`kubectl run debug
> ...`), remember it **also** falls under this restriction since it lacks
> the right labels — that doesn't indicate a real networking bug.

### 9.3 — If Logstash/Kafka needs to reach an external service (e.g. a
central Elasticsearch) over a dedicated VPN interface

```bash
sudo ufw route allow in on cni0 out on <VPN_ES_IFACE>
sudo ufw route allow in on flannel.1 out on <VPN_ES_IFACE>
sudo ufw reload
```

**Debug command** — if a specific port or flow isn't working, pinpoint
exactly where the packet gets dropped by zeroing the counters before the
test:
```bash
sudo iptables -Z FORWARD
# generate the test traffic (e.g. from inside a pod: wget/curl/ping)
sudo iptables -L FORWARD -n -v --line-numbers    # see which numbered rule incremented
```
If the packet never shows up on any physical interface (`sudo tcpdump -i
any -n <filter>`), the drop is local (FORWARD, NAT/masquerade, or a
`NetworkPolicy`) — don't suspect TPROXY or external networking before
confirming this.

---

## Step 10 — Node-specific values override

k3s's default `storageClass` is `local-path` (from
`local-path-provisioner`), **different** from MicroK8s's
`microk8s-hostpath` — always override it explicitly.

```yaml
# k8s/chart/values-<node-name>.yaml
# Keep this file LOCAL (not committed) — see .gitignore under k8s/chart/

kafka:
  enabled: true
  persistence:
    enabled: true
    size: "10Gi"
    storageClass: "local-path"
  heapOpts: "-Xmx512m -Xms512m"

network:
  interface: "<DATA_IFACE>"

# Adjust based on the VM's available RAM — k3s has much lower overhead than
# MicroK8s (measured around ~670MB vs. ~2.4GB), leaving more RAM for the
# application even on small VMs (4GB or less).
resources:
  logstash:
    heapOpts: "-Xmx512m -Xms512m"
    requests: { cpu: 200m, memory: 640Mi }
    limits:   { cpu: 500m, memory: 1Gi }
  kafka:
    requests: { cpu: 200m, memory: 640Mi }
    limits:   { cpu: 500m, memory: 896Mi }
```

> [!TIP]
> If the VM has little RAM (4GB or less), track real usage for a few days
> before treating the sizing as final (`kubectl top pods -n dpipot`, `free
> -h`) — `requests`/`limits` numbers are a theoretical ceiling, not actual
> usage.

---

## Step 11 — Namespace, secrets, ghcr-secret

```bash
kubectl create namespace dpipot

# required even with public images (kubelet requires the secret referenced
# in the chart, even if its content is a dummy):
kubectl create secret generic ghcr-secret --type=kubernetes.io/dockerconfigjson \
  --from-literal=.dockerconfigjson='{"auths":{}}' -n dpipot

kubectl apply -f k8s/secrets/logstash-secrets.yaml -f k8s/secrets/galah-secrets.yaml -n dpipot
```

---

## Step 12 — Deploy

```bash
helm upgrade --install dpipot k8s/chart/ \
  -f k8s/chart/values-<node-name>.yaml \
  --namespace dpipot --create-namespace
```

---

## Step 13 — Final verification

```bash
kubectl get pods -n dpipot -o wide          # all Running/Ready
kubectl logs -n dpipot -l app=dpipot-proxy --tail=50
sudo nft list table ip mangle               # should show the TPROXY chain with counter > 0 as traffic arrives
kubectl logs -n dpipot -l app=logstash --tail=50 | grep -i elasticsearch   # should show "Restored connection"/"version determined"
```

External connectivity test **from another machine** (not from the host
itself — loopback doesn't go through TPROXY's real path):
```bash
# from another machine, one per port configured in the honeypot:
nc -zv <NODE_PUBLIC_IP> 22
nc -zv <NODE_PUBLIC_IP> 80
# (Windows) Test-NetConnection -ComputerName <NODE_PUBLIC_IP> -Port 80
```

If a port doesn't respond, use the debug command from Step 9.3 before
suspecting TPROXY itself — in practice, the root cause has usually been in
the firewall/routing, not the proxy.

---

## Quick reference — Rocky/RHEL vs Ubuntu differences

| Item | Rocky/RHEL | Ubuntu |
|---|---|---|
| SELinux/AppArmor | SELinux Enforcing — needs `container-selinux`+`k3s-selinux` before k3s | AppArmor — never blocked anything in testing, no action needed |
| Firewall | `firewalld`, zones, default-deny per zone | `ufw`, no zones — **same default-deny trap for pod-routed traffic** |
| Network manager | NetworkManager — overrides `rp_filter` per interface | netplan/systemd-networkd — usually already in loose mode (`2`), no override |
| SSH | `ListenAddress` works directly | **24.04+ uses socket activation** — must disable `ssh.socket` first |
| Missing minimal packages | `tar`, `git` | `iptables`, `ufw`, `tcpdump`, `conntrack`, `git` (varies by image) |
| Reserved-RAM trimming | `kdump`/crashkernel (200-500MB) | `snapd`/`multipath-tools`/`lxd-installer` with no real use (~40-70MB) |
| Default storageClass | `local-path` | `local-path` (same, both k3s) |

---

## Troubleshooting checklist (symptom → likely cause)

| Symptom | Likely cause | Where to check |
|---|---|---|
| sshd's `ListenAddress` looks applied but the port still shows on `0.0.0.0` | `ssh.socket` active and doing the bind, ignoring `sshd_config` | Step 8.2 — `systemctl is-active ssh.socket` |
| Proxy's init container fails with `apk`/`temporary error` fetching packages | No real IPv6, `apk` trying to resolve over IPv6 | Step 5.1 |
| Pod can't reach the internet (`apk add`, external DNS, etc.), but the host can | `ufw` blocking routed traffic (`routed: deny`) without an explicit `ufw route allow` rule | Step 9.2 |
| Pod can't reach an external service over VPN, "no route to host"/timeout but the host can ping it | Same cause as above, but for the VPN interface | Step 9.3 |
| A one-off test pod has no internet access, but the real `dpipot-proxy` works fine | Intentional behavior of the `honeypots-isolation` NetworkPolicy (DNS-only egress for pods outside the exception list) | Step 9.2 (note) |
| Assumption about which interface "is the internet one" was wrong | A public IP doesn't imply a default route is configured on that interface | Start of this guide — `ip route get 8.8.8.8` |
| `kubectl` stops working after Step 6 | kubeconfig still points to `127.0.0.1` after the apiserver was restricted to the control plane | Step 6.1 |
| `kubectl`/`helm` throw permission errors again after restarting k3s | `systemctl restart k3s` recreates `/etc/rancher/k3s/k3s.yaml` with `600` permissions | Step 6.1 — copy to `~/.kube/config` again |
| TPROXY marks the packet (`iptables -t mangle` counter increments) but never delivers to the app | Strict `rp_filter` on some interface along the path | Step 5.2 |
