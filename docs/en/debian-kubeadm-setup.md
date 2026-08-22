# Installing dpipot-ng on Debian (kubeadm + Calico)

This guide documents installing dpipot-ng on a **Debian 13 (trixie)** node
using **kubeadm + Calico** — the first time this OS/orchestrator
combination was tested in the project. Following this order, the bugs
described below **should not occur** — every step is already fixed up
front instead of being patched after the fact.

If you're migrating from a Rocky Linux/RHEL or Ubuntu node running **k3s**,
check the differences table at the end of this document before starting —
kubeadm behaves quite differently from k3s in several non-obvious ways
(port binding, control-plane taint, storage class).

## Conventions used in this guide

The host has (at least) two network interfaces with different roles:

- **Data plane** (`<DATA_IFACE>`, e.g. `ens18`/`ens32`): the interface
  exposed to the internet, where attacker/scanner traffic arrives. This is
  the interface dpipot's TPROXY intercepts.
- **Control plane** (`<CTRL_IFACE>` / `<CTRL_CIDR>`, e.g. `ens19`, range
  `10.X.X.0/24`): the management/VPN network — administrative access (SSH),
  cluster traffic (API server, kubelet), and, if applicable, the path to a
  central Elasticsearch/observability stack outside the cluster.

Replace `<DATA_IFACE>`, `<CTRL_IFACE>`, `<CTRL_CIDR>`, `<CTRL_IFACE_IP>`,
and the example IPs with the real values for your environment in every
command below.

> [!CAUTION]
> **Don't assume which interface has the internet route just from the IP
> type** (public vs. private/RFC1918). Always confirm with the command
> below before writing any firewall rule or route, instead of trusting the
> naming convention:
> ```bash
> ip route get 8.8.8.8
> # the "via ... dev <interface>" line shows the real egress interface
> ```

---

## Step 1 — Permissions, SSH access, and a quick audit

```bash
# inventory of what's running BEFORE changing anything — compare against
# this again after the deploy if you want to confirm nothing odd showed up:
systemctl list-unit-files --state=enabled --type=service
systemctl list-units --type=service --state=running
free -h

sudo -n true && echo "passwordless sudo" || echo "sudo asks for password"
```

If it asks for a password, set up a dedicated NOPASSWD entry:
```bash
echo '<user> ALL=(ALL) NOPASSWD:ALL' | sudo tee /etc/sudoers.d/90-<user>
```

Generate a dedicated SSH key to administer this host:
```bash
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519_<node-name> -C "access-<node-name>"
# authorize the public key on the host (console/cloud-init/manual authorized_keys)
```

> [!TIP]
> A minimal **Debian netinst** install already ships lean — in the tests
> done, there was no service equivalent to Rocky's `kdump`/`sssd` or
> Ubuntu's `snapd`/`multipath-tools` idling and consuming RAM. A separate
> "trim the OS" step, like the other guides have, isn't necessary here.

---

## Step 2 — AppArmor: quick check, no action expected

```bash
sudo aa-status
```
In the tests done, the only profiles in `enforce` mode were unrelated
utilities (`nvidia_modprobe`, `lsb_release`) — they never blocked TPROXY
nor the classifier's `AF_PACKET`. If something looks like an AppArmor
block later on, confirm before disabling any profile:
```bash
sudo dmesg | grep -i apparmor | grep -i denied
```

---

## Step 3 — Base packages missing from the minimal image

```bash
sudo apt-get update
sudo apt-get install -y git curl gpg apt-transport-https ca-certificates \
  conntrack ipset tcpdump
```

> [!NOTE]
> `software-properties-common` **doesn't exist** in Debian trixie's
> default repository — it isn't needed for this guide anyway (only used
> by `add-apt-repository`, which we don't use here). Don't try to install
> it.

### 3.1 — NTP: client missing by default

A minimal Debian netinst install **does not include** `systemd-timesyncd`
— `timedatectl set-ntp true` silently fails with `NTP not supported`. This
matters because the TLS certificates `kubeadm` generates are sensitive to
clock drift.

```bash
sudo apt-get install -y systemd-timesyncd
sudo systemctl enable --now systemd-timesyncd
timedatectl status | grep -i synchronized   # should say "yes"
```

---

## Step 4 — sysctls and kernel modules: apply everything *before* the deploy

### 4.1 — Disable IPv6 (if there's no real IPv6 connectivity)

**Root cause:** the proxy's init container runs `apk add iptables
iproute2` inside an Alpine image. If the host has no real IPv6 route,
`apk` tries to resolve the mirrors over IPv6, gets a `temporary error`,
and the package install fails — leaving the pod stuck in `Init:Error` in
a backoff loop. Confirm whether you have real IPv6 before disabling it:

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
```

### 4.2 — `rp_filter` and `rmem_max`

```bash
sudo tee /etc/sysctl.d/98-dpipot-tproxy.conf << EOF
net.ipv4.conf.all.rp_filter=0
net.ipv4.conf.default.rp_filter=0
net.ipv4.conf.<DATA_IFACE>.rp_filter=0
net.ipv4.conf.<CTRL_IFACE>.rp_filter=0
EOF

# avoids afpacket_drops under traffic bursts — the AF_PACKET socket asks
# for a 32MB SO_RCVBUF, but the kernel silently caps it at the default
# rmem_max (~208KB) unless raised explicitly:
sudo tee /etc/sysctl.d/99-dpipot.conf << 'EOF'
net.core.rmem_max=134217728
net.core.rmem_default=134217728
net.core.netdev_max_backlog=10000
EOF
```

### 4.3 — kubeadm/Calico requirements (not needed on k3s)

**Unlike k3s** (which already handles this internally), `kubeadm`
requires swap disabled and bridge kernel modules loaded manually:

```bash
sudo swapoff -a
sudo sed -i '/swap/s/^/#/' /etc/fstab   # comment out, don't remove — persists across reboot

sudo modprobe br_netfilter
sudo modprobe overlay
sudo tee /etc/modules-load.d/k8s.conf << 'EOF'
br_netfilter
overlay
EOF

sudo tee /etc/sysctl.d/97-kubernetes.conf << 'EOF'
net.bridge.bridge-nf-call-iptables=1
net.bridge.bridge-nf-call-ip6tables=1
net.ipv4.ip_forward=1
EOF

sudo sysctl --system
# confirm rp_filter=0 and disable_ipv6=1 on every interface before continuing
```

---

## Step 5 — Container runtime: containerd

```bash
sudo apt-get install -y containerd
sudo mkdir -p /etc/containerd
containerd config default | sudo tee /etc/containerd/config.toml > /dev/null

# systemd cgroup driver — avoids a mismatch with kubelet (which defaults
# to systemd on modern OSes, while containerd defaults to cgroupfs):
sudo sed -i 's/SystemdCgroup = false/SystemdCgroup = true/' /etc/containerd/config.toml
```

> [!CAUTION]
> **The Debian package's `containerd config default` points `bin_dir` at
> `/usr/lib/cni`**, but both the `kubernetes-cni` package (installed in
> Step 6) and Calico's `install-cni` (Step 8) use the universal path
> `/opt/cni/bin`. This mismatch hangs **every CNI pod** in
> `ContainerCreating`/`Init` with the error `failed to find plugin
> "calico" in path [/usr/lib/cni]`. Fix it **before** installing Calico:
> ```bash
> sudo sed -i 's|bin_dir = "/usr/lib/cni"|bin_dir = "/opt/cni/bin"|' /etc/containerd/config.toml
> ```

```bash
sudo systemctl restart containerd
sudo systemctl enable containerd
```

---

## Step 6 — Install kubeadm, kubelet, kubectl

> [!CAUTION]
> **The `v1.31` stream of the official `pkgs.k8s.io` repository has an
> OpenPGP signature incompatible with the `sqv` verifier's policy on
> Debian trixie** (rejected since `2026-02-01` with the error `Signature
> Packet v3 is not considered secure`). Use a more recent stream — check
> which stable version is actually available instead of assuming an
> older one will work:

```bash
sudo mkdir -p /etc/apt/keyrings
curl -fsSL https://pkgs.k8s.io/core:/stable:/v1.33/deb/Release.key | \
  sudo gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg
echo 'deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v1.33/deb/ /' | \
  sudo tee /etc/apt/sources.list.d/kubernetes.list
sudo apt-get update
sudo apt-get install -y kubelet kubeadm kubectl
sudo apt-mark hold kubelet kubeadm kubectl
```

### 6.1 — Fix `/etc/hosts` before `kubeadm init`

Installs done via the graphical installer/netinst often map the hostname
to the **public** IP in `/etc/hosts` — this makes `kubelet` report the
wrong `INTERNAL-IP` (the data IP, not the control one) after init. Fix it
first:

```bash
sudo sed -i "s/^<NODE_PUBLIC_IP>\s*<node-name>/<CTRL_IFACE_IP>\t<node-name>/" /etc/hosts
```

### 6.2 — `kubeadm init` with an explicit bind

> [!CAUTION]
> **Unlike k3s, kubeadm's `--apiserver-advertise-address` only affects the
> *advertised*/certificate address — it does not restrict the actual
> *bind*.** Without explicit configuration, the apiserver (6443) listens
> on `0.0.0.0` even with the advertise address set correctly, exposing
> the cluster API on the data interface. Use an explicit config file
> instead of just command-line flags:

```bash
sudo tee /tmp/kubeadm-config.yaml << EOF
apiVersion: kubeadm.k8s.io/v1beta4
kind: InitConfiguration
localAPIEndpoint:
  advertiseAddress: <CTRL_IFACE_IP>
  bindPort: 6443
nodeRegistration:
  kubeletExtraArgs:
    - name: node-ip
      value: <CTRL_IFACE_IP>
---
apiVersion: kubeadm.k8s.io/v1beta4
kind: ClusterConfiguration
networking:
  podSubnet: 192.168.0.0/16
apiServer:
  extraArgs:
    - name: bind-address
      value: <CTRL_IFACE_IP>
EOF

sudo kubeadm init --config /tmp/kubeadm-config.yaml

mkdir -p $HOME/.kube
sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
sudo chown $(id -u):$(id -g) $HOME/.kube/config
```

The `node-ip` above fixes the reported `INTERNAL-IP` and the apiserver's
bind — but **not** the kubelet's own bind (port 10250), which still
listens on `0.0.0.0` until the step below:

```bash
grep -q '^address:' /var/lib/kubelet/config.yaml && \
  sudo sed -i "s/^address:.*/address: <CTRL_IFACE_IP>/" /var/lib/kubelet/config.yaml || \
  echo "address: <CTRL_IFACE_IP>" | sudo tee -a /var/lib/kubelet/config.yaml
sudo systemctl restart kubelet

# confirm both only listen on the control IP, never 0.0.0.0:
sudo ss -tlnp | grep -E ':6443|:10250'
```

### 6.3 — Install Helm (doesn't ship with kubeadm)

```bash
curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
```

---

## Step 7 — Calico (CNI)

```bash
kubectl create -f https://raw.githubusercontent.com/projectcalico/calico/v3.28.0/manifests/tigera-operator.yaml
kubectl create -f https://raw.githubusercontent.com/projectcalico/calico/v3.28.0/manifests/custom-resources.yaml

kubectl get pods -n calico-system -w   # wait for all Running
```

If any pod stays stuck in `ContainerCreating`/`Init` with a "CNI plugin
not found" error, go back to Step 5 (containerd's `bin_dir`) — that's the
exact symptom of that bug.

### 7.1 — Remove the control-plane taint (single-node cluster)

**Unlike k3s**, `kubeadm` marks the control-plane as unschedulable by
default. On a single-node cluster, this prevents every dpipot pod from
running:

```bash
kubectl taint nodes --all node-role.kubernetes.io/control-plane- 2>&1 || true
kubectl get nodes -o wide   # should show Ready, no taints
```

### 7.2 — `local-path-provisioner` (doesn't ship with kubeadm)

**Unlike k3s** (which bundles `local-path-provisioner`), kubeadm ships no
`StorageClass` at all by default — without one, any
`PersistentVolumeClaim` (e.g. Kafka's) stays pending indefinitely.

```bash
kubectl apply -f https://raw.githubusercontent.com/rancher/local-path-provisioner/master/deploy/local-path-storage.yaml
kubectl patch storageclass local-path -p '{"metadata": {"annotations":{"storageclass.kubernetes.io/is-default-class":"true"}}}'
kubectl get storageclass   # "local-path" should show as (default)
```

---

## Step 8 — Clone the repository

```bash
git clone --branch <desired-branch> https://github.com/spawnzao/dpipot-ng.git ~/dpipot-ng
cd ~/dpipot-ng
```

---

## Step 9 — Hardening: no management exposed on the data interface

> [!CAUTION]
> **Opening firewall rules without first confirming which ports/services
> are actually listening on the server is a serious security gap.** This
> step is only safe once you've made sure, as we did in Step 6.2, that
> **no real management service** (administrative SSH, cluster API,
> kubelet) responds on the data interface.

### 9.1 — Restrict the real `sshd` to the control plane

```bash
sudo tee /etc/ssh/sshd_config.d/99-restrict-listen.conf << EOF
ListenAddress <CTRL_IFACE_IP>
ListenAddress <OTHER_MANAGEMENT_IPS_IF_ANY>
EOF

sudo sshd -t && echo "config OK"   # always validate before restarting
sudo systemctl restart ssh

# validate with a NEW connection before closing the current session:
ssh -o ConnectTimeout=5 user@<CTRL_IFACE_IP> "echo ok"
ss -tlnp | grep :22   # 0.0.0.0:22 should not appear
```

### 9.2 — `nftables` baseline

Debian uses neither `firewalld` nor `ufw` by default — with no rules
active, the host is fully permissive (which is already enough for TPROXY
to work, since it needs to accept any TCP port on the data interface).
Add just one extra layer of defense-in-depth, explicitly blocking the
cluster's management ports on the public interface (even though Step 6.2
already restricts them at the source):

```bash
sudo tee /etc/nftables.conf << 'EOF'
#!/usr/sbin/nft -f
flush ruleset

table inet dpipot_filter {
    chain input {
        type filter hook input priority 0; policy accept;
        iifname "<DATA_IFACE>" tcp dport { 6443, 10250 } reject
    }
}
EOF
sudo nft -f /etc/nftables.conf
sudo systemctl enable nftables.service
```

> [!NOTE]
> Once Calico/kube-proxy write their own tables (`iptables-nft`), it's
> normal to see the warning `table ip mangle is managed by iptables-nft,
> do not touch!` when listing the ruleset — that doesn't indicate a
> conflict, the tables coexist fine.

---

## Step 10 — Node-specific values override

```yaml
# k8s/chart/values-<node-name>.yaml
# Keep this file LOCAL (not committed) — see .gitignore under k8s/chart/

network:
  interface: "<DATA_IFACE>"

kafka:
  enabled: true
  persistence:
    enabled: true
    size: "10Gi"
    storageClass: "local-path"

resources:
  kafka:
    heapOpts: "-Xmx768m -Xms768m"
    requests: { cpu: 200m, memory: 900Mi }
    limits:   { cpu: 500m, memory: 1536Mi }
  logstash:
    heapOpts: "-Xmx512m -Xms512m"
  cowrie:
    requests: { cpu: 100m, memory: 256Mi }
    limits:   { cpu: 1000m, memory: 1Gi }

config:
  # On the unified binary (dev branch), publishing nDPI events is
  # opt-in — without this, the dpipot-classifier-* ES index stays empty.
  NDPI_EVENTS_ENABLED: "true"
```

> [!WARNING]
> Always put `heapOpts` **inside** the `resources.<component>` block. A
> top-level `heapOpts` (outside `resources:`) is silently ignored by the
> chart — this has happened in production before.

If this node will **not** run the `galah` honeypot (for example, because
it has no GPU/LLM available), disable it and re-point the route:
```yaml
honeypots:
  galah:
    enabled: false
config:
  HONEYPOT_ROUTES: "HTTP=wordpot-svc:80, TLS=wordpot-svc:80, HTTP_AUTH=heralding:80, HTTP_SUSPECT=heralding:80, SSH=cowrie-svc:22, ..."
```

---

## Step 11 — Namespace, secrets, ghcr-secret

```bash
kubectl create namespace dpipot

# required even with public images (kubelet enforces the secret referenced
# in the chart, even if its content is a dummy):
kubectl create secret generic ghcr-secret --type=kubernetes.io/dockerconfigjson \
  --from-literal=.dockerconfigjson='{"auths":{}}' -n dpipot

kubectl apply -f k8s/secrets/logstash-secrets.yaml -n dpipot
# + galah-secrets.yaml, if this node will run galah
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
sudo nft list ruleset | grep -A5 TEST-TPROXY   # counter should climb as traffic arrives

# don't rely on grepping the log's text to validate Logstash → ES — the
# connection banner may never show up on stdout even while working fine.
# Check the Kafka consumer group's lag instead:
kubectl exec -n dpipot deploy/kafka -- /opt/kafka/bin/kafka-consumer-groups.sh \
  --bootstrap-server localhost:9092 --describe --group logstash-consumer
```

External connectivity test **from another machine** (not the host itself):
```bash
nc -zv <NODE_PUBLIC_IP> 22
nc -zv <NODE_PUBLIC_IP> 80
```

If a port doesn't respond, check whether the packet at least arrived and
got marked by TPROXY before suspecting the proxy itself:
```bash
sudo nft list ruleset | grep -A3 TEST-TPROXY   # did the counter climb after the test?
```
If the counter **didn't** climb, the block is external/upstream (outside
your control). If it did climb but the connection still doesn't complete,
capture real traffic on the data interface to confirm whether the
honeypot is actually responding:
```bash
sudo tcpdump -ni <DATA_IFACE> 'tcp and port 22'
```

---

## Quick reference — k3s vs. kubeadm differences

| Item | k3s (Rocky/Ubuntu) | kubeadm (Debian) |
|---|---|---|
| Swap | no need to disable | **must** be disabled (`swapoff -a` + comment out in fstab) |
| Kernel modules | not needed | `br_netfilter` + `overlay` loaded manually |
| CNI | Flannel bundled | Calico (or another) — separate manual install |
| Default `StorageClass` | `local-path` bundled | **none** — `local-path-provisioner` must be installed manually |
| apiserver/kubelet bind | already restricted to the control interface via flag | **not restricted by default** — needs an explicit config file (`bind-address`, `address`) |
| Control-plane taint | doesn't apply (single-node already schedulable) | applied by default — must be removed manually |
| Reported `INTERNAL-IP` | follows `--node-ip` | may incorrectly inherit from `/etc/hosts` — fix before init |
| Package repository signature | not applicable (`get.k3s.io` script) | older streams (`v1.31`) may have signatures rejected by Debian's `sqv` |
| `kubeconfig` | fixed symlink at `/etc/rancher/k3s/k3s.yaml` | `admin.conf` generated by `kubeadm init` itself |

---

## Troubleshooting checklist (symptom → likely cause)

| Symptom | Likely cause | Where to check |
|---|---|---|
| Calico pods stuck in `ContainerCreating`/`Init` with a CNI plugin not found error | containerd's `bin_dir` pointing at `/usr/lib/cni` instead of `/opt/cni/bin` | Step 5 |
| `apt-get update` fails with a signature error on the Kubernetes repository | Older stream (`v1.31`) with an OpenPGP v3 signature, rejected by `sqv` | Step 6 |
| `kubectl get nodes` shows `INTERNAL-IP` as the public IP, not the control one | `/etc/hosts` mapping the hostname to the wrong IP before `kubeadm init` | Step 6.1 |
| `6443`/`10250` listening on `0.0.0.0` even with `--apiserver-advertise-address` set | kubeadm doesn't restrict the bind by default — needs explicit `bind-address`/`address` | Step 6.2 |
| No dpipot pod schedules, even with free resources | `node-role.kubernetes.io/control-plane:NoSchedule` taint on a single-node cluster | Step 7.1 |
| Kafka's `PersistentVolumeClaim` stays `Pending` indefinitely | No `StorageClass` — kubeadm doesn't ship one by default | Step 7.2 |
| `kubeadm init` certificate errors about validity/clock | No NTP client installed (`systemd-timesyncd` missing on the minimal image) | Step 3.1 |
| Proxy's init container fails with an `apk`/`temporary error` fetching packages | No real IPv6, `apk` trying to resolve over IPv6 | Step 4.1 |
| Assumption about which interface "is the internet one" was wrong | A public IP doesn't imply a default route is configured on that interface | Start of this guide — `ip route get 8.8.8.8` |
