# Instalando o dpipot-ng em Debian (kubeadm + Calico)

Este guia documenta a instalação do dpipot-ng num nó **Debian 13 (trixie)**
usando **kubeadm + Calico** — a primeira vez que esta combinação de
SO/orquestrador foi testada no projeto. Seguindo esta ordem, os bugs abaixo
**não devem ocorrer** — cada passo já nasce corrigido, em vez de ser
corrigido depois do fato.

Se você está migrando de um nó Rocky Linux/RHEL ou Ubuntu com **k3s**, veja
a tabela de diferenças no final deste documento antes de começar — kubeadm
se comporta de forma bem diferente do k3s em vários pontos que não são
óbvios (bind de portas, taint do control-plane, storageClass).

## Convenções usadas neste guia

O host tem (pelo menos) duas interfaces de rede com papéis diferentes:

- **Data plane** (`<DATA_IFACE>`, ex. `ens18`/`ens32`): a interface exposta
  à internet, por onde o tráfego dos atacantes/scanners chega. É essa
  interface que o TPROXY do dpipot intercepta.
- **Control plane** (`<CTRL_IFACE>` / `<CTRL_CIDR>`, ex. `ens19`, faixa
  `10.X.X.0/24`): a rede de gerência/VPN — acesso administrativo (SSH),
  tráfego do cluster (API server, kubelet), e, se aplicável, o caminho até
  um Elasticsearch/observabilidade central fora do cluster.

Troque `<DATA_IFACE>`, `<CTRL_IFACE>`, `<CTRL_CIDR>`, `<CTRL_IFACE_IP>` e os
IPs de exemplo pelos valores reais do seu ambiente em todos os comandos
abaixo.

> [!CAUTION]
> **Não assuma qual interface tem rota de internet só pelo tipo de IP**
> (público vs. privado/RFC1918). Confirme sempre com o comando abaixo antes
> de escrever qualquer regra de firewall ou rota, em vez de confiar na
> convenção de nomes:
> ```bash
> ip route get 8.8.8.8
> # a linha "via ... dev <interface>" mostra a interface real de saída
> ```

---

## Passo 1 — Permissões, acesso SSH e auditoria rápida

```bash
# inventário do que está rodando ANTES de mudar qualquer coisa — compare
# de novo depois do deploy, se quiser confirmar que nada estranho apareceu:
systemctl list-unit-files --state=enabled --type=service
systemctl list-units --type=service --state=running
free -h

sudo -n true && echo "sudo sem senha" || echo "sudo pede senha"
```

Se pedir senha, configure um NOPASSWD dedicado:
```bash
echo '<usuario> ALL=(ALL) NOPASSWD:ALL' | sudo tee /etc/sudoers.d/90-<usuario>
```

Gere uma chave SSH dedicada para administrar este host:
```bash
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519_<node-name> -C "acesso-<node-name>"
# autorize a chave pública no host (console/cloud-init/authorized_keys manual)
```

> [!TIP]
> Uma instalação **Debian netinst** mínima já vem bem enxuta — nos testes
> feitos, não havia nenhum serviço equivalente ao `kdump`/`sssd` do Rocky ou
> ao `snapd`/`multipath-tools` do Ubuntu consumindo RAM à toa. Não é
> necessário um passo de "enxugar o SO" separado como nos outros guias.

---

## Passo 2 — AppArmor: checagem rápida, sem ação esperada

```bash
sudo aa-status
```
Nos testes feitos, os únicos profiles em modo `enforce` eram utilitários
irrelevantes (`nvidia_modprobe`, `lsb_release`) — não bloquearam TPROXY nem
o `AF_PACKET` do classifier. Se algo parecer um bloqueio do AppArmor mais
adiante, confirme antes de desativar qualquer profile:
```bash
sudo dmesg | grep -i apparmor | grep -i denied
```

---

## Passo 3 — Pacotes base ausentes na imagem mínima

```bash
sudo apt-get update
sudo apt-get install -y git curl gpg apt-transport-https ca-certificates \
  conntrack ipset tcpdump
```

> [!NOTE]
> `software-properties-common` **não existe** no repositório padrão do
> Debian trixie — não é necessário para este guia (usado só por
> `add-apt-repository`, que não usamos aqui). Não tente instalá-lo.

### 3.1 — NTP: cliente ausente por padrão

Uma instalação Debian netinst mínima **não inclui** `systemd-timesyncd` —
`timedatectl set-ntp true` falha silenciosamente com `NTP not supported`.
Isso importa porque os certificados TLS gerados pelo `kubeadm` são
sensíveis a relógio desincronizado.

```bash
sudo apt-get install -y systemd-timesyncd
sudo systemctl enable --now systemd-timesyncd
timedatectl status | grep -i synchronized   # deve dizer "yes"
```

---

## Passo 4 — sysctls e módulos: aplicar tudo *antes* do deploy

### 4.1 — Desabilitar IPv6 (se não houver conectividade IPv6 real)

**Causa do problema:** o init container do proxy roda `apk add iptables
iproute2` dentro de uma imagem Alpine. Se o host não tiver rota IPv6 real, o
`apk` tenta resolver os espelhos via IPv6, recebe `temporary error` e a
instalação do pacote falha — derrubando o pod em `Init:Error` num loop de
backoff. Confirme se você tem IPv6 real antes de desabilitar:

```bash
ip -6 addr show | grep -v 'scope link\|scope host'   # vazio = sem IPv6 global real
```

Se vier vazio, desabilite:
```bash
sudo tee /etc/sysctl.d/98-dpipot-disable-ipv6.conf << 'EOF'
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 0
EOF
```

### 4.2 — `rp_filter` e `rmem_max`

```bash
sudo tee /etc/sysctl.d/98-dpipot-tproxy.conf << EOF
net.ipv4.conf.all.rp_filter=0
net.ipv4.conf.default.rp_filter=0
net.ipv4.conf.<DATA_IFACE>.rp_filter=0
net.ipv4.conf.<CTRL_IFACE>.rp_filter=0
EOF

# evita afpacket_drops sob rajada de tráfego — o socket AF_PACKET pede
# SO_RCVBUF de 32MB, mas o kernel limita silenciosamente pelo rmem_max
# padrão (~208KB) se não for elevado explicitamente:
sudo tee /etc/sysctl.d/99-dpipot.conf << 'EOF'
net.core.rmem_max=134217728
net.core.rmem_default=134217728
net.core.netdev_max_backlog=10000
EOF
```

### 4.3 — Requisitos do kubeadm/Calico (não existem no k3s)

**Diferente do k3s** (que já lida com isso internamente), o `kubeadm`
exige swap desabilitado e módulos de bridge carregados manualmente:

```bash
sudo swapoff -a
sudo sed -i '/swap/s/^/#/' /etc/fstab   # comentar, não remover — persiste no reboot

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
# confirme rp_filter=0 e disable_ipv6=1 em todas as interfaces antes de seguir
```

---

## Passo 5 — Container runtime: containerd

```bash
sudo apt-get install -y containerd
sudo mkdir -p /etc/containerd
containerd config default | sudo tee /etc/containerd/config.toml > /dev/null

# cgroup driver systemd — evita mismatch com o kubelet (que usa systemd
# por padrão em SOs modernos, enquanto containerd usa cgroupfs por padrão):
sudo sed -i 's/SystemdCgroup = false/SystemdCgroup = true/' /etc/containerd/config.toml
```

> [!CAUTION]
> **`containerd config default` no pacote Debian aponta `bin_dir =
> "/usr/lib/cni"`**, mas tanto o pacote `kubernetes-cni` (instalado no
> Passo 6) quanto o `install-cni` do Calico (Passo 8) usam o caminho
> universal `/opt/cni/bin`. Esse mismatch trava **todos os pods do CNI**
> em `ContainerCreating`/`Init` com o erro `failed to find plugin "calico"
> in path [/usr/lib/cni]`. Corrija **antes** de instalar o Calico:
> ```bash
> sudo sed -i 's|bin_dir = "/usr/lib/cni"|bin_dir = "/opt/cni/bin"|' /etc/containerd/config.toml
> ```

```bash
sudo systemctl restart containerd
sudo systemctl enable containerd
```

---

## Passo 6 — Instalar kubeadm, kubelet, kubectl

> [!CAUTION]
> **A stream `v1.31` do repositório oficial `pkgs.k8s.io` tem assinatura
> OpenPGP incompatível com a política do verificador `sqv` no Debian
> trixie** (rejeitada desde `2026-02-01` com o erro `Signature Packet v3
> is not considered secure`). Use uma stream mais recente — teste qual
> versão estável está disponível antes de assumir que uma versão antiga
> vai funcionar:

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

### 6.1 — Corrigir `/etc/hosts` antes do `kubeadm init`

Instalações via instalador gráfico/netinst costumam mapear o hostname pro
IP **público** em `/etc/hosts` — isso faz o `kubelet` reportar
`INTERNAL-IP` errado (o IP de dados, não o de controle) depois do init.
Corrija antes:

```bash
sudo sed -i "s/^<NODE_PUBLIC_IP>\s*<node-name>/<CTRL_IFACE_IP>\t<node-name>/" /etc/hosts
```

### 6.2 — `kubeadm init` com bind explícito

> [!CAUTION]
> **Diferente do k3s, `--apiserver-advertise-address` do kubeadm só afeta
> o endereço *anunciado*/certificado — não restringe o *bind* real.**
> Sem configuração explícita, o apiserver (6443) escuta em `0.0.0.0`
> mesmo com o endereço de anúncio configurado corretamente, o que expõe a
> API do cluster na interface de dados. Use um arquivo de config
> explícito em vez de só flags de linha de comando:

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

O `node-ip` acima corrige o `INTERNAL-IP` relatado e o *bind* do
apiserver — mas **não** o bind do próprio kubelet (porta 10250), que
continua em `0.0.0.0` até o passo abaixo:

```bash
grep -q '^address:' /var/lib/kubelet/config.yaml && \
  sudo sed -i "s/^address:.*/address: <CTRL_IFACE_IP>/" /var/lib/kubelet/config.yaml || \
  echo "address: <CTRL_IFACE_IP>" | sudo tee -a /var/lib/kubelet/config.yaml
sudo systemctl restart kubelet

# confirme que os dois só escutam no IP de controle, nunca em 0.0.0.0:
sudo ss -tlnp | grep -E ':6443|:10250'
```

### 6.3 — Instalar o Helm (não vem com o kubeadm)

```bash
curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
```

---

## Passo 7 — Calico (CNI)

```bash
kubectl create -f https://raw.githubusercontent.com/projectcalico/calico/v3.28.0/manifests/tigera-operator.yaml
kubectl create -f https://raw.githubusercontent.com/projectcalico/calico/v3.28.0/manifests/custom-resources.yaml

kubectl get pods -n calico-system -w   # aguarde todos Running
```

Se algum pod ficar travado em `ContainerCreating`/`Init` com erro de
plugin CNI não encontrado, volte pro Passo 5 (`bin_dir` do containerd) —
esse é o sintoma exato desse bug.

### 7.1 — Remover o taint do control-plane (cluster single-node)

**Diferente do k3s**, o `kubeadm` marca o control-plane como não-agendável
por padrão. Num cluster de um nó só, isso impede todos os pods do dpipot
de rodar:

```bash
kubectl taint nodes --all node-role.kubernetes.io/control-plane- 2>&1 || true
kubectl get nodes -o wide   # deve mostrar Ready, sem taints
```

### 7.2 — `local-path-provisioner` (não vem com o kubeadm)

**Diferente do k3s** (que já traz o `local-path-provisioner` embutido),
o kubeadm não tem nenhum `StorageClass` por padrão — sem isso, qualquer
`PersistentVolumeClaim` (ex. do Kafka) fica pendente indefinidamente.

```bash
kubectl apply -f https://raw.githubusercontent.com/rancher/local-path-provisioner/master/deploy/local-path-storage.yaml
kubectl patch storageclass local-path -p '{"metadata": {"annotations":{"storageclass.kubernetes.io/is-default-class":"true"}}}'
kubectl get storageclass   # "local-path" deve aparecer como (default)
```

---

## Passo 8 — Clonar o repositório

```bash
git clone --branch <branch-desejada> https://github.com/spawnzao/dpipot-ng.git ~/dpipot-ng
cd ~/dpipot-ng
```

---

## Passo 9 — Hardening: nada de gerência exposto na interface de dados

> [!CAUTION]
> **Liberar regras de firewall sem antes confirmar quais portas/serviços
> estão realmente escutando no servidor é uma brecha de segurança grave.**
> Este passo só é seguro depois de garantir, como fizemos no Passo 6.2,
> que **nenhum serviço de gerência real** (SSH administrativo, API do
> cluster, kubelet) responde na interface de dados.

### 9.1 — Restringir o `sshd` real ao control plane

```bash
sudo tee /etc/ssh/sshd_config.d/99-restrict-listen.conf << EOF
ListenAddress <CTRL_IFACE_IP>
ListenAddress <OTHER_MANAGEMENT_IPS_IF_ANY>
EOF

sudo sshd -t && echo "config OK"   # sempre valide antes de restart
sudo systemctl restart ssh

# valide com uma conexão NOVA antes de fechar a sessão atual:
ssh -o ConnectTimeout=5 usuario@<CTRL_IFACE_IP> "echo ok"
ss -tlnp | grep :22   # não deve aparecer 0.0.0.0:22
```

### 9.2 — Baseline de `nftables`

Debian não usa `firewalld` nem `ufw` por padrão — sem nenhuma regra ativa,
o host fica totalmente permissivo (o que já é suficiente pro TPROXY
funcionar, já que ele precisa aceitar qualquer porta TCP na interface de
dados). Adicione só uma camada extra de defesa em profundidade, bloqueando
explicitamente as portas de gerência do cluster na interface pública
(mesmo que o Passo 6.2 já as restrinja na origem):

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
> Depois que o Calico/kube-proxy escreverem suas próprias tabelas
> (`iptables-nft`), é normal ver o aviso `table ip mangle is managed by
> iptables-nft, do not touch!` ao listar o ruleset — isso não indica
> conflito, as tabelas coexistem.

---

## Passo 10 — Values override específico do nó

```yaml
# k8s/chart/values-<node-name>.yaml
# Mantenha este arquivo LOCAL (não commitado) — ver .gitignore em k8s/chart/

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
  # No binário unificado (branch dev), a publicação de eventos nDPI é
  # opt-in — sem isso, o índice dpipot-classifier-* no ES fica vazio.
  NDPI_EVENTS_ENABLED: "true"
```

> [!WARNING]
> Sempre coloque `heapOpts` **dentro** do bloco `resources.<componente>`.
> Um `heapOpts` no nível raiz do arquivo (fora de `resources:`) é
> silenciosamente ignorado pelo chart — já aconteceu em produção.

Se este nó **não** for rodar o honeypot `galah` (por exemplo, por não ter
uma GPU/LLM disponível), desabilite e reaproveite a rota:
```yaml
honeypots:
  galah:
    enabled: false
config:
  HONEYPOT_ROUTES: "HTTP=wordpot-svc:80, TLS=wordpot-svc:80, HTTP_AUTH=heralding:80, HTTP_SUSPECT=heralding:80, SSH=cowrie-svc:22, ..."
```

---

## Passo 11 — Namespace, secrets, ghcr-secret

```bash
kubectl create namespace dpipot

# obrigatório mesmo com imagens públicas (o kubelet exige o secret
# referenciado no chart, ainda que o conteúdo seja um dummy):
kubectl create secret generic ghcr-secret --type=kubernetes.io/dockerconfigjson \
  --from-literal=.dockerconfigjson='{"auths":{}}' -n dpipot

kubectl apply -f k8s/secrets/logstash-secrets.yaml -n dpipot
# + galah-secrets.yaml, se este nó for rodar o galah
```

---

## Passo 12 — Deploy

```bash
helm upgrade --install dpipot k8s/chart/ \
  -f k8s/chart/values-<node-name>.yaml \
  --namespace dpipot --create-namespace
```

---

## Passo 13 — Verificação final

```bash
kubectl get pods -n dpipot -o wide          # todos Running/Ready
kubectl logs -n dpipot -l app=dpipot-proxy --tail=50
sudo nft list ruleset | grep -A5 TEST-TPROXY   # contador deve subir conforme chega tráfego

# não confie só em grep de texto do log pra validar Logstash → ES — o
# banner de conexão pode nunca aparecer via stdout mesmo funcionando.
# Confirme pelo lag do consumidor Kafka em vez disso:
kubectl exec -n dpipot deploy/kafka -- /opt/kafka/bin/kafka-consumer-groups.sh \
  --bootstrap-server localhost:9092 --describe --group logstash-consumer
```

Teste de conectividade externa **de outra máquina** (não do próprio host):
```bash
nc -zv <NODE_PUBLIC_IP> 22
nc -zv <NODE_PUBLIC_IP> 80
```

Se alguma porta não responder, verifique se o pacote pelo menos chegou e
foi marcado pelo TPROXY antes de suspeitar do proxy em si:
```bash
sudo nft list ruleset | grep -A3 TEST-TPROXY   # contador subiu depois do teste?
```
Se o contador **não** subiu, o bloqueio é externo/upstream (fora do seu
controle). Se subiu mas a conexão mesmo assim não completa, capture o
tráfego real na interface de dados pra confirmar se o honeypot está
respondendo:
```bash
sudo tcpdump -ni <DATA_IFACE> 'tcp and port 22'
```

---

## Referência rápida — diferenças k3s vs kubeadm

| Item | k3s (Rocky/Ubuntu) | kubeadm (Debian) |
|---|---|---|
| Swap | não precisa desabilitar | **precisa** (`swapoff -a` + comentar no fstab) |
| Módulos de kernel | não precisa | `br_netfilter` + `overlay` manuais |
| CNI | Flannel embutido | Calico (ou outro) — instalação manual separada |
| `StorageClass` padrão | `local-path` embutido | **nenhum** — precisa instalar `local-path-provisioner` manualmente |
| Bind do apiserver/kubelet | já restrito à interface de controle por flag | **não restringe por padrão** — precisa de config file explícito (`bind-address`, `address`) |
| Taint do control-plane | não aplica (single-node já agendável) | aplica por padrão — precisa remover manualmente |
| `INTERNAL-IP` reportado | segue o `--node-ip` | pode herdar de `/etc/hosts` incorretamente — corrigir antes do init |
| Assinatura do repositório de pacotes | não aplicável (script `get.k3s.io`) | streams antigas (`v1.31`) podem ter assinatura rejeitada pelo `sqv` do Debian |
| `kubeconfig` | symlink fixo em `/etc/rancher/k3s/k3s.yaml` | `admin.conf` gerado pelo próprio `kubeadm init` |

---

## Checklist de troubleshooting (sintoma → causa provável)

| Sintoma | Causa provável | Onde checar |
|---|---|---|
| Pods do Calico travados em `ContainerCreating`/`Init` com erro de plugin CNI não encontrado | `bin_dir` do containerd apontando pra `/usr/lib/cni` em vez de `/opt/cni/bin` | Passo 5 |
| `apt-get update` falha com erro de assinatura no repositório do Kubernetes | Stream antiga (`v1.31`) com assinatura OpenPGP v3, rejeitada pelo `sqv` | Passo 6 |
| `kubectl get nodes` mostra `INTERNAL-IP` como o IP público, não o de controle | `/etc/hosts` mapeando o hostname pro IP errado antes do `kubeadm init` | Passo 6.1 |
| `6443`/`10250` escutando em `0.0.0.0` mesmo com `--apiserver-advertise-address` configurado | kubeadm não restringe o bind por padrão — precisa de `bind-address`/`address` explícitos | Passo 6.2 |
| Nenhum pod do dpipot agenda, mesmo com recursos livres | Taint `node-role.kubernetes.io/control-plane:NoSchedule` num cluster single-node | Passo 7.1 |
| `PersistentVolumeClaim` do Kafka fica `Pending` indefinidamente | Sem `StorageClass` — kubeadm não traz um por padrão | Passo 7.2 |
| Certificados do `kubeadm init` com erro de validade/relógio | Sem cliente NTP instalado (`systemd-timesyncd` ausente na imagem mínima) | Passo 3.1 |
| Init container do proxy falha com `apk`/`temporary error` buscando pacotes | Sem IPv6 real, `apk` tentando resolver via IPv6 | Passo 4.1 |
| Suposição de qual interface "é a de internet" estava errada | IP público não implica rota default configurada nessa interface | Início deste guia — `ip route get 8.8.8.8` |
