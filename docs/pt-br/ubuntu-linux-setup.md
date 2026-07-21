# Instalando o dpipot-ng em Ubuntu Server (k3s)

Este guia documenta a instalação do dpipot-ng num nó **Ubuntu Server 24.04+**
usando **k3s**, incorporando as correções descobertas durante os testes de
compatibilidade de distro. Seguindo esta ordem, os bugs abaixo **não devem
ocorrer** — cada passo já nasce corrigido, em vez de ser corrigido depois do
fato.

Se você está migrando de um nó Rocky Linux/RHEL, veja a tabela de diferenças
no final deste documento antes de começar.

## Convenções usadas neste guia

O host tem (pelo menos) duas interfaces de rede com papéis diferentes:

- **Data plane** (`<DATA_IFACE>`, ex. `eth0`/`ens192`): a interface exposta à
  internet, por onde o tráfego dos atacantes/scanners chega. É essa interface
  que o TPROXY do dpipot intercepta.
- **Control plane** (`<CTRL_IFACE>` / `<CTRL_CIDR>`, ex. `wg0`, faixa
  `10.X.X.0/24`): a rede de gerência/VPN — acesso administrativo (SSH),
  tráfego do cluster (API server, kubelet), e, se aplicável, o caminho até um
  Elasticsearch/observabilidade central fora do cluster.

Troque `<DATA_IFACE>`, `<CTRL_IFACE>`, `<CTRL_CIDR>` e os IPs de exemplo pelos
valores reais do seu ambiente em todos os comandos abaixo.

> [!CAUTION]
> **Não assuma qual interface tem rota de internet só pelo tipo de IP**
> (público vs. privado/RFC1918). Em pelo menos um ambiente testado, a
> interface com o IP público (`<DATA_IFACE>`) **não tinha rota padrão
> nenhuma** — quem saía pra internet era a interface "de gerência". Confirme
> sempre com o comando abaixo antes de escrever qualquer regra de firewall ou
> rota, em vez de confiar na convenção de nomes:
> ```bash
> ip route get 8.8.8.8
> # a linha "via ... dev <interface>" mostra a interface real de saída
> ```

---

## Passo 1 — Enxugar o SO (opcional, recomendado em VMs pequenas)

```bash
# inventário do que está rodando ANTES de mudar qualquer coisa — você vai
# comparar com isso de novo no Passo 7.
systemctl list-units --type=service --state=running
sudo ss -tlnp
df -h /
free -h

# candidatos comuns a remover numa VM de honeypot (confirme antes de cada um
# se realmente está presente/ativo/sem uso na sua imagem específica):

# snapd: se nenhum snap estiver instalado, o daemon roda à toa (~40MB RSS)
snap list                                    # se vier vazio, pode remover:
sudo apt-get purge -y snapd lxd-installer

# multipath-tools: só útil com storage multipath real (SAN/iSCSI redundante)
lsblk                                        # se só houver 1 disco, remova:
sudo apt-get purge -y multipath-tools

sudo apt-get autoremove -y
```

> [!TIP]
> Aproveite para checar se há um kernel mais novo disponível (a remoção de
> pacotes acima às vezes força uma atualização de `initramfs`/kernel) e
> reiniciar agora, com a VM ainda vazia — melhor que descobrir isso depois
> com workloads no ar:
> ```bash
> apt list --upgradable 2>/dev/null | grep linux-image
> sudo reboot   # se houver kernel novo
> uname -r      # confirmar após reiniciar
> ```

---

## Passo 2 — Permissões e acesso SSH

```bash
# confirmar sudo sem senha (ou com senha, documentar qual):
sudo -n true && echo "sudo sem senha" || echo "sudo pede senha"
```

Se pedir senha, configure um NOPASSWD dedicado (evite usar `visudo` direto
numa sessão SSH sem um segundo acesso de backup aberto):
```bash
echo '<usuario> ALL=(ALL) NOPASSWD:ALL' | sudo tee /etc/sudoers.d/90-<usuario>
```

Gere uma chave SSH dedicada para administrar este host, em vez de reusar uma
chave de outro nó:
```bash
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519_<nome-do-no> -C "acesso-<nome-do-no>"
# autorize a chave pública no host (console/cloud-init/authorized_keys manual)
```

---

## Passo 3 — AppArmor: checagem rápida, sem ação esperada

Ubuntu usa **AppArmor**, não SELinux. Em todos os testes feitos, o AppArmor
**nunca** bloqueou o TPROXY nem o `AF_PACKET` do classifier — não se espera
problema aqui, mas vale confirmar que nenhum profile relacionado a
containers está em modo `enforce` restritivo antes de seguir:

```bash
sudo aa-status
```

Se algo parecer um bloqueio do AppArmor mais adiante, confirme antes de
desativar qualquer profile:
```bash
sudo dmesg | grep -i apparmor | grep -i denied
```

---

## Passo 4 — Pacotes base ausentes na imagem mínima

```bash
sudo apt-get update
sudo apt-get install -y tar curl git iptables ufw tcpdump conntrack
```
`tar`/`curl` geralmente já vêm na imagem base — não custa confirmar, já que
outras distros ensinaram a não assumir isso. `iptables`, `ufw`, `tcpdump` e
`conntrack` costumam estar ausentes e são necessários nos passos seguintes
(o k3s espera o binário `iptables` disponível no host; `tcpdump`/`conntrack`
são as ferramentas de debug deste guia).

---

## Passo 5 — sysctls: aplicar tudo *antes* do deploy, de forma persistente

### 5.1 — Desabilitar IPv6 (se não houver conectividade IPv6 real)

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
sudo sysctl --system
```

### 5.2 — `rp_filter` e forwarding

Diferente do Rocky/NetworkManager (que sobrescreve `rp_filter` por
interface, exigindo correção interface por interface), o Ubuntu com
`netplan`+`systemd-networkd` normalmente já traz `rp_filter=2` (modo loose)
por padrão em todas as interfaces — compatível com o roteamento assimétrico
que o TPROXY produz. Ainda assim, **confirme, não assuma**:

```bash
for i in /proc/sys/net/ipv4/conf/*/rp_filter; do echo "$i: $(cat $i)"; done
```
Se alguma interface aparecer com `1` (estrito), zere-a explicitamente:
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

## Passo 6 — Instalar k3s, já vinculado ao control plane

Instale o k3s prendendo o apiserver e o kubelet à interface de **control
plane** desde o início. Isso evita que qualquer um desses serviços de
gerência do cluster fique acessível pela interface de dados/internet — o
que, por sua vez, torna o bloqueio das portas 6443/10250 no firewall (Passo
9) apenas defesa em profundidade, não a única proteção.

O dpipot não usa Ingress nem LoadBalancer — desabilite os dois pra economizar
recurso:

```bash
curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC="\
  --disable=traefik --disable=servicelb \
  --bind-address=<IP_DO_CTRL_IFACE> \
  --node-ip=<IP_DO_CTRL_IFACE> \
  --tls-san=<IP_DO_CTRL_IFACE> \
" sh -

sudo k3s kubectl get nodes   # confirmar Ready
```

### 6.1 — kubeconfig

**Diferente do MicroK8s:** o `kubectl` do k3s é um symlink pro próprio
binário `k3s`, que por padrão sempre tenta ler
`/etc/rancher/k3s/k3s.yaml` (só root consegue ler), ignorando
`~/.kube/config` mesmo que ele exista.

```bash
mkdir -p ~/.kube
sudo cp /etc/rancher/k3s/k3s.yaml ~/.kube/config
sudo chown $(id -u):$(id -g) ~/.kube/config
chmod 600 ~/.kube/config

echo 'export KUBECONFIG=$HOME/.kube/config' >> ~/.bashrc
export KUBECONFIG=$HOME/.kube/config
```

> [!WARNING]
> Um `sudo systemctl restart k3s` **recria** `/etc/rancher/k3s/k3s.yaml` com
> permissão `600` root-only — se você reiniciar o serviço depois, vai
> precisar copiar o arquivo pra `~/.kube/config` de novo (por isso a cópia
> acima, em vez de só ajustar a permissão do arquivo original).

Como o apiserver só escuta no IP de control plane, ajuste o kubeconfig:
```bash
sed -i "s/127.0.0.1/<IP_DO_CTRL_IFACE>/" ~/.kube/config
kubectl get nodes
```

### 6.2 — Instalar o Helm (não vem com o k3s)

```bash
curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
```

---

## Passo 7 — Clonar o repositório

```bash
git clone --branch <branch-desejada> https://github.com/spawnzao/dpipot-ng.git ~/dpipot-ng
cd ~/dpipot-ng
```

---

## Passo 8 — Hardening: nada de gerência exposto na interface de dados

> [!CAUTION]
> **Liberar regras de firewall sem antes confirmar quais portas/serviços
> estão realmente escutando no servidor é uma brecha de segurança grave.**
> O Passo 9 deste guia libera TCP de forma ampla na interface de dados —
> isso só é seguro depois de garantir, como fazemos aqui, que **nenhum
> serviço de gerência real** (SSH administrativo, API do cluster, kubelet)
> responde nessa interface.

### 8.1 — Confirmar que o k3s já está restrito (feito no Passo 6)

```bash
sudo ss -tlnp | grep -E ':6443|:10250'
```
Os dois devem aparecer só no IP de control plane, nunca em `0.0.0.0` nem no
IP da interface de dados.

### 8.2 — Restringir o `sshd` real ao control plane

> [!CAUTION]
> **Ubuntu 24.04+ ativa socket-activation pro SSH por padrão**
> (`ssh.socket`). Isso faz o **socket**, não o `sshd`, fazer o bind da
> porta 22 — e o socket **ignora completamente** o `ListenAddress` do
> `sshd_config`. Se você só editar o `sshd_config.d` e reiniciar o
> `ssh.service`, a restrição parece aplicada (`sshd -t` valida sem erro),
> mas o processo real continua escutando em `0.0.0.0` — uma falsa sensação
> de segurança. **Desabilite o socket primeiro:**

```bash
sudo systemctl disable --now ssh.socket
sudo systemctl enable --now ssh.service

sudo tee /etc/ssh/sshd_config.d/99-restrict-listen.conf << EOF
ListenAddress <IP_DO_CTRL_IFACE>
ListenAddress <OUTROS_IPS_DE_GERENCIA_SE_HOUVER>
EOF

sudo sshd -t && echo "config OK"   # sempre valide antes de restart
sudo systemctl restart ssh.service

# valide com uma conexão NOVA antes de fechar a sessão atual:
ssh -o ConnectTimeout=5 usuario@<IP_DO_CTRL_IFACE> "echo ok"
```

Confirme:
```bash
ss -tlnp | grep :22   # não deve aparecer 0.0.0.0:22
```

### 8.3 — Revisar o inventário de serviços do Passo 1

Volte na lista de serviços/portas que você levantou no Passo 1 e remova ou
restrinja qualquer outro serviço de gerência que ainda apareça escutando de
forma ampla antes de seguir pro Passo 9. A regra geral: **o único tráfego
que deveria chegar pela interface de dados é o que o TPROXY do dpipot vai
interceptar.**

---

## Passo 9 — `ufw`: liberar o necessário pro honeypot

> [!NOTE]
> O `ufw` **não tem conceito de zonas** como o firewalld, mas **tem a mesma
> armadilha de política default-deny pra tráfego roteado** (`routed: deny`
> por padrão) — o que afeta especificamente o tráfego que os **pods**
> tentam rotear pra fora (internet, ou uma VPN externa como o Elasticsearch
> central), não o tráfego do próprio host. Sem os passos 9.2/9.3 abaixo, o
> deploy vai parecer travado (`Init:Error` no proxy tentando `apk add`,
> Logstash sem conseguir alcançar o ES) mesmo com o `ufw` "liberado" pra
> entrada.

### 9.1 — Política básica e liberação da interface de dados

```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing

sudo ufw allow in on <CTRL_IFACE> to any port 22 proto tcp

# opcional (defesa em profundidade — o Passo 6/8 já restringe isso na origem):
sudo ufw deny in on <DATA_IFACE> to any port 6443 proto tcp
sudo ufw deny in on <DATA_IFACE> to any port 10250 proto tcp
```

> [!WARNING]
> Confirme o Passo 8 (nenhum serviço de gerência exposto) **antes** de
> rodar o comando abaixo. Ele libera **todo TCP de entrada** na interface
> de dados — se algum serviço de gerência ainda estiver escutando ali, essa
> regra o expõe diretamente à internet.

```bash
sudo ufw allow in on <DATA_IFACE> proto tcp
sudo ufw --force enable
```

### 9.2 — Liberar o roteamento dos pods para a internet

Necessário pro init container do proxy conseguir `apk add` pacotes, e para
qualquer honeypot/componente que precise resolver DNS ou alcançar a
internet.

```bash
# use a interface que REALMENTE tem a rota default (confirmada no início
# deste guia com `ip route get 8.8.8.8`) — não assuma que é a de dados:
sudo ufw route allow in on cni0 out on <INTERFACE_COM_ROTA_DEFAULT>
sudo ufw route allow in on flannel.1 out on <INTERFACE_COM_ROTA_DEFAULT>
sudo ufw reload
```

> [!NOTE]
> O chart já inclui uma `NetworkPolicy` (`honeypots-isolation`) que restringe
> o egress dos **honeypots** a só DNS (porta 53/UDP) — isso é intencional
> (honeypots comprometidos não devem conseguir pivotar pra internet), não um
> bug. Os componentes `dpipot-proxy`/`kafka`/`logstash`/`filebeat` são
> excluídos dessa política e têm egress livre. Se estiver depurando
> conectividade com um pod de teste avulso (`kubectl run debug ...`), lembre
> que ele **também** cai nessa restrição por não ter os labels corretos —
> isso não indica um bug de rede real.

### 9.3 — Se o Logstash/Kafka precisar alcançar um serviço externo (ex:
Elasticsearch central) por uma interface de VPN dedicada

```bash
sudo ufw route allow in on cni0 out on <VPN_ES_IFACE>
sudo ufw route allow in on flannel.1 out on <VPN_ES_IFACE>
sudo ufw reload
```

**Comando de debug** — se uma porta ou fluxo específico não estiver
funcionando, identifique exatamente onde o pacote é descartado, zerando os
contadores antes do teste:
```bash
sudo iptables -Z FORWARD
# gere o tráfego de teste (ex: de dentro de um pod: wget/curl/ping)
sudo iptables -L FORWARD -n -v --line-numbers    # veja qual regra numerada incrementou
```
Se o pacote nunca aparecer em nenhuma interface física (`sudo tcpdump -i any
-n <filtro>`), o descarte é local (FORWARD, NAT/masquerade, ou uma
`NetworkPolicy`) — não adianta suspeitar do TPROXY ou de rede externa antes
de confirmar isso.

---

## Passo 10 — Values override específico do nó

`storageClass` padrão do k3s é `local-path` (do `local-path-provisioner`),
**diferente** do `microk8s-hostpath` do MicroK8s — sempre faça override
explícito.

```yaml
# k8s/chart/values-<nome-do-no>.yaml
# Mantenha este arquivo LOCAL (não commitado) — ver .gitignore em k8s/chart/

kafka:
  enabled: true
  persistence:
    enabled: true
    size: "10Gi"
    storageClass: "local-path"
  heapOpts: "-Xmx512m -Xms512m"

network:
  interface: "<DATA_IFACE>"

# Ajuste conforme a RAM disponível na VM — k3s tem overhead bem menor que
# MicroK8s (medido em torno de ~670MB vs. ~2.4GB), então sobra mais RAM
# pra aplicação mesmo em VMs pequenas (4GB ou menos).
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
> Se a VM tiver pouca RAM (4GB ou menos), acompanhe o uso real por alguns
> dias antes de considerar o dimensionamento definitivo (`kubectl top pods
> -n dpipot`, `free -h`) — números de `requests`/`limits` são um teto
> teórico, não o uso real.

---

## Passo 11 — Namespace, secrets, ghcr-secret

```bash
kubectl create namespace dpipot

# obrigatório mesmo com imagens públicas (o kubelet exige o secret referenciado
# no chart, ainda que o conteúdo seja um dummy):
kubectl create secret generic ghcr-secret --type=kubernetes.io/dockerconfigjson \
  --from-literal=.dockerconfigjson='{"auths":{}}' -n dpipot

kubectl apply -f k8s/secrets/logstash-secrets.yaml -f k8s/secrets/galah-secrets.yaml -n dpipot
```

---

## Passo 12 — Deploy

```bash
helm upgrade --install dpipot k8s/chart/ \
  -f k8s/chart/values-<nome-do-no>.yaml \
  --namespace dpipot --create-namespace
```

---

## Passo 13 — Verificação final

```bash
kubectl get pods -n dpipot -o wide          # todos Running/Ready
kubectl logs -n dpipot -l app=dpipot-proxy --tail=50
sudo nft list table ip mangle               # deve mostrar a chain do TPROXY com contador > 0 conforme chega tráfego
kubectl logs -n dpipot -l app=logstash --tail=50 | grep -i elasticsearch   # deve mostrar "Restored connection"/"version determined"
```

Teste de conectividade externa **de outra máquina** (não do próprio host —
loopback não passa pelo caminho real do TPROXY):
```bash
# de outra máquina, uma por porta configurada no honeypot:
nc -zv <IP_PUBLICO_DO_NO> 22
nc -zv <IP_PUBLICO_DO_NO> 80
# (Windows) Test-NetConnection -ComputerName <IP_PUBLICO_DO_NO> -Port 80
```

Se alguma porta não responder, use o comando de debug do Passo 9.3 antes de
suspeitar do TPROXY em si — na prática, a causa raiz costuma estar no
firewall/roteamento, não no proxy.

---

## Referência rápida — diferenças Rocky/RHEL vs Ubuntu

| Item | Rocky/RHEL | Ubuntu |
|---|---|---|
| SELinux/AppArmor | SELinux Enforcing — precisa `container-selinux`+`k3s-selinux` antes do k3s | AppArmor — nunca bloqueou nada nos testes, sem ação necessária |
| Firewall | `firewalld`, zonas, default-deny por zona | `ufw`, sem zonas — **mesma armadilha de default-deny pro tráfego roteado dos pods** |
| Gerenciador de rede | NetworkManager — sobrescreve `rp_filter` por interface | netplan/systemd-networkd — geralmente já vem em modo loose (`2`), sem sobrescrita |
| SSH | `ListenAddress` funciona direto | **24.04+ usa socket-activation** — precisa desabilitar `ssh.socket` antes |
| Pacotes mínimos ausentes | `tar`, `git` | `iptables`, `ufw`, `tcpdump`, `conntrack`, `git` (varia por imagem) |
| Redução de RAM reservada | `kdump`/crashkernel (200-500MB) | `snapd`/`multipath-tools`/`lxd-installer` sem uso real (~40-70MB) |
| storageClass padrão | `local-path` | `local-path` (igual, ambos k3s) |

---

## Checklist de troubleshooting (sintoma → causa provável)

| Sintoma | Causa provável | Onde checar |
|---|---|---|
| `ListenAddress` do sshd parece aplicado mas a porta continua em `0.0.0.0` | `ssh.socket` ativo fazendo o bind, ignorando o `sshd_config` | Passo 8.2 — `systemctl is-active ssh.socket` |
| Init container do proxy falha com `apk`/`temporary error` buscando pacotes | Sem IPv6 real, `apk` tentando resolver via IPv6 | Passo 5.1 |
| Pod não alcança a internet (`apk add`, DNS externo, etc.), mas o host consegue | `ufw` bloqueando tráfego roteado (`routed: deny`) sem regra `ufw route allow` explícita | Passo 9.2 |
| Pod não alcança serviço externo via VPN, "no route to host"/timeout mas o host consegue pingar | Mesma causa acima, mas pra interface de VPN | Passo 9.3 |
| Pod de teste avulso não tem acesso à internet, mas o `dpipot-proxy` real funciona normalmente | Comportamento intencional da `NetworkPolicy honeypots-isolation` (egress só DNS pra pods fora da lista de exceção) | Passo 9.2 (nota) |
| Suposição de qual interface "é a de internet" estava errada | IP público não implica rota default configurada nessa interface | Início deste guia — `ip route get 8.8.8.8` |
| `kubectl` para de funcionar depois do Passo 6 | kubeconfig ainda aponta pra `127.0.0.1` após o apiserver ser restrito ao control plane | Passo 6.1 |
| `kubectl`/`helm` voltam a dar erro de permissão depois de reiniciar o k3s | `systemctl restart k3s` recria `/etc/rancher/k3s/k3s.yaml` com permissão `600` | Passo 6.1 — recopiar pra `~/.kube/config` |
| TPROXY marca o pacote (`iptables -t mangle` conta) mas nunca entrega ao app | `rp_filter` estrito em alguma interface no caminho | Passo 5.2 |
