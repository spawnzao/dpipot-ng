# Instalando o dpipot-ng em Rocky Linux (k3s)

Este guia documenta a instalação do dpipot-ng num nó **Rocky Linux / RHEL 9**
usando **k3s** em vez de MicroK8s, incorporando as correções descobertas
durante os testes de compatibilidade de distro. Seguindo esta ordem, os bugs
abaixo **não devem ocorrer** — cada passo já nasce corrigido, em vez de ser
corrigido depois do fato.

Se você está migrando de um nó Ubuntu/MicroK8s, veja a tabela de diferenças
no final deste documento antes de começar.

## Convenções usadas neste guia

O host tem (pelo menos) duas interfaces de rede com papéis diferentes:

- **Data plane** (`<DATA_IFACE>`, ex. `eth0`/`ens18`): a interface exposta à
  internet, por onde o tráfego dos atacantes/scanners chega. É essa interface
  que o TPROXY do dpipot intercepta.
- **Control plane** (`<CTRL_IFACE>` / `<CTRL_CIDR>`, ex. `wg0`, faixa
  `10.X.X.0/24`): a rede de gerência/VPN — acesso administrativo (SSH),
  tráfego do cluster (API server, kubelet), e, se aplicável, o caminho até um
  Elasticsearch/observabilidade central fora do cluster.

Troque `<DATA_IFACE>`, `<CTRL_IFACE>`, `<CTRL_CIDR>` e os IPs de exemplo pelos
valores reais do seu ambiente em todos os comandos abaixo.

---

## Passo 1 — Enxugar o SO (opcional, recomendado em VMs pequenas)

Faça isso **antes** de instalar qualquer coisa, porque a remoção do `kdump`
exige reboot.

```bash
# kdump reserva memória fixa pro crashkernel (200-500MB dependendo do
# tamanho da RAM) — dispensável numa VM de honeypot.
sudo systemctl disable --now kdump.service
sudo dnf remove -y kexec-tools

# Confirme a string ATUAL de crashkernel antes de remover — a remoção do
# kexec-tools pode regenerar a config do grub e MUDAR a string, invalidando
# um --remove-args feito com o valor antigo.
cat /proc/cmdline | grep -o 'crashkernel=[^ ]*'
sudo grubby --remove-args="crashkernel=<valor-encontrado-acima>" --update-kernel=ALL

# sssd normalmente não é usado (sem domínio/realm configurado) nesse tipo de
# host — evita custo de boot desnecessário.
sudo systemctl disable sssd

sudo reboot
```

Depois do reboot, confirme:
```bash
cat /proc/cmdline   # não deve mais ter "crashkernel="
free -h              # RAM total deve ter subido
```

> [!TIP]
> Aproveite este momento pra fazer um inventário do que está rodando no
> host antes de ir pra frente: `systemctl list-units --type=service --state=running`
> e `sudo ss -tlnp`. Você vai usar essa lista de novo no Passo 7 pra
> confirmar que nada além do necessário ficou exposto.

---

## Passo 2 — SELinux: instalar as policies **antes** do k3s

RHEL/Rocky roda com SELinux **Enforcing** por padrão. Instalar o k3s sem as
policies corretas já instaladas causa falhas em operações comuns de
container (não só no TPROXY).

```bash
sudo dnf install -y container-selinux

sudo dnf config-manager --add-repo=https://rpm.rancher.io/k3s/stable/common/centos/9/noarch/
sudo rpm --import https://rpm.rancher.io/public.key
sudo dnf install -y k3s-selinux
```

**Não desative o SELinux.** Em todos os testes feitos, SELinux Enforcing
**nunca** foi a causa de nenhum problema do dpipot (TPROXY com
`privileged: true`/`NET_ADMIN` e captura raw `AF_PACKET` funcionam
normalmente sob Enforcing, contanto que as policies acima estejam
instaladas). Se algo parecer um problema de SELinux, confirme antes de
desativar:
```bash
sudo ausearch -m avc -ts recent   # se vier vazio, SELinux não é a causa
```

---

## Passo 3 — Pacotes base ausentes na imagem mínima

Imagens cloud mínimas de Rocky/RHEL não trazem `tar` nem `git` — ambos são
necessários mais adiante (o instalador do Helm precisa do `tar`; o repo
precisa do `git`).

```bash
sudo dnf install -y tar git
```

---

## Passo 4 — sysctls: aplicar tudo *antes* do deploy, de forma persistente

Este é o passo que evita a maior parte dos problemas de rede do TPROXY. Em
vez de corrigir isso depois que o deploy já falhou, aplique tudo agora.

### 4.1 — `rp_filter` por interface

**Causa do problema:** o NetworkManager do Rocky define `rp_filter=1`
(estrito) por interface, e isso **não é sobrescrito** só ajustando
`net.ipv4.conf.all.rp_filter`/`net.ipv4.conf.default.rp_filter` (diferente de
Ubuntu/netplan, onde isso basta). Um `rp_filter` estrito na interface de
data plane derruba silenciosamente os pacotes marcados pelo TPROXY antes de
chegarem ao socket transparente da aplicação — o TPROXY parece "funcionar"
pra algumas portas (qualquer uma que também tenha outro serviço real
escutando, como SSH) e falhar silenciosamente pras demais.

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

### 4.2 — Interfaces dinâmicas (`veth*`, uma por pod)

O k3s/containerd cria uma interface `veth*` nova a cada pod, e o
NetworkManager aplica `rp_filter=1` a cada uma dessas interfaces novas — uma
entrada estática no `sysctl.d` (passo 4.1) não cobre interfaces que ainda não
existem. A forma robusta de resolver isso **de uma vez**, sem precisar
corrigir manualmente a cada novo pod, é dizer ao NetworkManager pra não
gerenciar essas interfaces:

```bash
sudo tee /etc/NetworkManager/conf.d/99-k3s-cni-unmanaged.conf << 'EOF'
[keyfile]
unmanaged-devices=interface-name:cni0;interface-name:flannel.1;interface-name:veth*
EOF
sudo systemctl reload NetworkManager
```

Com isso, essas interfaces passam a herdar `net.ipv4.conf.default.rp_filter`
(já zerado no passo 4.1) em vez de receber o valor padrão do NetworkManager.

**Comando de debug pra confirmar** (rode isso se suspeitar do TPROXY
funcionando só parcialmente):
```bash
for i in /proc/sys/net/ipv4/conf/*/rp_filter; do echo "$i: $(cat $i)"; done | grep -v ': 0'
```
Se esse comando não imprimir nada, todas as interfaces estão com
`rp_filter=0`. Qualquer linha impressa é uma interface ainda estrita.

### 4.3 — `src_valid_mark`

Deixe em `0` (padrão). Foi testado explicitamente setar `=1` durante o
diagnóstico deste setup e isso **quebrou** conexões que antes funcionavam,
sem resolver nada — não é necessário pro TPROXY do dpipot funcionar.

---

## Passo 5 — Instalar k3s, já vinculado ao control plane

Instale o k3s prendendo o apiserver, o kubelet e o overlay de rede (flannel)
à interface de **control plane** desde o início. Isso evita que qualquer um
desses serviços de gerência do cluster fique acessível pela interface de
dados/internet — o que, por sua vez, elimina a necessidade de regras de
firewall pra bloquear as portas 6443/10250 mais adiante (Passo 8).

O dpipot não usa Ingress nem LoadBalancer — desabilite os dois pra economizar
recurso:

```bash
curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC="\
  --disable=traefik --disable=servicelb \
  --bind-address=<IP_DO_CTRL_IFACE> \
  --advertise-address=<IP_DO_CTRL_IFACE> \
  --node-ip=<IP_DO_CTRL_IFACE> \
  --flannel-iface=<CTRL_IFACE> \
  --kubelet-arg=address=<IP_DO_CTRL_IFACE> \
" sh -

sudo k3s kubectl get nodes   # confirmar Ready
```

> [!NOTE]
> `--flannel-iface` deve apontar pra interface de **control plane**, não
> pra de dados — é por essa interface que o overlay de rede entre nós do
> cluster (VXLAN) circula, e ela não tem motivo pra passar pela interface
> exposta à internet. Se seu cluster for de um nó só (sem outros workers),
> isso não afeta o funcionamento, mas já deixa correto pra quando escalar.
>
> Se este nó algum dia precisar aceitar **outros nós** (workers) se juntando
> ao cluster através da interface de dados (cenário raro, geralmente
> desencorajado), não aplique o `--bind-address`/`--advertise-address` —
> nesse caso, use regras de firewall (Passo 8) como única camada de defesa.

### 5.1 — kubeconfig

**Diferente do MicroK8s:** o `kubectl` do k3s é um symlink pro próprio
binário `k3s`, que por padrão sempre tenta ler
`/etc/rancher/k3s/k3s.yaml` (só root consegue ler), ignorando
`~/.kube/config` mesmo que ele exista e esteja com a permissão certa.

```bash
mkdir -p ~/.kube
sudo cp /etc/rancher/k3s/k3s.yaml ~/.kube/config
sudo chown $(id -u):$(id -g) ~/.kube/config
chmod 600 ~/.kube/config

echo 'export KUBECONFIG=$HOME/.kube/config' >> ~/.bashrc
export KUBECONFIG=$HOME/.kube/config
```

Como o apiserver agora só escuta no IP de control plane (passo 5), o
kubeconfig gerado (que por padrão aponta pra `127.0.0.1:6443`) precisa ser
ajustado:
```bash
sed -i "s/127.0.0.1/<IP_DO_CTRL_IFACE>/" ~/.kube/config
kubectl get nodes   # confirme que ainda funciona com o novo endereço
```

### 5.2 — Instalar o Helm (não vem com o k3s)

```bash
curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
```

---

## Passo 6 — Clonar o repositório

```bash
git clone --branch release/0.3 https://github.com/spawnzao/dpipot-ng.git ~/dpipot-ng
cd ~/dpipot-ng
```

---

## Passo 7 — Hardening: nada de gerência exposto na interface de dados

> [!CAUTION]
> **Liberar regras de firewall sem antes confirmar quais portas/serviços
> estão realmente escutando no servidor é uma brecha de segurança grave.**
> O Passo 8 deste guia libera TCP de forma ampla na interface de dados —
> isso só é seguro depois de garantir, como fazemos aqui, que **nenhum
> serviço de gerência real** (SSH administrativo, API do cluster, kubelet)
> responde nessa interface. Sem esse passo, liberar o firewall de forma
> ampla exporia esses serviços diretamente à internet.

Este passo consolida o princípio "não expor o que não precisa ser exposto",
em vez de depender só de bloqueio na borda (que é frágil: uma regra mal
escrita, um `--reload` do firewalld, ou uma reinstalação futura podem
remover a proteção sem aviso).

### 7.1 — Confirmar que o k3s já está restrito (feito no Passo 5)

```bash
sudo ss -tlnp | grep -E ':6443|:10250'
```
Os dois devem aparecer só no IP de control plane, nunca em `0.0.0.0` nem no
IP da interface de dados.

### 7.2 — Restringir o `sshd` real ao control plane

O honeypot SSH do dpipot (via TPROXY) e o `sshd` real do sistema escutam na
mesma porta (22). Se o `sshd` real continuar respondendo na interface de
dados, ele cria ambiguidade: se o TPROXY cair por qualquer motivo, uma
conexão externa na porta 22 pode ser respondida pelo `sshd` real sem que
isso seja óbvio em testes — e, mais grave, é uma porta de gerência real
exposta à internet.

```bash
sudo tee /etc/ssh/sshd_config.d/99-restrict-listen.conf << EOF
ListenAddress <IP_DO_CTRL_IFACE>
ListenAddress <OUTROS_IPS_DE_GERENCIA_SE_HOUVER>
EOF

sudo sshd -t && echo "config OK"   # sempre valide antes de restart
sudo systemctl restart sshd

# valide com uma conexão NOVA antes de fechar a sessão atual:
ssh -o ConnectTimeout=5 usuario@<IP_DO_CTRL_IFACE> "echo ok"
```

Confirme:
```bash
ss -tlnp | grep :22   # não deve aparecer 0.0.0.0:22
```

### 7.3 — Revisar o inventário de serviços do Passo 1

Volte na lista de serviços/portas que você levantou no Passo 1
(`systemctl list-units --type=service --state=running` e `ss -tlnp`) e
remova ou restrinja qualquer outro serviço de gerência que ainda apareça
escutando de forma ampla (`cockpit`, painéis de administração, etc.) antes
de seguir pro Passo 8. A regra geral: **o único tráfego que deveria chegar
pela interface de dados é o que o TPROXY do dpipot vai interceptar.**

---

## Passo 8 — firewalld: liberar o necessário pro honeypot

A zona padrão do firewalld (`public`) tem política **default-deny**: só
libera os serviços explicitamente listados (`ssh`, `dhcpv6-client`,
`cockpit` por padrão). Qualquer porta fora dessa lista é **rejeitada
silenciosamente**, mesmo *depois* do TPROXY já ter marcado e redirecionado o
pacote corretamente no `mangle`. Isso é fundamentalmente incompatível com a
arquitetura do dpipot, que precisa aceitar conexões em portas arbitrárias
não pré-configuradas.

Isso é diferente do `ufw` (usado em setups Ubuntu), que por padrão é
permissivo — é por isso que esse bug é específico de hosts com firewalld.

### 8.1 — Bloqueio de 6443/10250: opcional depois do Passo 7

Como o Passo 7 já vinculou o apiserver e o kubelet exclusivamente ao control
plane, eles **não respondem** na interface de dados independentemente do
firewall — o bloqueio abaixo é uma camada extra de defesa (redundante, mas
recomendada como boa prática de defesa em profundidade), não a única linha
de proteção:

```bash
sudo firewall-cmd --permanent --direct --add-rule ipv4 filter INPUT 0 -i <DATA_IFACE> -p tcp --dport 6443 -j REJECT
sudo firewall-cmd --permanent --direct --add-rule ipv4 filter INPUT 0 -i <DATA_IFACE> -p tcp --dport 10250 -j REJECT
```
Use regras `--direct`, não reatribuição de zona — mover uma interface "viva"
(com rota ativa) entre zonas faz o NetworkManager reconfigurá-la, o que pode
derrubar a conectividade da rede de pods.

### 8.2 — Liberar TCP para o honeypot na zona ativa

> [!WARNING]
> Confirme o Passo 7 (nenhum serviço de gerência exposto) **antes** de
> rodar o comando abaixo. Ele libera **todo TCP de entrada** na zona ativa
> — se algum serviço de gerência ainda estiver escutando na interface de
> dados nesse ponto, essa regra o expõe diretamente à internet.

```bash
sudo firewall-cmd --permanent --zone=public --add-rich-rule='rule family="ipv4" protocol value="tcp" accept'
```

> **Trade-off:** se `<DATA_IFACE>` e `<CTRL_IFACE>` estiverem na mesma zona
> firewalld, essa regra libera TCP nas duas — rich rules não suportam match
> por interface (interface é o que define a zona, não um critério dentro
> dela). As regras `--direct` do passo 8.1 continuam válidas e são
> terminais independente da zona.

### 8.3 — Se o Logstash/Kafka precisar alcançar um serviço externo (ex:
Elasticsearch central) por uma interface de VPN dedicada

Tráfego roteado (*forwarded*) do host — pod → serviço externo via VPN — passa
pela chain nativa `filter_FORWARD` do firewalld, que **também** é
default-deny. Se a interface da VPN não pertencer a nenhuma zona, esse
tráfego é rejeitado mesmo com o roteamento IP funcionando perfeitamente.

```bash
sudo firewall-cmd --permanent --zone=public --add-interface=<VPN_ES_IFACE>
sudo firewall-cmd --reload
```

Isso gera automaticamente uma regra `oifname "<VPN_ES_IFACE>" accept` na
chain de forward da zona.

> [!CAUTION]
> Um `firewall-cmd --reload` limpa tabelas `nft` não gerenciadas pelo
> firewalld (isso inclui a tabela `mangle` do TPROXY criada pelo init
> container do proxy). **Depois de qualquer `--reload`, reinicie o pod do
> proxy** pra forçar o init container a recriar a configuração:
> ```bash
> kubectl delete pod -n dpipot -l app=dpipot-proxy
> ```
> Fazendo os passos 8.1–8.3 **antes** do deploy (como este guia propõe),
> você evita precisar desse `--reload` depois que o TPROXY já estiver ativo.

**Comando de debug** — se uma porta específica não estiver respondendo,
rastreie o pacote em tempo real por todas as tabelas/chains do netfilter:
```bash
# instala uma regra de trace temporária pra uma porta específica
sudo iptables -t raw -A PREROUTING -i <DATA_IFACE> -p tcp --dport <PORTA> -j TRACE
sudo nft monitor trace   # deixe rodando e gere tráfego pra essa porta
# remova a regra depois:
sudo iptables -t raw -F PREROUTING
```
Procure no output por um `reject` ou `drop` — normalmente aparece na chain
`inet firewalld filter_IN_<zona>` (rejeição do firewalld) ou
`inet firewalld filter_FORWARD` (se for tráfego roteado).

---

## Passo 9 — Values override específico do nó

`storageClass` padrão do k3s é `local-path` (do `local-path-provisioner`),
**diferente** do `microk8s-hostpath` do MicroK8s — sempre faça override
explícito.

```yaml
# k8s/chart/values-<nome-do-no>.yaml
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

# Ajuste conforme a RAM disponível na VM — k3s tem overhead bem menor que
# MicroK8s (~670MB vs ~2.4GB medidos em testes lado a lado), então sobra
# mais RAM pra aplicação mesmo em VMs pequenas.
resources:
  kafka:
    heapOpts: "-Xmx512m -Xms512m"
    requests: { cpu: 200m, memory: 640Mi }
    limits:   { cpu: 500m, memory: 896Mi }
  logstash:
    heapOpts: "-Xmx512m -Xms512m"
```

---

## Passo 10 — Namespace, secrets, ghcr-secret

```bash
kubectl create namespace dpipot

# obrigatório mesmo com imagens públicas (o kubelet exige o secret referenciado
# no chart, ainda que o conteúdo seja um dummy):
kubectl create secret generic ghcr-secret --type=kubernetes.io/dockerconfigjson \
  --from-literal=.dockerconfigjson='{"auths":{}}' -n dpipot

kubectl apply -f k8s/secrets/logstash-secrets.yaml -f k8s/secrets/galah-secrets.yaml
```

---

## Passo 11 — Deploy

```bash
helm upgrade --install dpipot k8s/chart/ \
  -f k8s/chart/values-<nome-do-no>.yaml \
  --namespace dpipot --create-namespace
```

---

## Passo 12 — Verificação final

```bash
kubectl get pods -n dpipot -o wide          # todos Running/Ready
kubectl logs -n dpipot -l app=dpipot-proxy -c proxy --tail=50
sudo ausearch -m avc -ts recent             # deve vir vazio (sem AVC denials)
sudo nft list table ip mangle               # deve mostrar a chain do TPROXY com contador > 0 conforme chega tráfego
```

Teste de conectividade externa **de outra máquina** (não do próprio host —
loopback não passa pelo caminho real do TPROXY):
```bash
# de outra máquina, uma por porta configurada no honeypot:
nc -zv <IP_PUBLICO_DO_NO> 22
nc -zv <IP_PUBLICO_DO_NO> 80
# (Windows) Test-NetConnection -ComputerName <IP_PUBLICO_DO_NO> -Port 80
```

Se alguma porta não responder, use o comando de trace do passo 8.3 antes de
suspeitar do TPROXY em si — na prática, a causa raiz quase sempre esteve no
firewalld, não no proxy.

---

## Referência rápida — diferenças Ubuntu/MicroK8s vs Rocky/k3s

| Item | Ubuntu/MicroK8s | Rocky/k3s |
|---|---|---|
| Overhead do k8s (medido) | ~2.4GB (MicroK8s+Calico) | ~670MB (k3s+flannel+kube-router) |
| `kubectl` | sempre usa `~/.kube/config` | precisa `export KUBECONFIG=~/.kube/config` |
| storageClass padrão | `microk8s-hostpath` | `local-path` |
| Firewall | `ufw`, permissivo por padrão | `firewalld`, **default-deny** por zona |
| SELinux | N/A (AppArmor) | Enforcing — precisa `container-selinux`+`k3s-selinux` antes do k3s |
| `rp_filter` | `all`/`default=0` já basta | sobrescrito por interface pelo NetworkManager — precisa zerar cada interface (ou usar `unmanaged-devices`) |
| Pacotes mínimos ausentes | — | `tar`, `git` não vêm na imagem cloud mínima |
| `kdump`/crashkernel | não reserva RAM por padrão | reserva 200-500MB — remover em VM pequena |

---

## Checklist de troubleshooting (sintoma → causa provável)

| Sintoma | Causa provável | Onde checar |
|---|---|---|
| Só a porta configurada como serviço do sistema (ex: 22/SSH) responde, as demais dão timeout | firewalld rejeitando na zona (passo 8.2) | `sudo nft list chain inet firewalld filter_IN_<zona>_allow`; trace do passo 8.3 |
| Todas as portas do honeypot pararam de responder ao mesmo tempo, depois de um `firewall-cmd --reload` | reload limpou a tabela `mangle` do TPROXY | `sudo nft list table ip mangle` (vazia?) → reiniciar pod do proxy |
| TPROXY marca o pacote (`iptables -t mangle` conta) mas nunca entrega ao app | `rp_filter` estrito em alguma interface no caminho | passo 4.1/4.2, comando de debug de rp_filter |
| Pod não alcança serviço externo via VPN, "no route to host" mas o host consegue pingar | firewalld FORWARD rejeitando (interface da VPN fora de qualquer zona) | passo 8.3 |
| `kubectl` para de funcionar depois do Passo 5 | kubeconfig ainda aponta pra `127.0.0.1` após o apiserver ser restrito ao control plane | passo 5.1 |
| AVC denial suspeito | quase nunca é isso — confirme antes de desativar SELinux | `sudo ausearch -m avc -ts recent` |
