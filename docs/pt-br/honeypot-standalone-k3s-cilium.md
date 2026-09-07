# Honeypots standalone (sem dpipot-ng) em k3s + Cilium, isolados por WireGuard

Este guia documenta como montar um host que roda **só os honeypots**
(`cowrie`, `heralding`, `wordpot`, `galah`) — sem `dpipot-proxy`, sem
TPROXY, sem nDPI local. Um `dpipot-ng` remoto (rodando noutro host, com o
proxy/classificador) é quem encaminha o tráfego já classificado pra cá.

Isso é útil quando você quer separar a superfície de ataque real (o host
com TPROXY, exposto à internet) do host que efetivamente roda os
honeypots — reduzindo o "raio de explosão" se um honeypot for
comprometido, e permitindo testar várias combinações de orquestração/CNI
sem afetar produção.

Diferente dos outros guias deste repositório (Rocky, Ubuntu, Debian), aqui
**não tem interface de dados nenhuma exposta à internet** — o host só
existe dentro de redes privadas (WireGuard). Se você está procurando o
guia de um nó completo (proxy + honeypots), veja
[ubuntu-linux-setup.md](ubuntu-linux-setup.md) ou
[rocky-linux-setup.md](rocky-linux-setup.md).

> [!NOTE]
> Este modo usa um **chart Helm separado** (`k8s/chart-standalone/`), não
> o chart principal (`k8s/chart/`) usado nos outros guias. É uma decisão
> deliberada: em vez de acrescentar flags condicionais (`dpipotProxy.
> enabled`, `hostExpose.enabled`, etc.) no chart de produção pra suportar
> os dois modos, o modo standalone vive isolado num chart próprio — zero
> risco de regressão no chart usado pelos nós de produção normais.

## Convenções usadas neste guia

Este host tem (pelo menos) 4 interfaces, cada uma com um papel bem
específico — **nenhuma delas é "a interface de dados"**, já que não há
TPROXY aqui:

- **Saída externa** (`<EXT_IFACE>`, ex. `ens18`): só usada pelo próprio
  host pra sair pra internet (atualização de pacotes, etc.) — **nenhum
  serviço administrativo escuta nela**.
- **Admin primária** (`<ADMIN_WG_IFACE>` / `<ADMIN_CIDR>`, ex. `wg0`,
  `10.X.X.0/24`): malha WireGuard de gerência — SSH, API do k3s, agente
  Cilium.
- **Admin backup** (`<ADMIN_BACKUP_WG_IFACE>` / `<ADMIN_BACKUP_CIDR>`, ex.
  `wg1`, `10.Y.Y.0/24`): segunda malha de administração, independente da
  primeira (redundância — se o servidor WireGuard de uma malha cair, a
  outra continua de pé). Tratada com o mesmo nível de confiança da admin
  primária.
- **Rede de honeypot** (`<HONEYPOT_WG_IFACE>` / `<HONEYPOT_CIDR>`, ex.
  `wg2`, `10.Z.Z.0/24`): rede isolada, **sem rota de internet, sem DNS**.
  É por ela que o `dpipot-proxy` remoto alcança os honeypots deste host.
  Nenhuma outra interface tem visibilidade dela.

> [!CAUTION]
> **As 3 malhas WireGuard não devem se enxergar entre si no roteamento do
> host.** Isso não é automático — WireGuard não faz bridging entre
> interfaces diferentes por padrão (cada uma é isolada por natureza), mas
> se alguém adicionar uma rota estática ou uma regra de `FORWARD`
> "temporária pra debugar" ligando duas delas, o isolamento quebra
> silenciosamente. Nenhuma regra desse tipo é necessária neste guia —
> se você planeja permitir a malha admin **iniciar** conexão pra dentro da
> rede de honeypot (ex. pra investigar um honeypot comprometido), isso
> precisa de uma regra de firewall com estado (`conntrack`), fora do
> escopo deste guia.

Troque todos os placeholders (`<...>`) pelos valores reais do seu
ambiente.

---

## Passo 1 — Levantamento inicial

Antes de tocar em qualquer coisa, confirme o que já existe:

```bash
hostname
ip -br a
ip route
sudo wg show          # confirmar que as 3 interfaces WireGuard já existem
ss -tulpn             # portas já em uso — importante, vamos bindar 21/22/23/
                       # 25/80/110/143/3306/3389/5432/5900/2222/5900 depois
df -h /
```

> [!NOTE]
> Este guia assume que as 3 interfaces WireGuard (`<ADMIN_WG_IFACE>`,
> `<ADMIN_BACKUP_WG_IFACE>`, `<HONEYPOT_WG_IFACE>`) **já estão configuradas
> e ativas** antes de começar — a criação delas foge do escopo deste guia
> (depende do seu provedor/topologia de WireGuard).

---

## Passo 2 — Sudo temporário (se necessário)

Se o `sudo` do seu usuário pede senha interativa e você vai rodar os
comandos deste guia via automação (script, agente, CI), libere
temporariamente e **remova no final**:

```bash
echo "<seu-usuario> ALL=(ALL) NOPASSWD:ALL" | sudo tee /etc/sudoers.d/90-temp
sudo chmod 440 /etc/sudoers.d/90-temp
sudo visudo -c                          # valida a sintaxe antes de confiar nela

# ao final de tudo:
# sudo rm /etc/sudoers.d/90-temp
```

---

## Passo 3 — Hardening do SSH: só nas interfaces de admin

Nada de administração deve escutar na interface de saída externa nem na
rede de honeypot.

```bash
sudo tee /etc/ssh/sshd_config.d/90-listen-admin-only.conf > /dev/null <<EOF
ListenAddress <IP_DO_ADMIN_WG_IFACE>
ListenAddress <IP_DO_ADMIN_BACKUP_WG_IFACE>
EOF
sudo sshd -t && echo OK    # valida a sintaxe ANTES de reiniciar
```

> [!CAUTION]
> **Bug conhecido (corrida `sshd` vs `wg-quick` no boot)**: por padrão a
> unit do `ssh` não depende do WireGuard — em alguns boots o `sshd` tenta
> bindar o `ListenAddress` antes da interface WireGuard existir, e fica
> preso na interface que já estava de pé (pode levar minutos até alguém
> reiniciar o serviço manualmente). Corrija **antes** de reiniciar o SSH:
> ```bash
> sudo mkdir -p /etc/systemd/system/ssh.service.d
> sudo tee /etc/systemd/system/ssh.service.d/90-wait-wireguard.conf > /dev/null <<EOF
> [Unit]
> After=wg-quick@<ADMIN_WG_IFACE>.service wg-quick@<ADMIN_BACKUP_WG_IFACE>.service
> Wants=wg-quick@<ADMIN_WG_IFACE>.service wg-quick@<ADMIN_BACKUP_WG_IFACE>.service
> EOF
> sudo systemctl daemon-reload
> ```

Reinicie com uma rede de segurança (revert automático se você perder
acesso):

```bash
sudo bash -c '
  (sleep 45 && ! systemctl is-active --quiet ssh && \
    rm -f /etc/ssh/sshd_config.d/90-listen-admin-only.conf && \
    systemctl restart ssh) &
  systemctl restart ssh
'
# confirme que reconectou ANTES de continuar:
ssh <usuario>@<IP_DO_ADMIN_WG_IFACE> "echo RECONNECT_OK"
```

---

## Passo 4 — Instalar k3s (sem kube-proxy, sem CNI padrão)

```bash
curl -sfL https://get.k3s.io | sudo sh -s - server \
  --flannel-backend=none \
  --disable-kube-proxy \
  --disable-network-policy \
  --disable=traefik \
  --disable=servicelb \
  --bind-address=<IP_DO_ADMIN_WG_IFACE> \
  --node-ip=<IP_DO_ADMIN_WG_IFACE> \
  --advertise-address=<IP_DO_ADMIN_WG_IFACE> \
  --tls-san=<IP_DO_ADMIN_BACKUP_WG_IFACE> \
  --write-kubeconfig-mode 644
```

> [!CAUTION]
> **`--disable-kube-proxy` não é opcional se você vai usar Cilium com
> `kubeProxyReplacement=true`** (próximo passo). Sem essa flag, o
> kube-proxy embutido do k3s e o Cilium brigam pelas mesmas regras de
> rede — sintoma: `coredns`/`local-path-provisioner`/`metrics-server`
> ficam em `CrashLoopBackOff` com erro `i/o timeout` tentando alcançar o
> `ClusterIP` da API (`10.43.0.1:443` ou equivalente). Isso só afeta
> **pods**, não o host — testar com `curl` do próprio host pro
> `ClusterIP` funciona normalmente, escondendo o problema se você não
> testar de dentro de um pod.

```bash
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
kubectl get nodes -o wide   # NotReady é esperado, sem CNI ainda
```

---

## Passo 5 — Helm + Cilium

```bash
curl -sfL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | sudo bash

helm repo add cilium https://helm.cilium.io/
helm repo update

helm install cilium cilium/cilium --version 1.16.5 --namespace kube-system \
  --set kubeProxyReplacement=true \
  --set k8sServiceHost=<IP_DO_ADMIN_WG_IFACE> \
  --set k8sServicePort=6443 \
  --set operator.replicas=1 \
  --set devices='{<ADMIN_WG_IFACE>,<ADMIN_BACKUP_WG_IFACE>}'
```

> [!WARNING]
> **`devices` precisa listar explicitamente as interfaces de admin** — sem
> essa opção, o Cilium autodetecta **todas** as interfaces do host
> (incluindo a de saída externa e a rede de honeypot), o que confunde o
> datapath de `kubeProxyReplacement` (mesmo sintoma do bug acima:
> `ClusterIP` inacessível de dentro de pods). Se você tem duas malhas de
> admin (como neste guia), liste as duas — `devices` aceita uma lista.

```bash
# aguardar o cilium ficar pronto (pode levar 1-2min):
kubectl -n kube-system rollout status daemonset/cilium
kubectl get nodes -o wide   # agora deve estar Ready
```

---

## Passo 6 — `ufw`: desabilitar ou liberar tráfego roteado

Muitas imagens Ubuntu vêm com `ufw` pré-habilitado, com política
`deny (routed)`/`deny (incoming)` por padrão.

```bash
sudo ufw status verbose
```

> [!CAUTION]
> **`ufw` com política `deny` em `FORWARD` quebra qualquer CNI** — todo
> tráfego pod↔host fica bloqueado, mesmo com o Cilium 100% correto.
> Sintoma idêntico ao dos dois bugs anteriores (pods não alcançam o
> `ClusterIP`/API), então é fácil confundir a causa se você já mexeu no
> k3s/Cilium antes de checar o `ufw`. Se a única regra existente for
> SSH — e o `sshd` já está restrito por `ListenAddress` (Passo 3) — essa
> regra do `ufw` é redundante:
> ```bash
> sudo ufw disable
> ```
> Se você precisa manter o `ufw` ativo por outro motivo, libere
> explicitamente o CIDR dos pods do Cilium e as interfaces WireGuard no
> `FORWARD`/`INPUT` — mais regras pra manter, redundante com o que o
> Cilium já faz.

Valide de dentro de um pod (não só do host — o host sempre vai conseguir,
mesmo com o bug presente):

```bash
kubectl run debugtest --image=busybox:stable --restart=Never --rm -i \
  --timeout=15s -- wget -T3 -O- https://<IP_DO_ADMIN_WG_IFACE>:6443/healthz
```

---

## Passo 7 — Clonar o repositório

```bash
git clone https://github.com/spawnzao/dpipot-ng.git ~/dpipot-ng
cd ~/dpipot-ng/k8s/chart-standalone
```

> [!NOTE]
> Repare que é `k8s/chart-standalone/`, **não** `k8s/chart/` (usado nos
> outros guias). É um chart Helm independente, com seus próprios
> `Chart.yaml`/`values.yaml`/`templates/` — não compartilha nada com o
> chart de produção, então instalar/desinstalar aqui nunca afeta um nó
> completo.

---

## Passo 8 — Imagem do túnel WireGuard do `galah` (build-time, não runtime)

O `galah` sobe seu **próprio túnel WireGuard** (`wg-llm`), isolado, só pra
falar com o backend LLM — os outros honeypots não têm essa capability. Como
a rede de honeypot não tem internet (Passo 10), o `initContainer` que sobe
esse túnel **não pode instalar pacotes em tempo de execução**.

Construa a imagem numa máquina **com** internet (não precisa ser o host
de honeypot):

```bash
mkdir wg-tools-image && cd wg-tools-image
cat > Dockerfile <<'EOF'
FROM alpine:3.19
RUN apk add --no-cache wireguard-tools iproute2
EOF
docker build -t dpipot/wg-tools:3.19 .
docker save dpipot/wg-tools:3.19 -o wg-tools.tar
scp wg-tools.tar <usuario>@<IP_DO_ADMIN_WG_IFACE>:~/
```

No host de honeypot, importe direto no containerd do k3s (sem precisar
de um registry):

```bash
sudo k3s ctr images import ~/wg-tools.tar
sudo k3s ctr images ls | grep wg-tools
rm ~/wg-tools.tar
```

---

## Passo 9 — Secrets do `galah` (túnel WireGuard + API key do LLM)

Gere o `.conf` do WireGuard do lado do backend LLM (fora do escopo deste
guia — depende de como você provisiona o peer, e só é necessário se
`honeypots.galah.wgTunnel.enabled: true`, o padrão deste chart). Crie o
Secret **direto no cluster**, sem passar a chave privada por nenhum
arquivo intermediário desnecessário:

```bash
kubectl create namespace dpipot --dry-run=client -o yaml | kubectl apply -f -
kubectl -n dpipot create secret generic galah-wg-secret \
  --from-file=wg-llm.conf=<caminho-do-seu-galah-wg.conf>
```

> [!NOTE]
> O nome do arquivo dentro do Secret (`wg-llm.conf`) importa — ele vira o
> nome da interface (`wg-llm`) quando o `initContainer` roda `wg-quick up
> /etc/wireguard-secret/wg-llm.conf`.

O `galah` também precisa da API key do provedor LLM configurado em
`honeypots.galah.llmApiBase` (veja `k8s/secrets/galah-llm-api-key.yaml.example`
pro formato):

```bash
kubectl -n dpipot create secret generic galah-llm-api-key \
  --from-literal=api_key=<sua-chave-ou-valor-fixo-do-seu-backend>
```

---

## Passo 10 — Values override específico do host

O `k8s/chart-standalone/values.yaml` já traz o modo standalone como
único modo (sem flags pra "ligar/desligar" — diferente do chart
principal, aqui não tem outro jeito de rodar), e o `galah` já vem
apontado por padrão pra um provedor externo genérico (Groq) — assim como
o chart principal, pra não embutir nenhuma infraestrutura própria como
"padrão" do repositório. Copie `values-honeypots.yaml` (o exemplo
versionado) pra `values-<nome-do-host>.yaml` e troque os placeholders:

```yaml
hostExpose:
  ip: "<IP_DO_HONEYPOT_WG_IFACE>"

honeypotIsolation:
  allowedIngressCIDR: "<HONEYPOT_CIDR>"   # só o dpipot-proxy remoto
  galahWgEndpoint:
    ip: "<IP_PUBLICO_DO_ENDPOINT_WG_DO_LLM>"
    port: 51820

honeypots:
  galah:
    # só sobrescreva model/llmApiBase se for usar um backend LLM
    # próprio via túnel - o padrão (Groq) já funciona sem isso
    model: "<MODELO_DO_SEU_BACKEND_LLM>"
    llmApiBase: "http://<IP_INTERNO_DO_TUNEL_ATE_O_LLM>:8000/v1"
```

> [!WARNING]
> **Conflito de porta 80 entre `heralding` e `wordpot`**: os dois têm um
> módulo HTTP na porta 80. Isso nunca dá problema nos nós com
> `dpipot-proxy` local (cada honeypot tem seu próprio `ClusterIP`), mas
> aqui os dois vão tentar bindar o **mesmo** `hostIP:80` — o pod que
> perder a corrida de agendamento fica `Pending` com `didn't have free
> ports for the requested pod ports`. O `values.yaml` padrão deste chart
> já vem com `honeypots.heralding.disableHttpModule: true` justamente por
> isso — o `wordpot` cobre HTTP genérico. Se seu `dpipot-proxy` remoto
> distinguir `HTTP` de `HTTP_AUTH` na classificação, ambos precisam
> apontar pro `wordpot` neste host específico (perdendo essa distinção só
> aqui). Só mude pra `false` se tiver certeza que não há conflito no seu
> caso (ex.: `wordpot` desabilitado).

Cada honeypot já binda via `hostPort` + `hostIP` (mantendo o pod no seu
próprio namespace de rede — diferente de `hostNetwork: true`, que
compartilharia a rede do host inteira e faria a `NetworkPolicy` deixar de
valer pra esse pod). Isso é comportamento fixo deste chart, não uma opção.

---

## Passo 11 — Deploy

```bash
helm lint . -f values.yaml -f values-<nome-do-host>.yaml
helm template . -f values.yaml -f values-<nome-do-host>.yaml | less   # revise antes de aplicar
helm install dpipot-standalone . -f values.yaml -f values-<nome-do-host>.yaml -n dpipot
```

```bash
kubectl -n dpipot get pods -o wide
kubectl -n dpipot get pvc
```

---

## Passo 12 — Verificação

Confirme que o `galah` sobe o túnel:

```bash
POD=$(kubectl -n dpipot get pod -l app=galah -o jsonpath='{.items[0].metadata.name}')
kubectl -n dpipot logs $POD -c wg-tunnel --tail=10
# esperado: "ip link set mtu ... up dev wg-llm"
```

Force uma resposta via LLM (path que não bate em nenhuma regra estática)
e confirme no log:

```bash
POD_IP=$(kubectl -n dpipot get pod -l app=galah -o jsonpath='{.items[0].status.podIP}')
curl -s -m 30 http://$POD_IP:8080/admin/config.php -o /dev/null
kubectl -n dpipot logs $POD -c galah --tail=5
# esperado: "generated HTTP response: ..." e "sent the response to ... (source: llm)"
```

> [!NOTE]
> Testar via `curl` direto do **próprio host** pro `hostIP:hostPort`
> (ex. `<IP_DO_HONEYPOT_WG_IFACE>:8080`) pode dar "empty reply" mesmo
> com tudo funcionando — é um artefato de auto-teste (o tráfego vira
> loopback local em vez de atravessar o caminho de ingress real). A
> validação de verdade só é conclusiva vindo de **outro host** na rede
> de honeypot (o `dpipot-proxy` remoto de verdade).

Confirme que o isolamento de DNS/internet está valendo — o `galah` tenta
um lookup reverso de enriquecimento por padrão; ele **deve falhar**:

```bash
kubectl -n dpipot logs $POD -c galah --tail=10 | grep -i "lookup"
# esperado: "i/o timeout" — se resolver, a NetworkPolicy não está aplicando
```

---

## Referência rápida — diferenças vs. um nó completo (proxy + honeypots)

| Item | Nó completo (Rocky/Ubuntu/Debian) | Honeypot standalone (este guia) |
|---|---|---|
| `dpipotProxy` | Habilitado (DaemonSet, `hostNetwork: true`) | Desabilitado |
| CNI | Flannel (padrão do k3s) ou Calico | Cilium (`kubeProxyReplacement`) |
| Exposição dos honeypots | `ClusterIP`, consumido pelo `dpipot-proxy` local | `hostPort`+`hostIP`, consumido por um `dpipot-proxy` remoto via WireGuard |
| `NetworkPolicy` | `honeypots-isolation` (libera DNS geral + LLM externo) | `honeypot-full-isolation` (nega tudo, exceção só pro túnel `wg-llm` do galah) |
| Backend LLM do `galah` | Direto via malha admin (`OPENAI_API_BASE` aponta pro IP do LLM) | Via túnel WireGuard próprio `wg-llm`, dentro do pod (`wgTunnel.enabled`) |
| `heralding` porta 80 | Sempre habilitado, sem conflito (ClusterIP próprio) | Desabilitado se `wordpot` também estiver no mesmo `hostIP` |

---

## Checklist de troubleshooting (sintoma → causa provável)

| Sintoma | Causa provável | Onde checar |
|---|---|---|
| `coredns`/`local-path-provisioner`/`metrics-server` em `CrashLoopBackOff`, erro `i/o timeout` pro `ClusterIP` da API | k3s instalado sem `--disable-kube-proxy` (briga com o `kubeProxyReplacement` do Cilium) | Passo 4 |
| Mesmo sintoma acima, mas já com `--disable-kube-proxy` | Cilium autodetectou interfaces demais (`devices`) | Passo 5 |
| Mesmo sintoma acima, mas Cilium com `devices` correto | `ufw` com política `deny` em `FORWARD` | Passo 6 |
| PVC do `galah` fica `Pending` pra sempre | `storageClass` errada (`microk8s-hostpath` só existe no MicroK8s) — no k3s use `local-path` | Passo 10 |
| Pod do `heralding` ou `wordpot` fica `Pending` com `didn't have free ports` | Conflito de porta 80 entre os dois no mesmo `hostIP` | Passo 10 |
| `initContainer` do `galah` trava em `apk add`/`ContainerCreating` por muito tempo | Pod já sob `NetworkPolicy` sem internet — `apk` nunca resolve | Passo 8 |
| `galah` responde só com regras estáticas, nunca via LLM | Path testado bate na regra `^/$`/outra regra estática do `rules.yaml` — teste um path diferente | Passo 12 |
| `curl` do próprio host pro `hostIP:hostPort` do honeypot dá "empty reply" mas o log do pod mostra que respondeu | Auto-teste via loopback, não é o caminho real de ingress — teste de outro host na rede de honeypot | Passo 12 (nota) |
| `galah` consegue resolver DNS (lookup funciona) quando não deveria | `NetworkPolicy honeypot-full-isolation` não foi aplicada, ou `podSelector`/namespace errados | Passo 10, Passo 12 |
