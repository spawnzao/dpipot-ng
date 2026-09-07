# dpipot-proxy Standalone (Somente Proxy) — k3s + Flannel

Este guia configura um nó **somente proxy**: captura o tráfego de internet (TPROXY
+ nDPI), classifica e encaminha as conexões para um nó remoto de honeypots, sem
executar honeypots localmente.

```
Internet → [nó proxy] ──WireGuard──> [nó honeypot]
              TPROXY + nDPI            cowrie/heralding/galah/wordpot
              dpipot-proxy
              Kafka + Logstash → ES
```

O nó proxy usa k3s com Flannel (sem Cilium — o TPROXY funciona com o kube-proxy
padrão). O nó honeypot é configurado separadamente; veja
[honeypot-standalone-k3s-cilium.md](honeypot-standalone-k3s-cilium.md).

---

## Pré-requisitos

- Debian 12+, Ubuntu 22.04+ ou Rocky Linux 9 no nó proxy
- Duas interfaces de rede:
  - **interface de controle/admin** (`<ADMIN_IFACE>`): SSH, WireGuard admin, tráfego do cluster
  - **interface de dados** (`<DATA_IFACE>`): voltada para o tráfego de internet a ser capturado
- Helm 3 instalado na sua estação de trabalho
- Nó honeypot remoto já implantado e acessível via rede WireGuard isolada
- Acesso ao cluster Elasticsearch (endpoint + chave de API)

---

## 1. Instalar k3s (Flannel, sem substituição do kube-proxy)

```bash
curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC=" \
  --node-ip=<IP_DA_IFACE_ADMIN> \
  --advertise-address=<IP_DA_IFACE_ADMIN> \
  --bind-address=<IP_DA_IFACE_ADMIN> \
  --flannel-iface=<ADMIN_IFACE> \
  --disable=traefik \
" sh -
```

> **Nota:** Não use `--disable-kube-proxy` aqui — o kube-proxy padrão funciona
> perfeitamente para o pipeline proxy. O Cilium é usado somente no nó honeypot.

Aguarde o nó ficar pronto:

```bash
sudo k3s kubectl get nodes
```

---

## 2. Corrigir `rp_filter` na interface de dados

> **Importante:** `net.ipv4.conf.all.rp_filter=0` sozinho **não é suficiente**.
> O kernel usa o valor **mais restritivo** entre `all` e a interface específica.
> Em uma interface de dados sem gateway próprio (roteamento assimétrico), o
> `rp_filter` estrito na interface descarta silenciosamente todos os pacotes
> de entrada — inclusive ICMP — mesmo com o `all` relaxado.

Configure os dois:

```bash
cat >> /etc/sysctl.d/99-dpipot.conf << 'EOF'
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.<DATA_IFACE>.rp_filter = 0
net.ipv4.conf.all.forwarding = 1
net.ipv4.ip_forward = 1
EOF

sysctl -p /etc/sysctl.d/99-dpipot.conf
```

Verifique:

```bash
sysctl net.ipv4.conf.all.rp_filter net.ipv4.conf.<DATA_IFACE>.rp_filter
# Ambos devem ser 0
```

---

## 3. Corrigir vazamento do WireGuard pela interface de dados

> **Contexto:** Se o IP do `Endpoint` do peer WireGuard estiver na mesma /25 (ou
> sub-rede similar) que o IP da interface de dados, o kernel pode rotear os pacotes
> UDP do WireGuard pela interface de dados via rota diretamente conectada — que
> tem precedência sobre qualquer rota explícita via interface de controle. Isso
> faz o handshake do WireGuard sair pela interface errada e falhar silenciosamente.
>
> **Solução:** Usar `FwMark` na interface WireGuard e uma tabela de roteamento
> dedicada que força todos os pacotes do WireGuard pela interface de controle.

Edite `/etc/wireguard/<ADMIN_WG_IFACE>.conf` (sua interface WireGuard de admin):

```ini
[Interface]
PrivateKey = <CHAVE_PRIVADA_WG_ADMIN>
Address = <ENDERECO_WG_ADMIN>/24
FwMark = 0x64
Table = off          # não instala rotas na tabela principal

PostUp = ip rule add fwmark 0x64 table 200 priority 100
PostUp = ip route add default via <GW_IFACE_ADMIN> dev <ADMIN_IFACE> table 200
PostDown = ip rule del fwmark 0x64 table 200 priority 100
PostDown = ip route del default via <GW_IFACE_ADMIN> dev <ADMIN_IFACE> table 200

[Peer]
PublicKey = <CHAVE_PUBLICA_WG_NO_HONEYPOT>
Endpoint = <IP_PUBLICO_NO_HONEYPOT>:51820
AllowedIPs = <CIDR_REDE_WG_HONEYPOT>
PersistentKeepalive = 25
```

> `FwMark = 0x64` marca os pacotes UDP de saída do WireGuard. A regra `ip rule`
> envia esses pacotes marcados para a tabela 200, que tem uma rota forçada via
> interface de controle — garantindo que o tráfego WireGuard nunca toque a
> interface de dados.

Aplique:

```bash
wg-quick down <ADMIN_WG_IFACE> 2>/dev/null || true
wg-quick up <ADMIN_WG_IFACE>
```

---

## 4. Criar o namespace e os secrets

```bash
sudo k3s kubectl create namespace dpipot
```

**Credenciais do Elasticsearch** (pipeline Logstash):

```bash
sudo k3s kubectl -n dpipot create secret generic logstash-elasticsearch-secrets \
  --from-literal=ES_HOST="https://<HOST_ES>:9200" \
  --from-literal=ES_API_KEY="<CHAVE_API_ES>"
```

**Certificado CA do Elasticsearch** (se usar HTTPS):

```bash
sudo k3s kubectl -n dpipot create secret generic elastic-certs \
  --from-file=ca.crt=/caminho/para/ca.crt
```

---

## 5. Configurar `values-proxy-only.yaml`

Copie o arquivo de exemplo e preencha os valores:

```bash
cp k8s/chart-standalone/values-proxy-only.yaml \
   k8s/chart-standalone/values-<hostname>.yaml
```

Campos principais a configurar:

```yaml
network:
  interface: "<DATA_IFACE>"    # ex.: ens192, eth1

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
  HONEYPOT_ROUTES: "<IP_WG_HONEYPOT>:<PORTA>"
  LOG_LEVEL: "info"
```

---

## 6. Implantar com Helm

```bash
cd /caminho/para/dpipot-ng

helm install dpipot-standalone k8s/chart-standalone/ \
  -n dpipot \
  -f k8s/chart-standalone/values-<hostname>.yaml
```

Acompanhe o status dos pods:

```bash
sudo k3s kubectl -n dpipot get pods -w
```

---

## 7. Verificar as regras TPROXY

Após o `dpipot-proxy` iniciar, confirme que o init container aplicou as regras:

```bash
sudo iptables -t mangle -L PREROUTING -n -v | grep TPROXY
# Esperado: regra redirecionando TCP em <DATA_IFACE> para 127.0.0.1:8080

sudo ip rule show
# Esperado: fwmark 0x1 lookup 100

sudo ip route show table 100
# Esperado: local 0.0.0.0/0 dev lo
```

---

## 8. Verificar conectividade com o Kafka

```bash
sudo k3s kubectl -n dpipot exec -it deploy/kafka -- \
  /opt/kafka/bin/kafka-topics.sh \
  --bootstrap-server localhost:9092 \
  --list
```

Os tópicos `dpipot.events.proxy` e `dpipot.events.classifier` devem aparecer
após as primeiras conexões passarem pelo proxy.

---

## 9. Verificar o pipeline Logstash → Elasticsearch

Acompanhe os logs do Logstash:

```bash
sudo k3s kubectl -n dpipot logs deploy/logstash -f
```

Procure por `Pipeline started` para os dois pipelines (`kafka-to-elasticsearch`
e `kubernetes-logs`).

Verifique a criação dos índices no Elasticsearch:

```bash
curl -s -H "Authorization: ApiKey <CHAVE_API_ES>" \
  "https://<HOST_ES>:9200/_cat/indices/dpipot-proxy-*?v"
```

---

## 10. Resolução de problemas

| Sintoma | Causa provável | Solução |
|---|---|---|
| Pacotes de entrada em `<DATA_IFACE>` descartados silenciosamente | `rp_filter` configurado apenas no `all`, não na interface específica | Defina `net.ipv4.conf.<DATA_IFACE>.rp_filter=0` explicitamente |
| Handshake WireGuard para o nó honeypot falha | Pacotes WG roteados pela interface de dados (rota conectada tem prioridade) | Adicione `FwMark` + rota na tabela 200 via interface de controle |
| `dpipot-proxy` não está capturando tráfego | Regras TPROXY ausentes ou interface errada | Verifique logs do init container; confirme `network.interface` nos values |
| Logstash não grava no ES | `ES_HOST` ou `ES_API_KEY` incorretos, CA ausente | Verifique o conteúdo dos secrets e o secret `elastic-certs` |
| Tópicos não aparecem no Kafka | `dpipot-proxy` não consegue alcançar o Kafka | Verifique `KAFKA: "true"` no ConfigMap e o Service `kafka-svc` |
