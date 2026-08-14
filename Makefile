NAMESPACE ?= dpipot
export PATH := $(PATH):/usr/local/go/bin
export LD_LIBRARY_PATH := /usr/local/lib:$(LD_LIBRARY_PATH)

.PHONY: build setup-tproxy stop-all test-tproxy
.PHONY: addons deploy-dev deploy-prod update status logs logs-kafka clean help

# ===========================================
# BUILD
# ===========================================

build:
	@echo "=== Build dpipot ==="
	CGO_ENABLED=1 go build -o dpipot ./cmd/dpipot
	@echo "Binary: ./dpipot"

# ===========================================
# TPROXY LOCAL
# ===========================================

setup-tproxy:
	@echo "=== Setup TPROXY ==="
	sudo sysctl -w net.ipv4.ip_forward=1
	sudo sysctl -w net.ipv4.conf.all.route_localnet=1
	sudo sysctl -w net.ipv4.conf.all.rp_filter=0
	sudo sysctl -w net.ipv4.conf.default.rp_filter=0
	grep -q "100 tproxy" /etc/iproute2/rt_tables || echo "100 tproxy" | sudo tee -a /etc/iproute2/rt_tables
	sudo ip rule add fwmark 0x1 lookup 100 2>/dev/null || true
	sudo ip route add local default dev lo table 100 2>/dev/null || true
	sudo iptables -t mangle -N TEST-TPROXY 2>/dev/null || true
	sudo iptables -t mangle -A TEST-TPROXY -p tcp --dport 50000:55000 -j MARK --set-mark 0x1
	sudo iptables -t mangle -A TEST-TPROXY -p tcp --dport 50000:55000 -j TPROXY --tproxy-mark 0x1/0x1 --on-port 8080
	sudo iptables -t mangle -A PREROUTING -p tcp -j TEST-TPROXY
	@echo "OK - Verifique com: sudo iptables -t mangle -L TEST-TPROXY -v -n"

stop-all:
	@pkill -9 dpipot 2>/dev/null; echo "Serviços parados"

test-tproxy:
	@echo "Testando TPROXY (enviando para 127.0.0.1:50001)..."
	@echo -e "GET / HTTP/1.1\r\nHost: test\r\n\r\n" | nc 127.0.0.1 50001 || true
	@echo "" && sudo iptables -t mangle -L TEST-TPROXY -v -n

# ===========================================
# KUBERNETES
# ===========================================

addons:
	microk8s enable dns hostpath-storage helm3

deploy-dev:
	microk8s helm3 -n $(NAMESPACE) upgrade --install dpipot k8s/chart/ --create-namespace
	microk8s kubectl rollout status daemonset/dpipot-proxy -n $(NAMESPACE) --timeout=120s

deploy-prod:
	microk8s helm3 -n $(NAMESPACE) upgrade --install dpipot k8s/chart/ -f k8s/chart/values-prod.yaml --create-namespace
	microk8s kubectl rollout status daemonset/dpipot-proxy -n $(NAMESPACE) --timeout=120s

update:
	microk8s kubectl rollout restart daemonset/dpipot-proxy -n $(NAMESPACE)

status:
	microk8s kubectl get pods,svc -n $(NAMESPACE) -o wide

logs:
	microk8s kubectl logs -n $(NAMESPACE) -l app=dpipot-proxy -f

logs-kafka:
	microk8s kubectl logs -n $(NAMESPACE) -l app=kafka -f

# ===========================================
# CLEAN
# ===========================================

clean:
	rm -f dpipot

help:
	@echo "=== dpipot-ng Makefile ==="
	@echo ""
	@echo "Build:"
	@echo "  make build             Build binário dpipot unificado"
	@echo ""
	@echo "TPROXY Local:"
	@echo "  make setup-tproxy      Configurar regras TPROXY e iptables"
	@echo "  make stop-all          Parar processo dpipot"
	@echo "  make test-tproxy       Testar TPROXY"
	@echo ""
	@echo "Kubernetes:"
	@echo "  make addons            Habilitar addons MicroK8s (dns, hostpath-storage, helm3)"
	@echo "  make deploy-dev        Deploy com valores padrão (Helm)"
	@echo "  make deploy-prod       Deploy prod (Helm, values-prod.yaml)"
	@echo "  make update            Restart rolling do daemonset"
	@echo "  make status            Status pods e services"
	@echo "  make logs              Logs do dpipot-proxy"
	@echo "  make logs-kafka        Logs do Kafka"
	@echo ""
	@echo "Util:"
	@echo "  make clean             Remover binário local"
