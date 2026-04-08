NAMESPACE ?= dpipot
export PATH := $(PATH):/usr/local/go/bin
export LD_LIBRARY_PATH := /usr/local/lib:$(LD_LIBRARY_PATH)

.PHONY: addons deploy-dev deploy-prod status logs-proxy logs-ndpi logs-kafka test clean
.PHONY: build build-proxy build-classifier setup-tproxy start-classifier start-proxy start-all stop-all test-tproxy

# ===========================================
# BUILD
# ===========================================

build: build-proxy build-classifier

build-proxy:
	@echo "=== Build Proxy (Go) ==="
	cd proxy && go build -o dpipot-proxy ./cmd/proxy
	@echo "Proxy: proxy/dpipot-proxy"

build-classifier:
	@echo "=== Build Classifier (C) ==="
	cd classifier && make
	@echo "Classifier: classifier/classifier"

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

# ===========================================
# START/STOP LOCAL
# ===========================================

start-classifier:
	@mkdir -p /var/run/dpipot && chmod 777 /var/run/dpipot
	cd classifier && LD_LIBRARY_PATH=/usr/local/lib ./classifier /var/run/dpipot/ndpi.sock &
	@sleep 2 && ls -la /var/run/dpipot/ndpi.sock

start-proxy:
	cd proxy && KAFKA_BROKERS="" LOG_LEVEL=debug LD_LIBRARY_PATH=/usr/local/lib sudo ./dpipot-proxy &

start-all: setup-tproxy start-classifier start-proxy
	@echo "=== Todos os serviços iniciados ==="

stop-all:
	@pkill -9 classifier 2>/dev/null; pkill -9 dpipot-proxy 2>/dev/null; echo "Serviços parados"

# ===========================================
# TEST
# ===========================================

test-tproxy:
	@echo "Testando TPROXY (enviando para 127.0.0.1:50001)..."
	@echo -e "GET / HTTP/1.1\r\nHost: test\r\n\r\n" | nc 127.0.0.1 50001 || true
	@echo "" && sudo iptables -t mangle -L TEST-TPROXY -v -n

# ===========================================
# KUBERNETES
# ===========================================

addons:
	microk8s enable dns hostpath-storage ingress

deploy-dev:
	cd k8s/base && kubectl apply -k .
	kubectl rollout status daemonset/dpipot-proxy -n $(NAMESPACE) --timeout=120s

deploy-prod:
	cd k8s/overlays/prod && kubectl apply -k .
	kubectl rollout status daemonset/dpipot-proxy -n $(NAMESPACE) --timeout=120s

update:
	kubectl rollout restart daemonset/dpipot-proxy -n $(NAMESPACE)

status:
	kubectl get pods,svc -n $(NAMESPACE) -o wide

logs-proxy:
	kubectl logs -n $(NAMESPACE) -l app=dpipot-proxy -c proxy -f

logs-ndpi:
	kubectl logs -n $(NAMESPACE) -l app=dpipot-proxy -c ndpi-classifier -f

logs-kafka:
	kubectl logs -n $(NAMESPACE) -l app=kafka -f

# ===========================================
# CLEAN
# ===========================================

clean:
	cd proxy && rm -f dpipot-proxy
	cd classifier && make clean

help:
	@echo "=== dpipot-ng Makefile ==="
	@echo ""
	@echo "Build:"
	@echo "  make build-proxy       Build proxy Go"
	@echo "  make build-classifier  Build classifier C"
	@echo "  make build             Build todos"
	@echo ""
	@echo "TPROXY Local:"
	@echo "  make setup-tproxy      Configurar TPROXY"
	@echo "  make start-classifier  Iniciar classifier"
	@echo "  make start-proxy       Iniciar proxy"
	@echo "  make start-all         Iniciar tudo"
	@echo "  make stop-all          Parar todos"
	@echo "  make test-tproxy       Testar TPROXY"
	@echo ""
	@echo "Kubernetes:"
	@echo "  make addons            Habilitar addons MicroK8s"
	@echo "  make deploy-dev        Deploy dev"
	@echo "  make deploy-prod      Deploy prod"
	@echo "  make status            Status pods"
	@echo "  make logs-proxy        Logs proxy"
	@echo "  make logs-ndpi         Logs nDPI"
	@echo ""
	@echo "Util:"
	@echo "  make clean             Limpar builds"
