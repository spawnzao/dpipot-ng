NAMESPACE ?= dpipot

.PHONY: addons deploy-dev deploy-prod status logs-proxy logs-ndpi test clean

# ── setup microk8s ────────────────────────────────────────────────────────────

addons:
	microk8s enable dns storage

# ── pull e deploy (imagens vêm do ghcr.io via GitHub Actions) ────────────────

deploy-dev:
	microk8s kubectl apply -k k8s/overlays/dev
	microk8s kubectl rollout status daemonset/dpipot-proxy -n $(NAMESPACE) --timeout=120s

deploy-prod:
	microk8s kubectl apply -k k8s/overlays/prod
	microk8s kubectl rollout status daemonset/dpipot-proxy -n $(NAMESPACE) --timeout=120s

# força o microk8s a puxar a imagem mais nova do ghcr.io
update:
	microk8s kubectl rollout restart daemonset/dpipot-proxy -n $(NAMESPACE)

# ── observabilidade ───────────────────────────────────────────────────────────

status:
	microk8s kubectl get pods -n $(NAMESPACE) -o wide

logs-proxy:
	microk8s kubectl logs -n $(NAMESPACE) -l app=dpipot-proxy -c proxy -f

logs-ndpi:
	microk8s kubectl logs -n $(NAMESPACE) -l app=dpipot-proxy -c ndpi-classifier -f

logs-kafka:
	microk8s kubectl logs -n $(NAMESPACE) -l app=kafka -f

# ── testes ────────────────────────────────────────────────────────────────────

test:
	cd proxy && go test ./...

# ── limpeza ───────────────────────────────────────────────────────────────────

clean:
	microk8s kubectl delete -k k8s/overlays/dev --ignore-not-found
