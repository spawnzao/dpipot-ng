REGISTRY  ?= ghcr.io/spawnzao
VERSION   ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
NAMESPACE ?= dpipot

.PHONY: all build push deploy-dev deploy-prod test clean

all: build

# ── build ────────────────────────────────────────────────────────────────────

build: build-proxy build-classifier

build-proxy:
	docker build \
		--tag $(REGISTRY)/dpipot-proxy:$(VERSION) \
		--tag $(REGISTRY)/dpipot-proxy:latest \
		./proxy

build-classifier:
	docker build \
		--tag $(REGISTRY)/dpipot-classifier:$(VERSION) \
		--tag $(REGISTRY)/dpipot-classifier:latest \
		./classifier

# ── push ─────────────────────────────────────────────────────────────────────

push: push-proxy push-classifier

push-proxy:
	docker push $(REGISTRY)/dpipot-proxy:$(VERSION)
	docker push $(REGISTRY)/dpipot-proxy:latest

push-classifier:
	docker push $(REGISTRY)/dpipot-classifier:$(VERSION)
	docker push $(REGISTRY)/dpipot-classifier:latest

# ── deploy ───────────────────────────────────────────────────────────────────

deploy-dev:
	kubectl apply -k k8s/overlays/dev

deploy-prod:
	kubectl apply -k k8s/overlays/prod

# ── testes ───────────────────────────────────────────────────────────────────

test: test-proxy

test-proxy:
	cd proxy && go test ./...

# ── desenvolvimento local ─────────────────────────────────────────────────────

# roda o proxy localmente (requer nDPI socket e Kafka disponíveis)
run-proxy:
	cd proxy && go run ./cmd/proxy

# ── limpeza ──────────────────────────────────────────────────────────────────

clean:
	docker rmi $(REGISTRY)/dpipot-proxy:$(VERSION) 2>/dev/null || true
	docker rmi $(REGISTRY)/dpipot-classifier:$(VERSION) 2>/dev/null || true
	cd proxy && go clean ./...
