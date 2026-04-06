#!/bin/bash
# build-local.sh — aplica os manifests no microk8s
# As imagens são puxadas automaticamente do ghcr.io
#
# uso: ./scripts/build-local.sh [dev|prod]

set -e

ENV="${1:-dev}"

echo "==> aplicando manifests no microk8s (env: ${ENV})..."
microk8s kubectl apply -k "k8s/overlays/${ENV}"

echo "==> aguardando pods subirem..."
microk8s kubectl rollout status daemonset/dpipot-proxy -n dpipot --timeout=120s

echo ""
echo "==> pods em execução:"
microk8s kubectl get pods -n dpipot -o wide
