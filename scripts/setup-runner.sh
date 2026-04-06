#!/bin/bash
# setup-runner.sh — configura o GitHub Actions self-hosted runner na sua máquina
#
# O runner permite que o GitHub Actions faça deploy direto no microk8s
# sem precisar de acesso externo ao cluster.
#
# Pré-requisitos:
#   - microk8s instalado e rodando
#   - Token de registro do GitHub (Settings → Actions → Runners → New self-hosted runner)
#
# Uso:
#   ./scripts/setup-runner.sh <GITHUB_REPO_URL> <RUNNER_TOKEN>
#
# Exemplo:
#   ./scripts/setup-runner.sh https://github.com/spawnzao/dpipot-ng AABBCC...

set -e

REPO_URL="${1:?Informe a URL do repositório: https://github.com/usuario/repo}"
TOKEN="${2:?Informe o token do runner (Settings → Actions → Runners)}"
RUNNER_DIR="$HOME/actions-runner"
RUNNER_VERSION="2.317.0"

echo "==> criando diretório do runner em ${RUNNER_DIR}..."
mkdir -p "${RUNNER_DIR}"
cd "${RUNNER_DIR}"

echo "==> baixando runner v${RUNNER_VERSION}..."
curl -sL \
    "https://github.com/actions/runner/releases/download/v${RUNNER_VERSION}/actions-runner-linux-x64-${RUNNER_VERSION}.tar.gz" \
    -o runner.tar.gz

tar xzf runner.tar.gz
rm runner.tar.gz

echo "==> configurando runner para ${REPO_URL}..."
./config.sh \
    --url "${REPO_URL}" \
    --token "${TOKEN}" \
    --name "$(hostname)-microk8s" \
    --labels "self-hosted,microk8s,linux" \
    --unattended \
    --replace

echo "==> instalando runner como serviço systemd..."
sudo ./svc.sh install
sudo ./svc.sh start

echo ""
echo "==> runner instalado e rodando!"
echo "    Verifique em: ${REPO_URL}/settings/actions/runners"
echo ""
echo "    Para ver os logs:"
echo "    sudo journalctl -u actions.runner.* -f"
