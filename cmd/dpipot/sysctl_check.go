package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"go.uber.org/zap"

	"github.com/spawnzao/dpipot-ng/internal/capture"
)

const (
	rmemMaxPath    = "/proc/sys/net/core/rmem_max"
	sysctlConfFile = "/etc/sysctl.d/99-dpipot.conf"
)

// sysctlConf é o conteúdo recomendado para o arquivo de configuração do kernel.
// rmem_max = 128 MB: permite que SO_RCVBUF=32MB do AF_PACKET seja honrado.
// netdev_max_backlog = 10000: fila maior entre NIC e stack de rede do kernel.
const sysctlConf = `# dpipot-ng: configurações do kernel para captura de pacotes via AF_PACKET
# Gerado automaticamente — pode ser editado manualmente.

# Permite que SO_RCVBUF=32MB do socket AF_PACKET seja honrado pelo kernel.
# Sem isso o kernel limita silenciosamente ao rmem_max padrão (~208KB),
# causando drops de pacotes antes mesmo do processo ler um único frame.
net.core.rmem_max = 134217728
net.core.rmem_default = 134217728

# Fila por NIC entre hardware e stack de rede do kernel.
# Padrão (1000) é insuficiente sob tráfego de varredura massiva.
net.core.netdev_max_backlog = 10000
`

// checkRmemMax lê net.core.rmem_max e avisa se está abaixo de capture.BufferSize.
// Em modo interativo (TTY) oferece criar o arquivo sysctl e aplicar imediatamente.
// Em modo não-interativo (pod Kubernetes) apenas loga o aviso e os comandos corretivos.
func checkRmemMax(log *zap.Logger) {
	data, err := os.ReadFile(rmemMaxPath)
	if err != nil {
		log.Warn("não foi possível verificar net.core.rmem_max",
			zap.String("path", rmemMaxPath),
			zap.Error(err),
		)
		return
	}

	current, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		log.Warn("valor de rmem_max inválido",
			zap.String("raw", strings.TrimSpace(string(data))),
			zap.Error(err),
		)
		return
	}

	needed := int64(capture.BufferSize) // 32 MB — mesmo valor pedido via SO_RCVBUF
	if current >= needed {
		log.Info("net.core.rmem_max OK",
			zap.String("atual", fmt.Sprintf("%d bytes (%d MB)", current, current/1024/1024)),
			zap.String("mínimo", fmt.Sprintf("%d bytes (%d MB)", needed, needed/1024/1024)),
		)
		return
	}

	log.Warn("net.core.rmem_max abaixo do recomendado — drops de pacotes no kernel são esperados",
		zap.String("atual", fmt.Sprintf("%d bytes (%d KB)", current, current/1024)),
		zap.String("recomendado", "134217728 bytes (128 MB)"),
		zap.String("mínimo_necessário", fmt.Sprintf("%d bytes (%d MB)", needed, needed/1024/1024)),
		zap.String("campo_afetado", "afpacket_drops no heartbeat"),
		zap.String("causa", "SO_RCVBUF=32MB é silenciosamente limitado ao rmem_max do OS"),
	)

	if !isTerminal() {
		// Modo pod/não-interativo: apenas loga os passos para o operador.
		log.Warn("para corrigir no host, execute como root:",
			zap.String("passo_1", fmt.Sprintf("crie o arquivo %s (ver sysctl_check.go para conteúdo)", sysctlConfFile)),
			zap.String("passo_2", "sysctl --system"),
			zap.String("passo_3", "reinicie o pod para recriar o socket AF_PACKET"),
		)
		return
	}

	// Modo interativo — exibe aviso detalhado e oferece ação.
	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "  AVISO: net.core.rmem_max abaixo do recomendado\n")
	fmt.Fprintf(os.Stderr, "  ─────────────────────────────────────────────────────────\n")
	fmt.Fprintf(os.Stderr, "  Atual:        %d bytes (%d KB)\n", current, current/1024)
	fmt.Fprintf(os.Stderr, "  Recomendado:  134217728 bytes (128 MB)\n")
	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "  O socket AF_PACKET pede SO_RCVBUF=32MB, mas o kernel\n")
	fmt.Fprintf(os.Stderr, "  silenciosamente limita ao rmem_max do OS (%d KB).\n", current/1024)
	fmt.Fprintf(os.Stderr, "  Com esse buffer, picos de tráfego causam drops no kernel\n")
	fmt.Fprintf(os.Stderr, "  antes do processo ler qualquer pacote (afpacket_drops).\n")
	fmt.Fprintf(os.Stderr, "  ─────────────────────────────────────────────────────────\n\n")

	reader := bufio.NewReader(os.Stdin)

	fmt.Fprintf(os.Stderr, "  Criar %s com os valores recomendados? [s/N] ", sysctlConfFile)
	resp := readLine(reader)

	if resp != "s" && resp != "sim" {
		fmt.Fprintf(os.Stderr, "  ↳ Nenhuma alteração feita. Continuando...\n\n")
		return
	}

	if err := os.WriteFile(sysctlConfFile, []byte(sysctlConf), 0644); err != nil {
		if os.IsPermission(err) {
			fmt.Fprintf(os.Stderr, "\n  ✗ Sem permissão para criar %s\n", sysctlConfFile)
			fmt.Fprintf(os.Stderr, "    Execute como root, ou crie manualmente:\n\n")
			fmt.Fprintf(os.Stderr, "    sudo tee %s << 'EOF'\n%sEOF\n\n", sysctlConfFile, sysctlConf)
		} else {
			fmt.Fprintf(os.Stderr, "\n  ✗ Erro ao criar arquivo: %v\n\n", err)
		}
		fmt.Fprintf(os.Stderr, "  Continuando sem alteração...\n\n")
		return
	}

	fmt.Fprintf(os.Stderr, "  ✓ Arquivo criado: %s\n\n", sysctlConfFile)

	fmt.Fprintf(os.Stderr, "  Executar 'sysctl --system' agora para aplicar? [s/N] ")
	resp = readLine(reader)

	if resp != "s" && resp != "sim" {
		fmt.Fprintf(os.Stderr, "\n  ↳ Para aplicar manualmente:\n")
		fmt.Fprintf(os.Stderr, "      sudo sysctl --system\n")
		fmt.Fprintf(os.Stderr, "    Depois reinicie este processo para recriar o socket AF_PACKET.\n\n")
		return
	}

	fmt.Fprintf(os.Stderr, "  Executando: sysctl --system ...\n")
	out, err := exec.Command("sysctl", "--system").CombinedOutput() //nolint:gosec
	if err != nil {
		fmt.Fprintf(os.Stderr, "\n  ✗ Erro ao executar sysctl: %v\n", err)
		if len(out) > 0 {
			fmt.Fprintf(os.Stderr, "    Saída:\n%s\n", out)
		}
		fmt.Fprintf(os.Stderr, "  Tente: sudo sysctl --system\n\n")
		return
	}

	// Exibe apenas as linhas relevantes ao dpipot.
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "rmem") || strings.Contains(line, "netdev_max") {
			fmt.Fprintf(os.Stderr, "    %s\n", line)
		}
	}

	fmt.Fprintf(os.Stderr, "\n  ✓ sysctl aplicado.\n")
	fmt.Fprintf(os.Stderr, "  ! Reinicie este processo para recriar o socket AF_PACKET com o novo buffer.\n\n")
}

// isTerminal retorna true se stdin for um terminal interativo (não um pipe ou pod).
func isTerminal() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// readLine lê uma linha do reader e retorna em lowercase sem espaços.
func readLine(r *bufio.Reader) string {
	line, _ := r.ReadString('\n')
	return strings.ToLower(strings.TrimSpace(line))
}
