package proxy

import (
	"bufio"
	"os"
	"strconv"
	"strings"
)

// portAliases mapeia porta TCP → lista de nomes conhecidos (maiúsculos).
// Populado pelo InitPortMap a partir do /etc/services.
var portAliases map[uint16][]string

// ndpiNameOverrides corrige os casos onde o nDPI usa nome diferente do /etc/services.
// Ex: /etc/services chama a porta 53 de "domain", mas o nDPI classifica como "DNS".
// Os valores aqui são ADICIONADOS à lista de aliases — não substituem os do /etc/services.
var ndpiNameOverrides = map[uint16]string{
	53:  "DNS",    // /etc/services: "domain"
	443: "TLS",    // /etc/services: "https"
	445: "SMB",    // /etc/services: "microsoft-ds"
	631: "IPP",    // /etc/services: "ipp" (já correto, por precaução)
	5353: "MDNS",  // /etc/services: "mdns"
}

// InitPortMap carrega /etc/services e constrói portAliases.
// Usa fallback embutido mínimo se o arquivo não estiver disponível.
// Seguro chamar múltiplas vezes (substitui o mapa anterior).
func InitPortMap(path string) {
	m := loadEtcServices(path)
	if len(m) == 0 {
		m = builtinPortAliases()
	}
	// Aplica overrides nDPI: adiciona o nome nDPI à lista se ainda não estiver
	for port, ndpiName := range ndpiNameOverrides {
		names := m[port]
		found := false
		for _, n := range names {
			if n == ndpiName {
				found = true
				break
			}
		}
		if !found {
			m[port] = append([]string{ndpiName}, names...) // nDPI name vai na frente (expected_proto)
		}
	}
	portAliases = m
}

// loadEtcServices faz parse do /etc/services e retorna map[port][]names (só TCP).
// Cada linha tem formato: service-name  port/proto  [aliases...]  [# comment]
func loadEtcServices(path string) map[uint16][]string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	m := make(map[uint16][]string)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		// remove comentário inline
		if idx := strings.Index(line, "#"); idx >= 0 {
			line = line[:idx]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		portProto := strings.SplitN(fields[1], "/", 2)
		if len(portProto) != 2 || portProto[1] != "tcp" {
			continue // só TCP interessa para mismatch de protocolo de aplicação
		}
		port64, err := strconv.ParseUint(portProto[0], 10, 16)
		if err != nil {
			continue
		}
		port := uint16(port64)
		// Coleta primary name + aliases, todos em maiúsculo, sem duplicatas
		existing := make(map[string]struct{})
		for _, prev := range m[port] {
			existing[prev] = struct{}{}
		}
		for _, name := range fields[0:] {
			if strings.Contains(name, "/") {
				break // chegou no campo port/proto, para
			}
			upper := strings.ToUpper(name)
			if _, dup := existing[upper]; !dup {
				m[port] = append(m[port], upper)
				existing[upper] = struct{}{}
			}
		}
	}
	return m
}

// builtinPortAliases é o fallback quando /etc/services não está disponível.
func builtinPortAliases() map[uint16][]string {
	return map[uint16][]string{
		21:    {"FTP"},
		22:    {"SSH"},
		23:    {"TELNET"},
		25:    {"SMTP", "MAIL"},
		53:    {"DNS", "DOMAIN"},
		80:    {"HTTP", "WWW"},
		110:   {"POP3", "POP-3"},
		143:   {"IMAP", "IMAP2"},
		443:   {"TLS", "HTTPS"},
		445:   {"SMB", "MICROSOFT-DS"},
		3306:  {"MYSQL"},
		3389:  {"RDP"},
		5432:  {"POSTGRESQL", "POSTGRES"},
		5900:  {"VNC"},
		6379:  {"REDIS"},
		8080:  {"HTTP", "WWW"},
		8443:  {"TLS", "HTTPS"},
		9200:  {"ELASTICSEARCH"},
		27017: {"MONGODB"},
	}
}

// checkPortProtoMismatch retorna (isMismatch, expectedProto).
// Compara o protocolo detectado pelo nDPI com os nomes esperados para a porta.
// Reclassificações internas do proxy (HTTP_AUTH, HTTP_SUSPECT) nunca são mismatch.
func checkPortProtoMismatch(dstPort uint16, ndpiLabel string) (bool, string) {
	if portAliases == nil {
		return false, ""
	}
	names, ok := portAliases[dstPort]
	if !ok {
		return false, "" // porta desconhecida: sem opinião
	}
	detected := strings.ToUpper(ndpiLabel)

	// Reclassificações internas do proxy são comportamento intencional.
	// HTTP_AUTH: portas HTTP com autenticação (fixas na config)
	// HTTP_SUSPECT: GET fora da whitelist → redirecionado para galah (LLM honeypot)
	// TLS.X: transporte TLS com app identificado — o mismatch é avaliado sobre o X
	if detected == "HTTP_AUTH" || detected == "HTTP_SUSPECT" {
		return false, ""
	}

	for _, name := range names {
		if strings.Contains(detected, name) || strings.Contains(name, detected) {
			return false, ""
		}
	}
	return true, names[0] // names[0] = melhor nome canônico (nDPI override fica na frente)
}
