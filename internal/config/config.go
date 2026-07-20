package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	// proxy
	ListenAddr          string
	ProxyTimeout        time.Duration
	Routes              map[string]string
	DefaultRoute        string
	MaxPayloadBytes     int64
	SSHInputBufSize     int
	SSHOutputBufSize    int
	MaxConnections      int
	MaxPerIPConns       int
	ServerFirstPorts    map[uint16]string
	ServerFirstPortsTLS map[uint16]string
	HttpAuthPorts       map[uint16]bool
	HttpAuthPortsTLS    map[uint16]bool
	PayloadB64Enabled   bool
	PayloadHexEnabled   bool

	// classifier (agora no mesmo processo)
	ClassifierInterface string
	FlowTableTTL        time.Duration // TTL de entradas na flow table (ex: 60s)
	PortProtocolMap     map[uint16]string

	// kafka (compartilhado)
	KafkaEnabled bool
	KafkaBrokers string
	KafkaTopic   string

	LogLevel string
}

func Load() (*Config, error) {
	serverFirstPortsRaw := getEnv("SERVER_FIRST_PORTS", "")
	serverFirstPortsTLSRaw := getEnv("SERVER_FIRST_PORTS_TLS", "")

	cfg := &Config{
		ListenAddr:          getEnv("PROXY_LISTEN_ADDR", "0.0.0.0:8080"),
		ProxyTimeout:        getDuration("PROXY_TIMEOUT", 15*time.Second),
		DefaultRoute:        getEnv("DEFAULT_ROUTE", "heralding:80"),
		MaxPayloadBytes:     getInt64("MAX_PAYLOAD_BYTES", 65536),
		SSHInputBufSize:     getInt("SSH_INPUT_BUF_SIZE", 4096),
		SSHOutputBufSize:    getInt("SSH_OUTPUT_BUF_SIZE", 65536),
		MaxConnections:      getInt("MAX_CONNECTIONS", 10000),
		MaxPerIPConns:       getInt("MAX_CONNECTIONS_PER_IP", 50),
		PayloadB64Enabled:   parseBoolEnv("PAYLOAD_B64_ENABLED", true),
		PayloadHexEnabled:   parseBoolEnv("PAYLOAD_HEX_ENABLED", true),
		ServerFirstPorts:    parseServerFirstPorts(serverFirstPortsRaw),
		ServerFirstPortsTLS: parseServerFirstPortsTLS(serverFirstPortsTLSRaw),
		HttpAuthPorts:       parsePortList(getEnv("HTTP_AUTH_PORTS", "")),
		HttpAuthPortsTLS:    parsePortList(getEnv("HTTP_AUTH_PORTS_TLS", "")),

		ClassifierInterface: getEnv("CLASSIFIER_INTERFACE", "ens192"),
		FlowTableTTL:        getDuration("FLOWTRACKER_TTL", 60*time.Second),
		PortProtocolMap:     parsePortProtocolMap(serverFirstPortsRaw),

		KafkaEnabled: parseBoolEnv("KAFKA", true),
		KafkaBrokers: getEnv("KAFKA_BROKERS", "kafka-svc:9092"),
		KafkaTopic:   getEnv("KAFKA_TOPIC", "dpipot.events"),

		LogLevel: getEnv("LOG_LEVEL", "info"),
	}

	routesRaw := getEnv("HONEYPOT_ROUTES",
		"HTTP=wordpot-svc:80,SSH=cowrie-svc:22,FTP_CONTROL=heralding:21,TELNET=heralding:23")
	routes, err := parseRoutes(routesRaw)
	if err != nil {
		return nil, fmt.Errorf("HONEYPOT_ROUTES inválido: %w", err)
	}
	cfg.Routes = routes

	return cfg, nil
}

func parseRoutes(raw string) (map[string]string, error) {
	routes := make(map[string]string)
	for _, pair := range strings.Split(raw, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		parts := strings.SplitN(pair, "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("par inválido: %q (esperado PROTO=host:porta)", pair)
		}
		routes[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
	}
	return routes, nil
}

func parseServerFirstPorts(raw string) map[uint16]string {
	result := make(map[uint16]string)
	for _, pair := range strings.Split(raw, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		parts := strings.SplitN(pair, ":", 2)
		if len(parts) != 2 {
			continue
		}
		port, err := strconv.ParseUint(strings.TrimSpace(parts[0]), 10, 16)
		if err != nil {
			continue
		}
		result[uint16(port)] = strings.TrimSpace(parts[1])
	}
	return result
}

func parseServerFirstPortsTLS(raw string) map[uint16]string {
	result := make(map[uint16]string)
	for _, pair := range strings.Split(raw, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		parts := strings.SplitN(pair, ":", 2)
		if len(parts) != 2 {
			continue
		}
		port, err := strconv.ParseUint(strings.TrimSpace(parts[0]), 10, 16)
		if err != nil {
			continue
		}
		result[uint16(port)] = strings.TrimSpace(parts[1])
	}
	return result
}

func parsePortList(raw string) map[uint16]bool {
	result := make(map[uint16]bool)
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		port, err := strconv.ParseUint(entry, 10, 16)
		if err != nil {
			continue
		}
		result[uint16(port)] = true
	}
	return result
}

func parsePortProtocolMap(raw string) map[uint16]string {
	result := make(map[uint16]string)
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		parts := strings.SplitN(entry, ":", 2)
		if len(parts) != 2 {
			continue
		}
		port, err := strconv.ParseUint(strings.TrimSpace(parts[0]), 10, 16)
		if err != nil {
			continue
		}
		result[uint16(port)] = strings.TrimSpace(parts[1])
	}
	return result
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func parseBoolEnv(key string, fallback bool) bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(key)))
	switch v {
	case "true", "1", "enable", "enabled", "yes":
		return true
	case "false", "0", "disable", "disabled", "no":
		return false
	}
	return fallback
}

func getDuration(key string, fallback time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return fallback
	}
	return d
}

func getInt(key string, fallback int) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return n
}

func getInt64(key string, fallback int64) int64 {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return fallback
	}
	return n
}
