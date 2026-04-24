package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config contém todas as configurações do proxy lidas de variáveis de ambiente.
type Config struct {
	ListenAddr         string
	CertsPath         string
	NDPISocketPath    string
	NDPITimeout      time.Duration
	Routes           map[string]string
	DefaultRoute    string
	KafkaBrokers     string
	KafkaTopic       string
	MaxPayloadBytes int64
	LogLevel        string
	ClassifierEnabled bool
	ClassifierHost  string
	ClassifierPort int
	ServerFirstPorts []uint16
	PortProtocolMap  map[uint16]string
}

func Load() (*Config, error) {
	cfg := &Config{
		ListenAddr:        getEnv("PROXY_LISTEN_ADDR", "0.0.0.0:8080"),
		CertsPath:         getEnv("CERTS_PATH", "./certs"),
		NDPISocketPath:    getEnv("NDPI_SOCKET_PATH", "/var/run/dpipot/ndpi.sock"),
		NDPITimeout:       getDuration("NDPI_TIMEOUT", 500*time.Millisecond),
		DefaultRoute:      getEnv("DEFAULT_ROUTE", "dionaea-svc:4444"),
		KafkaBrokers:      getEnv("KAFKA_BROKERS", "kafka-svc:9092"),
		KafkaTopic:        getEnv("KAFKA_TOPIC", "dpipot.events"),
		MaxPayloadBytes:   getInt64("MAX_PAYLOAD_BYTES", 0),
		LogLevel:          getEnv("LOG_LEVEL", "info"),
		ClassifierEnabled: getEnv("CLASSIFIER_ENABLED", "false") == "true",
		ClassifierHost:    "127.0.0.1",
		ClassifierPort:    getInt("FLOWTRACKER_PORT", 9090),
	}

	routesRaw := getEnv("HONEYPOT_ROUTES",
		"HTTP=elasticpot-svc:9200,MongoDB=mongodbhp-svc:27017,SSH=cowrie-svc:22")
	routes, err := parseRoutes(routesRaw)
	if err != nil {
		return nil, fmt.Errorf("HONEYPOT_ROUTES inválido: %w", err)
	}
	cfg.Routes = routes

	serverFirstPortsRaw := getEnv("SERVER_FIRST_PORTS", "")
	cfg.ServerFirstPorts = parseServerFirstPorts(serverFirstPortsRaw)

	portProtocolMapRaw := getEnv("PORT_PROTOCOL_MAP", "")
	cfg.PortProtocolMap = parsePortProtocolMap(portProtocolMapRaw)

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

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
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

func parseServerFirstPorts(raw string) []uint16 {
	if raw == "" {
		return nil
	}
	var ports []uint16
	for _, p := range strings.Split(raw, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		port, err := strconv.ParseUint(p, 10, 16)
		if err != nil {
			continue
		}
		ports = append(ports, uint16(port))
	}
	return ports
}

func parsePortProtocolMap(raw string) map[uint16]string {
	result := make(map[uint16]string)
	if raw == "" {
		return result
	}
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
