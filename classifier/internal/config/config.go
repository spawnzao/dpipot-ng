package config

import (
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	ClassifierInterface string
	FlowTrackerPort     string
	FlowTrackerTTL      int
	LogLevel           string
	KafkaBrokers       string
	KafkaTopic         string
	ServerFirstPorts   []uint16
	PortProtocolMap   map[uint16]string
}

func Load() (*Config, error) {
	cfg := &Config{
		ClassifierInterface: getEnv("CLASSIFIER_INTERFACE", "ens192"),
		FlowTrackerPort:   getEnv("FLOWTRACKER_PORT", "9090"),
		FlowTrackerTTL:    getInt("FLOWTRACKER_TTL", 5),
		LogLevel:         getEnv("LOG_LEVEL", "info"),
		KafkaBrokers:     getEnv("KAFKA_BROKERS", "kafka-svc:9092"),
		KafkaTopic:       getEnv("KAFKA_TOPIC", "dpipot.events"),
	}

	serverFirstPortsRaw := getEnv("SERVER_FIRST_PORTS", "")
	cfg.ServerFirstPorts = parseServerFirstPorts(serverFirstPortsRaw)

	portProtocolMapRaw := getEnv("PORT_PROTOCOL_MAP", "")
	cfg.PortProtocolMap = parsePortProtocolMap(portProtocolMapRaw)

	return cfg, nil
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
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

func (c *Config) FlowTrackerListenAddr() string {
	return "127.0.0.1:" + c.FlowTrackerPort
}

func (c *Config) TTL() time.Duration {
	return time.Duration(c.FlowTrackerTTL) * time.Minute
}