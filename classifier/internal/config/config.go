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

func (c *Config) FlowTrackerListenAddr() string {
	return "127.0.0.1:" + c.FlowTrackerPort
}

func (c *Config) TTL() time.Duration {
	return time.Duration(c.FlowTrackerTTL) * time.Minute
}