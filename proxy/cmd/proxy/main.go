package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spawnzao/dpipot-ng/proxy/internal/config"
	"github.com/spawnzao/dpipot-ng/proxy/internal/flowtracker"
	"github.com/spawnzao/dpipot-ng/proxy/internal/httpclassifier"
	kafkapkg "github.com/spawnzao/dpipot-ng/proxy/internal/kafka"
	"github.com/spawnzao/dpipot-ng/proxy/internal/mitm"
	proxypkg "github.com/spawnzao/dpipot-ng/proxy/internal/proxy"
	"github.com/spawnzao/dpipot-ng/proxy/internal/router"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func main() {
	// carrega configuração das ENV vars
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		os.Exit(1)
	}

	// inicializa logger estruturado
	log, err := newLogger(cfg.LogLevel)
	if err != nil {
		fmt.Fprintf(os.Stderr, "logger error: %v\n", err)
		os.Exit(1)
	}
	defer log.Sync()

	log.Info("iniciando dpipot-ng proxy",
		zap.String("listen", cfg.ListenAddr),
		zap.String("kafka_brokers", cfg.KafkaBrokers),
		zap.Any("routes", cfg.Routes),
		zap.Int("max_connections", cfg.MaxConnections),
		zap.Int("max_per_ip_conns", cfg.MaxPerIPConns),
		zap.Int64("max_payload_bytes", cfg.MaxPayloadBytes),
	)

	if cfg.FlowTrackerTTL > cfg.ProxyTimeout {
		log.Warn("FLOWTRACKER_TTL maior que PROXY_TIMEOUT: a tabela mantém entradas por mais tempo que a duração da conexão!",
			zap.Duration("flowtracker_ttl", cfg.FlowTrackerTTL),
			zap.Duration("proxy_timeout", cfg.ProxyTimeout),
		)
	}

	// inicializa Kafka producer (opcional: KAFKA=false desabilita)
	var producer *kafkapkg.Producer
	if cfg.KafkaEnabled {
		producer, err = kafkapkg.NewProducer(cfg.KafkaBrokers, cfg.KafkaTopic, log, cfg.PayloadB64Enabled, cfg.PayloadHexEnabled)
		if err != nil {
			log.Fatal("kafka producer", zap.Error(err))
		}
		defer producer.Close()
		log.Info("Kafka habilitado", zap.String("brokers", cfg.KafkaBrokers))
	} else {
		log.Info("Kafka desabilitado (KAFKA=false)")
	}

	// inicializa router
	r := router.New(cfg.Routes, cfg.DefaultRoute, log)
	log.Info("rotas configuradas", zap.Any("routes", r.Routes()))

	// inicializa FlowTracker client
	flowTracker := flowtracker.NewClient(*cfg, log)
	log.Info("FlowTracker inicializado", zap.Bool("enabled", flowTracker.IsEnabled()))

	// inicializa host keys (SSH + TLS) - reutilizadas em todas as conexões
	if err := proxypkg.InitHostKeys(func(format string, args ...interface{}) {
		log.Info("HostKeys: "+fmt.Sprintf(format, args...))
	}); err != nil {
		log.Fatal("HostKeys init failed", zap.Error(err))
	}

	// inicializa CertManager usando as host keys já geradas
	certMgr, err := mitm.NewCertManagerWithKeys(func(format string, args ...interface{}) {
		log.Info("CertManager: "+format, zap.Any("args", args))
	})
	if err != nil {
		log.Fatal("CertManager init failed", zap.Error(err))
	}

	// inicializa health server (HTTP na porta 8081)
	healthServer := proxypkg.NewHealthServer(
		"0.0.0.0:8081",
		producer,
		log,
	)

	// initialize HTTP classifier with whitelist
	path := os.Getenv("HTTP_CLASSIFIER_CONFIG")
	if path == "" {
    	path = "/etc/dpipot/legitimate_paths.yaml"
	}
	httpClassifier, err := httpclassifier.LoadFromFile(path)
	if err != nil {
		log.Fatal("failed to load legitimate_paths.yaml", zap.Error(err))
	}
	log.Info("HTTP classifier loaded successfully", zap.String("path", path))

	// carrega mapa de portas bem conhecidas a partir do /etc/services
	proxypkg.InitPortMap("/etc/services")

	// inicializa servidor TCP
	server := proxypkg.NewServer(
		cfg.ListenAddr,
		r,
		producer,
		cfg.MaxPayloadBytes,
		cfg.SSHInputBufSize,
		cfg.SSHOutputBufSize,
		cfg.MaxConnections,
		cfg.MaxPerIPConns,
		log,
		flowTracker,
		certMgr,
		cfg.ServerFirstPorts,
		cfg.ServerFirstPortsTLS,
		cfg.HttpAuthPorts,
		cfg.HttpAuthPortsTLS,
		httpClassifier,
		cfg.ProxyTimeout,
	)

	// captura sinais de shutdown (SIGTERM do Kubernetes, SIGINT do terminal)
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	errCh := make(chan error, 2)

	go func() {
		err := server.ListenAndServe()
		if err != nil {
			log.Error("proxy ListenAndServe falhou", zap.Error(err))
		}
		errCh <- err
	}()

	go func() {
		errCh <- healthServer.Start()
	}()

	select {
	case sig := <-sigCh:
		log.Info("sinal recebido, encerrando", zap.String("signal", sig.String()))
	case err := <-errCh:
		if err != nil {
			log.Fatal("serviço crítico falhou, encerrando processo", zap.Error(err))
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	server.Stop()

	if err := healthServer.Shutdown(ctx); err != nil {
		log.Error("health server shutdown", zap.Error(err))
	}

	log.Info("proxy encerrado")
}

func newLogger(level string) (*zap.Logger, error) {
	lvl := zapcore.InfoLevel
	if err := lvl.UnmarshalText([]byte(level)); err != nil {
		lvl = zapcore.InfoLevel
	}

	cfg := zap.Config{
		Level:       zap.NewAtomicLevelAt(lvl),
		Development: false,
		Encoding:    "json", // JSON para facilitar ingestão no Elasticsearch
		EncoderConfig: zapcore.EncoderConfig{
			TimeKey:        "ts",
			LevelKey:       "level",
			NameKey:        "logger",
			CallerKey:      "caller",
			MessageKey:     "msg",
			StacktraceKey:  "stacktrace",
			LineEnding:     zapcore.DefaultLineEnding,
			EncodeLevel:    zapcore.LowercaseLevelEncoder,
			EncodeTime:     zapcore.ISO8601TimeEncoder,
			EncodeDuration: zapcore.StringDurationEncoder,
			EncodeCaller:   zapcore.ShortCallerEncoder,
		},
		OutputPaths:      []string{"stdout"},
		ErrorOutputPaths: []string{"stderr"},
	}

	return cfg.Build()
}
