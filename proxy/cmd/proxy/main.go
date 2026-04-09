package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spawnzao/dpipot-ng/proxy/internal/config"
	kafkapkg "github.com/spawnzao/dpipot-ng/proxy/internal/kafka"
	"github.com/spawnzao/dpipot-ng/proxy/internal/ndpi"
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
		zap.String("ndpi_socket", cfg.NDPISocketPath),
		zap.String("kafka_brokers", cfg.KafkaBrokers),
		zap.Any("routes", cfg.Routes),
	)

	// aguarda o sidecar nDPI estar disponível antes de aceitar tráfego
	// importante no Kubernetes onde os containers do Pod sobem em paralelo
	log.Info("inicializando nDPI...")
	ndpiClient, err := ndpi.NewClient(cfg.NDPISocketPath, cfg.NDPITimeout)
	if err != nil {
		log.Fatal("nDPI init failed", zap.Error(err))
	}
	log.Info("nDPI inicializado com sucesso via CGO")

	if err := waitForNDPI(ndpiClient, 30*time.Second, log); err != nil {
		log.Fatal("sidecar nDPI não ficou disponível", zap.Error(err))
	}
	log.Info("sidecar nDPI disponível")

	// inicializa Kafka producer
	producer, err := kafkapkg.NewProducer(cfg.KafkaBrokers, cfg.KafkaTopic, log)
	if err != nil {
		log.Fatal("kafka producer", zap.Error(err))
	}
	defer producer.Close()

	// inicializa router
	r := router.New(cfg.Routes, cfg.DefaultRoute, log)
	log.Info("rotas configuradas", zap.Any("routes", r.Routes()))

	// inicializa health server (HTTP na porta 8081)
	healthServer := proxypkg.NewHealthServer(
		"0.0.0.0:8081",
		ndpiClient,
		producer,
		log,
	)

	// inicializa servidor TCP
	server := proxypkg.NewServer(
		cfg.ListenAddr,
		ndpiClient,
		r,
		producer,
		cfg.MaxPayloadBytes,
		log,
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

	sig := <-sigCh
	log.Info("sinal recebido, encerrando", zap.String("signal", sig.String()))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := healthServer.Shutdown(ctx); err != nil {
		log.Error("health server shutdown", zap.Error(err))
	}

	log.Info("proxy encerrado")
}

// waitForNDPI tenta conectar no socket do nDPI até o timeout.
// Necessário porque no Kubernetes os containers do Pod sobem em paralelo.
func waitForNDPI(client *ndpi.Client, timeout time.Duration, log *zap.Logger) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if err := client.Ping(); err == nil {
			return nil
		}
		log.Debug("nDPI ainda não disponível, aguardando...")
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("timeout aguardando nDPI após %s", timeout)
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
