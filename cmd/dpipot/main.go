package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/spawnzao/dpipot-ng/internal/capture"
	"github.com/spawnzao/dpipot-ng/internal/config"
	"github.com/spawnzao/dpipot-ng/internal/flow"
	"github.com/spawnzao/dpipot-ng/internal/httpclassifier"
	"github.com/spawnzao/dpipot-ng/internal/kafka"
	"github.com/spawnzao/dpipot-ng/internal/mitm"
	"github.com/spawnzao/dpipot-ng/internal/ndpi"
	"github.com/spawnzao/dpipot-ng/internal/proxy"
	"github.com/spawnzao/dpipot-ng/internal/router"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load config: %v\n", err)
		os.Exit(1)
	}

	logger, err := newLogger(cfg.LogLevel)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to init logger: %v\n", err)
		os.Exit(1)
	}
	defer logger.Sync()

	logger.Info("starting dpipot",
		zap.String("listen", cfg.ListenAddr),
		zap.String("interface", cfg.ClassifierInterface),
		zap.Duration("flow_table_ttl", cfg.FlowTableTTL),
		zap.String("kafka_brokers", cfg.KafkaBrokers),
	)

	// Shared in-memory flow table — written by nDPI goroutine, read by proxy handlers.
	flowTable := flow.NewTable(flow.TableConfig{
		TTL:          cfg.FlowTableTTL,
		CleanupEvery: 1 * time.Minute,
	})
	defer flowTable.Close()

	// AF_PACKET capture
	af, err := capture.NewAFPacket(capture.Config{
		Interface:   cfg.ClassifierInterface,
		SnapLen:     65535,
		Promiscuous: true,
	})
	if err != nil {
		logger.Fatal("failed to create AF_PACKET capturer",
			zap.Error(err),
			zap.String("interface", cfg.ClassifierInterface),
		)
	}
	defer af.Close()
	logger.Info("AF_PACKET capturer initialized", zap.String("interface", cfg.ClassifierInterface))

	// Build port slice from map keys (for nDPI handler)
	serverFirstSlice := make([]uint16, 0, len(cfg.ServerFirstPorts))
	for port := range cfg.ServerFirstPorts {
		serverFirstSlice = append(serverFirstSlice, port)
	}

	// nDPI handler — classifies packets and writes to flowTable
	// producer is nil here (created below); passed after construction if NdpiEventsEnabled
	ndpiHandler, err := ndpi.NewHandler(ndpi.HandlerConfig{
		FlowTable:         flowTable,
		Logger:            logger,
		ServerFirstPorts:  serverFirstSlice,
		PortProtocolMap:   cfg.PortProtocolMap,
		NdpiEventsEnabled: cfg.NdpiEventsEnabled,
		NodeName:          os.Getenv("NODE_NAME"),
		PodName:           os.Getenv("POD_NAME"),
	})
	if err != nil {
		logger.Fatal("failed to create nDPI handler", zap.Error(err))
	}
	logger.Info("nDPI handler initialized")

	// Kafka producer
	var producer *kafka.Producer
	if cfg.KafkaEnabled {
		producer, err = kafka.NewProducer(cfg.KafkaBrokers, cfg.KafkaTopic, logger, cfg.PayloadB64Enabled, cfg.PayloadHexEnabled)
		if err != nil {
			logger.Warn("failed to create kafka producer, continuing without it", zap.Error(err))
		} else {
			defer producer.Close()
			logger.Info("Kafka producer initialized",
				zap.String("topic", cfg.KafkaTopic),
				zap.Bool("ndpi_events", cfg.NdpiEventsEnabled),
			)
		}
	} else {
		logger.Info("Kafka disabled (KAFKA=false)")
	}

	// Wire producer into nDPI handler after it's created (avoids circular init)
	if cfg.NdpiEventsEnabled && producer != nil {
		ndpiHandler.SetProducer(producer)
	}

	// Router
	r := router.New(cfg.Routes, cfg.DefaultRoute, logger)

	// Host keys and TLS cert manager
	proxy.InitPortMap("/etc/services")
	mitmLog := func(format string, args ...interface{}) {
		logger.Info(fmt.Sprintf(format, args...))
	}
	if err := proxy.InitHostKeys(mitmLog); err != nil {
		logger.Fatal("failed to init host keys", zap.Error(err))
	}
	certMgr, err := mitm.NewCertManager(mitmLog)
	if err != nil {
		logger.Fatal("failed to create cert manager", zap.Error(err))
	}

	// HTTP classifier (optional)
	var httpClass *httpclassifier.Classifier
	httpClassifierConfig := os.Getenv("HTTP_CLASSIFIER_CONFIG")
	if httpClassifierConfig != "" {
		httpClass, err = httpclassifier.LoadFromFile(httpClassifierConfig)
		if err != nil {
			logger.Warn("failed to load HTTP classifier config, disabling",
				zap.String("path", httpClassifierConfig),
				zap.Error(err),
			)
		}
	}

	// Proxy server
	server := proxy.NewServer(
		cfg.ListenAddr,
		r,
		producer,
		cfg.MaxPayloadBytes,
		cfg.SSHInputBufSize,
		cfg.SSHOutputBufSize,
		cfg.MaxConnections,
		cfg.MaxPerIPConns,
		logger,
		flowTable,
		certMgr,
		cfg.ServerFirstPorts,
		cfg.ServerFirstPortsTLS,
		cfg.HttpAuthPorts,
		cfg.HttpAuthPortsTLS,
		httpClass,
		cfg.ProxyTimeout,
	)

	// Start AF_PACKET capture
	af.Start()

	// Goroutine: feed packets into nDPI
	var captureWg sync.WaitGroup
	captureWg.Add(1)
	go func() {
		defer captureWg.Done()
		for {
			select {
			case packet, ok := <-af.Packets():
				if !ok {
					return
				}
				// Skip broadcast frames
				if len(packet.Data) >= 6 &&
					packet.Data[0] == 0xff && packet.Data[1] == 0xff &&
					packet.Data[2] == 0xff && packet.Data[3] == 0xff &&
					packet.Data[4] == 0xff && packet.Data[5] == 0xff {
					continue
				}
				// Skip ARP
				if len(packet.Data) >= 14 {
					ethertype := uint16(packet.Data[12])<<8 | uint16(packet.Data[13])
					if ethertype == 0x0806 {
						continue
					}
				}
				// Skip loopback traffic
				if len(packet.Data) >= 34 {
					src := packet.Data[26:30]
					dst := packet.Data[30:34]
					if src[0] == 127 && dst[0] == 127 {
						continue
					}
				}
				ndpiHandler.ProcessPacket(packet.Data)
			case err, ok := <-af.Errors():
				if !ok {
					return
				}
				logger.Error("AF_PACKET error", zap.Error(err))
			}
		}
	}()

	// Signal handling for graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// Health server (port 8081) — liveness and readiness probes
	healthServer := proxy.NewHealthServer("0.0.0.0:8081", producer, logger)
	go func() {
		if err := healthServer.Start(); err != nil && err != http.ErrServerClosed {
			logger.Error("health server error", zap.Error(err))
		}
	}()

	// Start proxy server in background
	serverErr := make(chan error, 1)
	go func() {
		serverErr <- server.ListenAndServe()
	}()

	logger.Info("dpipot running — AF_PACKET + TPROXY in-process")

	select {
	case sig := <-sigCh:
		logger.Info("received signal, shutting down", zap.String("signal", sig.String()))
	case err := <-serverErr:
		if err != nil {
			logger.Error("proxy server error", zap.Error(err))
		}
	}

	logger.Info("shutting down")
	hctx, hcancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer hcancel()
	healthServer.Shutdown(hctx)
	server.Stop()
	af.Close()
	captureWg.Wait()
	ndpiHandler.Close()

	logger.Info("dpipot stopped")
}

func newLogger(level string) (*zap.Logger, error) {
	lvl := zapcore.InfoLevel
	if err := lvl.UnmarshalText([]byte(level)); err != nil {
		lvl = zapcore.InfoLevel
	}
	cfg := zap.Config{
		Level:       zap.NewAtomicLevelAt(lvl),
		Development: false,
		Encoding:    "json",
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
