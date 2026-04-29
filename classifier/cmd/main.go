package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spawnzao/dpipot-ng/classifier/internal/capture"
	"github.com/spawnzao/dpipot-ng/classifier/internal/config"
	"github.com/spawnzao/dpipot-ng/classifier/internal/flow"
	"github.com/spawnzao/dpipot-ng/classifier/internal/flowtracker"
	kafkapkg "github.com/spawnzao/dpipot-ng/classifier/internal/kafka"
	"github.com/spawnzao/dpipot-ng/classifier/internal/ndpi"
	"go.uber.org/zap"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load config: %v\n", err)
		os.Exit(1)
	}

	logger, err := zap.NewDevelopment()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to init logger: %v\n", err)
		os.Exit(1)
	}
	defer logger.Sync()

	logger.Info("starting classifier",
		zap.String("interface", cfg.ClassifierInterface),
		zap.String("listen", cfg.FlowTrackerListenAddr()),
		zap.Int("ttl_minutes", cfg.FlowTrackerTTL),
		zap.String("kafka_brokers", cfg.KafkaBrokers),
	)

	flowTable := flow.NewTable(flow.TableConfig{
		TTL:          cfg.TTL(),
		CleanupEvery: 1 * time.Minute,
	})
	if flowTable == nil {
		logger.Fatal("failed to create flow table")
	}

	afConfig := capture.Config{
		Interface:   cfg.ClassifierInterface,
		SnapLen:     65535,
		Promiscuous: true,
	}

	af, err := capture.NewAFPacket(afConfig)
	if err != nil {
		logger.Fatal("failed to create AF_PACKET capturer",
			zap.Error(err),
			zap.String("interface", cfg.ClassifierInterface),
		)
	}
	defer af.Close()

	logger.Info("AF_PACKET capturer initialized", zap.String("interface", cfg.ClassifierInterface))

	kafkaProducer, err := kafkapkg.NewProducer(cfg.KafkaBrokers, cfg.KafkaTopic, logger)
	if err != nil {
		logger.Warn("failed to create kafka producer for nDPI, continuing without it",
			zap.Error(err),
		)
	} else {
		defer kafkaProducer.Close()
		logger.Info("Kafka producer initialized for nDPI", zap.String("topic", cfg.KafkaTopic+"-ndpi"))
	}

	ndpiHandler, err := ndpi.NewHandler(ndpi.HandlerConfig{
		FlowTable:        flowTable,
		Logger:           logger,
		Producer:         kafkaProducer,
		ServerFirstPorts: cfg.ServerFirstPorts,
		PortProtocolMap:  cfg.PortProtocolMap,
	})
	if err != nil {
		logger.Fatal("failed to create nDPI handler",
			zap.Error(err),
		)
	}
	defer ndpiHandler.Close()

	logger.Info("nDPI handler initialized")

	ftServer := flowtracker.NewServer(flowtracker.ServerConfig{
		FlowTable:  flowTable,
		Logger:     logger,
		ListenAddr: cfg.FlowTrackerListenAddr(),
	})

	go func() {
		if err := ftServer.Start(cfg.FlowTrackerListenAddr()); err != nil {
			logger.Error("FlowTracker server failed", zap.Error(err))
		}
	}()

	logger.Info("FlowTracker TCP server started", zap.String("addr", cfg.FlowTrackerListenAddr()))

	af.Start()

	go func() {
		for {
			select {
			case packet, ok := <-af.Packets():
				if !ok {
					return
				}
				if len(packet.Data) >= 6 && packet.Data[0] == 0xff && packet.Data[1] == 0xff && packet.Data[2] == 0xff && packet.Data[3] == 0xff && packet.Data[4] == 0xff && packet.Data[5] == 0xff {
					continue
				}

				if len(packet.Data) >= 14 {
					ethertype := uint16(packet.Data[12])<<8 | uint16(packet.Data[13])
					if ethertype == 0x0806 {
						continue
					}
				}

				if len(packet.Data) >= 20 {
					srcIP := packet.Data[26:30]
					dstIP := packet.Data[30:34]
					if srcIP[0] == 127 && dstIP[0] == 127 {
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

	logger.Info("classifier is running")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	logger.Info("shutting down classifier")

	ftServer.Stop()
	af.Close()
	ndpiHandler.Close()
	flowTable.Close()

	logger.Info("classifier stopped")
}

