package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/spawnzao/dpipot-ng/classifier/internal/capture"
	"github.com/spawnzao/dpipot-ng/classifier/internal/flow"
	"github.com/spawnzao/dpipot-ng/classifier/internal/flowtracker"
	"github.com/spawnzao/dpipot-ng/classifier/internal/ndpi"
	"go.uber.org/zap"
)

var (
	interfaceName = flag.String("interface", "eth1", "Interface to capture packets")
	listenAddr    = flag.String("listen", "127.0.0.1:9090", "TCP listen address")
	ttlMinutes    = flag.Int("ttl", 5, "Flow entry TTL in minutes")
	logLevel      = flag.String("log", "info", "Log level (debug, info, warn, error)")
)

func main() {
	flag.Parse()

	logger, err := zap.NewDevelopment()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to init logger: %v\n", err)
		os.Exit(1)
	}
	defer logger.Sync()

	logger.Info("starting classifier",
		zap.String("interface", *interfaceName),
		zap.String("listen", *listenAddr),
		zap.Int("ttl_minutes", *ttlMinutes),
	)

	flowTable := flow.NewTable(flow.TableConfig{
		TTL:          time.Duration(*ttlMinutes) * time.Minute,
		CleanupEvery: 1 * time.Minute,
	})
	if flowTable == nil {
		logger.Fatal("failed to create flow table")
	}

	afConfig := capture.Config{
		Interface:   *interfaceName,
		SnapLen:     65535,
		Promiscuous: true,
	}

	af, err := capture.NewAFPacket(afConfig)
	if err != nil {
		logger.Fatal("failed to create AF_PACKET capturer",
			zap.Error(err),
			zap.String("interface", *interfaceName),
		)
	}
	defer af.Close()

	logger.Info("AF_PACKET capturer initialized", zap.String("interface", *interfaceName))

	ndpiHandler, err := ndpi.NewHandler(ndpi.HandlerConfig{
		FlowTable: flowTable,
		Logger:    logger,
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
		ListenAddr: *listenAddr,
	})

	go func() {
		if err := ftServer.Start(*listenAddr); err != nil {
			logger.Error("FlowTracker server failed", zap.Error(err))
		}
	}()

	logger.Info("FlowTracker TCP server started", zap.String("addr", *listenAddr))

	var packetCount int64
	var errorCount int64

	af.Start()

	// Debug: verifica se está recebendo pacotes nos primeiros 10s
	go func() {
		time.Sleep(3 * time.Second)

		log.Printf("[DEBUG] Aguardando pacote por 10s...")
		select {
		case pkt, ok := <-af.Packets():
			if !ok {
				log.Printf("[DEBUG] Canal Packets() fechado — af.Start() falhou?")
			} else {
				log.Printf("[DEBUG] Primeiro pacote recebido! len=%d", len(pkt.Data))
			}
		case err, ok := <-af.Errors():
			if !ok {
				log.Printf("[DEBUG] Canal Errors() fechado")
			} else {
				log.Printf("[DEBUG] Erro no canal: %v", err)
			}
		case <-time.After(10 * time.Second):
			log.Printf("[DEBUG] TIMEOUT — nenhum pacote em 10s. Problema na captura.")
		}
	}()

	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case packet, ok := <-af.Packets():
				if !ok {
					return
				}
				atomic.AddInt64(&packetCount, 1)
				if packetCount%10 == 0 {
					logger.Debug("packets received", zap.Int64("count", packetCount), zap.Int("size", len(packet.Data)))
				}
				ndpiHandler.ProcessPacket(packet.Data)
			case err, ok := <-af.Errors():
				if !ok {
					return
				}
				atomic.AddInt64(&errorCount, 1)
				logger.Error("AF_PACKET error", zap.Error(err))
			case <-ticker.C:
				logger.Info("classifier stats", zap.Int64("packets", packetCount), zap.Int64("errors", errorCount))
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
