package main

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"sync/atomic"
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

var runDiag = os.Getenv("RUN_DIAGNOSTIC") == "true"

func main() {
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load config: %v\n", err)
		os.Exit(1)
	}

	if runDiag {
		runDiagnostic(cfg.ClassifierInterface)
		return
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

	var packetCount int64
	var errorCount int64

	af.Start()

	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
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

func runDiagnostic(ifaceName string) {
	fmt.Println("=== DIAGNÓSTICO AF_PACKET ===")

	fmt.Println("\n[1] Criando socket sem bind...")
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		fmt.Printf("FALHA socket: %v\n", err)
		return
	}
	defer syscall.Close(fd)
	fmt.Println("OK: socket criado")

	fmt.Println("\n[2] Interfaces disponíveis:")
	ifaces, _ := net.Interfaces()
	for _, i := range ifaces {
		fmt.Printf("  interface: %s (index=%d, flags=%v)\n", i.Name, i.Index, i.Flags)
	}

	fmt.Println("\n[3] Testando recvfrom SEM bind (timeout 5s)...")
	tv := syscall.NsecToTimeval(5 * time.Second.Nanoseconds())
	err = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)
	if err != nil {
		fmt.Printf("SetsockoptTimeval failed: %v\n", err)
	}

	buf := make([]byte, 65535)
	n, _, err := syscall.Recvfrom(fd, buf, 0)
	if err != nil {
		fmt.Printf("TIMEOUT ou ERRO sem bind: %v\n", err)
	} else {
		fmt.Printf("OK: pacote接收 sem bind! len=%d\n", n)
	}

	fmt.Println("\n[4] Testando recvfrom COM bind (timeout 5s)...")
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		fmt.Printf("InterfaceByName %s failed: %v\n", ifaceName, err)
		iface, err = net.InterfaceByName("eth0")
		if err != nil {
			fmt.Printf("InterfaceByName eth0 also failed: %v\n", err)
			return
		}
		ifaceName = "eth0"
	}

	fmt.Printf("Usando interface: %s (index=%d)\n", iface.Name, iface.Index)

	fd2, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		fmt.Printf("FALHA socket2: %v\n", err)
		return
	}
	defer syscall.Close(fd2)

	addr := syscall.SockaddrLinklayer{
		Protocol: htons(syscall.ETH_P_ALL),
		Ifindex:  iface.Index,
	}
	err = syscall.Bind(fd2, &addr)
	fmt.Printf("Bind result: err=%v\n", err)

	err = syscall.SetsockoptTimeval(fd2, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)
	if err != nil {
		fmt.Printf("SetsockoptTimeval failed: %v\n", err)
	}

	n, _, err = syscall.Recvfrom(fd2, buf, 0)
	if err != nil {
		fmt.Printf("TIMEOUT ou ERRO com bind: %v\n", err)
	} else {
		fmt.Printf("OK: pacote com bind! len=%d\n", n)
	}

	fmt.Println("\n=== FIM DO DIAGNÓSTICO ===")
}

func htons(i uint16) uint16 {
	return (i<<8)&0xff00 | i>>8
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}