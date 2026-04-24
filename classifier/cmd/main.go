package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/spawnzao/dpipot-ng/classifier/internal/capture"
	"github.com/spawnzao/dpipot-ng/classifier/internal/flow"
	"github.com/spawnzao/dpipot-ng/classifier/internal/flowtracker"
	kafkapkg "github.com/spawnzao/dpipot-ng/classifier/internal/kafka"
	"github.com/spawnzao/dpipot-ng/classifier/internal/ndpi"
	"go.uber.org/zap"
)

var (
	interfaceName = flag.String("interface", "eth1", "Interface to capture packets")
	listenAddr    = flag.String("listen", "127.0.0.1:9090", "TCP listen address")
	ttlMinutes    = flag.Int("ttl", 5, "Flow entry TTL in minutes")
	logLevel      = flag.String("log", "info", "Log level (debug, info, warn, error)")
	runDiag       = flag.Bool("diag", false, "Run AF_PACKET diagnostic and exit")
	kafkaBrokers  = flag.String("kafka-brokers", "kafka-svc.dpipot.svc.cluster.local:9092", "Kafka brokers")
	kafkaTopic    = flag.String("kafka-topic", "dpipot.events", "Kafka topic base")
	serverFirstPorts = flag.String("server-first-ports", "21,25,110,143,465,993,995,3306,3389,5432,5900,5222,6379,1521,8883", "Ports that use server-first protocol (comma-separated)")
)

func main() {
	flag.Parse()

	// Diagnostic mode - run AF_PACKET tests and exit
	if *runDiag {
		runDiagnostic(*interfaceName)
		return
	}

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
		zap.String("kafka_brokers", *kafkaBrokers),
		zap.String("server_first_ports", *serverFirstPorts),
	)

	serverFirstPorts := parseServerFirstPorts(*serverFirstPorts)

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

	kafkaProducer, err := kafkapkg.NewProducer(*kafkaBrokers, *kafkaTopic, logger)
	if err != nil {
		logger.Warn("failed to create kafka producer for nDPI, continuing without it",
			zap.Error(err),
		)
	} else {
		defer kafkaProducer.Close()
		logger.Info("Kafka producer initialized for nDPI", zap.String("topic", *kafkaTopic+"-ndpi"))
	}

	ndpiHandler, err := ndpi.NewHandler(ndpi.HandlerConfig{
		FlowTable:         flowTable,
		Logger:            logger,
		Producer:          kafkaProducer,
		ServerFirstPorts:  serverFirstPorts,
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

	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case packet, ok := <-af.Packets():
				if !ok {
					return
				}
				// Skip broadcast packets (MAC: ff:ff:ff:ff:ff:ff)
				if len(packet.Data) >= 6 && packet.Data[0] == 0xff && packet.Data[1] == 0xff && packet.Data[2] == 0xff && packet.Data[3] == 0xff && packet.Data[4] == 0xff && packet.Data[5] == 0xff {
					continue
				}

				// Skip ARP (ethertype 0x0806)
				if len(packet.Data) >= 14 {
					ethertype := uint16(packet.Data[12])<<8 | uint16(packet.Data[13])
					if ethertype == 0x0806 {
						continue
					}
				}

				// Skip loopback (127.0.0.1)
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

	// Testa 1: socket sem bind — recebe de qualquer interface
	fmt.Println("\n[1] Criando socket sem bind...")
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		fmt.Printf("FALHA socket: %v\n", err)
		return
	}
	defer syscall.Close(fd)
	fmt.Println("OK: socket criado")

	// Testa 2: lista interfaces disponíveis
	fmt.Println("\n[2] Interfaces disponíveis:")
	ifaces, _ := net.Interfaces()
	for _, i := range ifaces {
		fmt.Printf("  interface: %s (index=%d, flags=%v)\n", i.Name, i.Index, i.Flags)
	}

	// Testa 3: recvfrom com timeout de 5s (sem bind)
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
		fmt.Printf("OK: pacote recebido sem bind! len=%d\n", n)
	}

	// Testa 4: agora tenta com bind para a interface
	fmt.Println("\n[4] Testando recvfrom COM bind (timeout 5s)...")
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		fmt.Printf("InterfaceByName %s failed: %v\n", ifaceName, err)
		// Try eth0
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

func logPacketDetails(data []byte, logger *zap.Logger) {
	if len(data) < 14 {
		logger.Info("packet too short", zap.Int("len", len(data)))
		return
	}

	dstMAC := data[0:6]
	_ = dstMAC
	srcMAC := data[6:12]
	ethertype := uint16(data[12])<<8 | uint16(data[13])

	logger.Info("PACKET",
		zap.Int("len", len(data)),
		zap.String("src_mac", fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", srcMAC[0], srcMAC[1], srcMAC[2], srcMAC[3], srcMAC[4], srcMAC[5])),
		zap.String("ethertype", fmt.Sprintf("0x%04x", ethertype)),
	)

	if ethertype == 0x0800 && len(data) >= 34 {
		ipHeader := data[14:]
		ihl := int(ipHeader[0]&0x0F) * 4
		protocol := ipHeader[9]
		srcIP := net.IP(ipHeader[12:16])
		dstIP := net.IP(ipHeader[16:20])

		logger.Info("IP",
			zap.String("src", srcIP.String()),
			zap.String("dst", dstIP.String()),
			zap.Uint8("proto", protocol),
		)

		if protocol == 6 && len(data) >= 14+ihl+20 {
			tcpHeader := data[14+ihl:]
			srcPort := uint16(tcpHeader[0])<<8 | uint16(tcpHeader[1])
			dstPort := uint16(tcpHeader[2])<<8 | uint16(tcpHeader[3])
			flags := tcpHeader[13]

			flagsStr := ""
			if flags&0x02 != 0 {
				flagsStr += "SYN "
			}
			if flags&0x10 != 0 {
				flagsStr += "ACK "
			}
			if flags&0x04 != 0 {
				flagsStr += "RST "
			}
			if flags&0x08 != 0 {
				flagsStr += "PSH "
			}
			if flags&0x01 != 0 {
				flagsStr += "FIN "
			}

			logger.Info("TCP",
				zap.Uint16("src_port", srcPort),
				zap.Uint16("dst_port", dstPort),
				zap.String("flags", flagsStr),
			)

			tcpDataOffset := int((tcpHeader[12]>>4)&0x0F) * 4
			payloadStart := 14 + ihl + tcpDataOffset
			if payloadStart < len(data) {
				logger.Info("TCP_PAYLOAD",
					zap.Int("len", len(data)-payloadStart),
					zap.String("data", fmt.Sprintf("%x", data[payloadStart:min(payloadStart+32, len(data))])),
				)
			} else {
				logger.Info("TCP_NO_PAYLOAD")
			}
		}

		if protocol == 17 && len(data) >= 14+ihl+8 {
			udpHeader := data[14+ihl:]
			srcPort := uint16(udpHeader[0])<<8 | uint16(udpHeader[1])
			dstPort := uint16(udpHeader[2])<<8 | uint16(udpHeader[3])

			logger.Info("UDP",
				zap.Uint16("src_port", srcPort),
				zap.Uint16("dst_port", dstPort),
			)
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
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
