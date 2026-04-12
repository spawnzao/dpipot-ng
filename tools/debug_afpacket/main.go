package main

import (
	"fmt"
	"net"
	"syscall"
	"time"
)

func main() {
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
		printPacketInfo(buf[:n])
	}

	// Testa 4: agora tenta com bind para a interface
	fmt.Println("\n[4] Testando recvfrom COM bind (timeout 5s)...")
	iface, err := net.InterfaceByName("ens192")
	if err != nil {
		fmt.Printf("InterfaceByName ens192 failed: %v\n", err)
		iface, err = net.InterfaceByName("eth0")
		if err != nil {
			fmt.Printf("InterfaceByName eth0 also failed: %v\n", err)
			return
		}
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
		printPacketInfo(buf[:n])
	}

	fmt.Println("\n=== FIM DO DIAGNÓSTICO ===")
}

func htons(i uint16) uint16 {
	return (i<<8)&0xff00 | i>>8
}

func printPacketInfo(data []byte) {
	if len(data) < 14 {
		return
	}
	fmt.Printf("  Ethernet: src=%02x:%02x:%02x:%02x:%02x:%02x dst=%02x:%02x:%02x:%02x:%02x:%02x\n",
		data[6], data[7], data[8], data[9], data[10], data[11],
		data[0], data[1], data[2], data[3], data[4], data[5])

	// Check if IP
	if len(data) >= 14 {
		proto := uint16(data[12])<<8 | uint16(data[13])
		fmt.Printf("  EtherType: 0x%04x\n", proto)
		if proto == 0x0800 && len(data) >= 20 {
			version := (data[14] >> 4) & 0xf
			fmt.Printf("  IP version: %d, protocol: %d\n", version, data[23])
		}
	}
}
