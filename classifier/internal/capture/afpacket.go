package capture

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	SnapLen       = 65535
	BufferSize    = 32 * 1024 * 1024
	Promiscuous   = true
	Timeout       = 100 * time.Millisecond
	MaxPacketSize = 65535
	ETH_P_ALL     = 0x0003
)

type Packet struct {
	Data      []byte
	Timestamp time.Time
}

type AFPacket struct {
	iface   string
	fd      int
	closed  bool
	mu      sync.RWMutex
	wg      sync.WaitGroup
	packets chan *Packet
	errors  chan error
	done    chan struct{}
}

type Config struct {
	Interface   string
	SnapLen     int
	Promiscuous bool
	Timeout     time.Duration
}

func NewAFPacket(cfg Config) (*AFPacket, error) {
	if cfg.Interface == "" {
		return nil, fmt.Errorf("interface é obrigatória")
	}

	if cfg.SnapLen == 0 {
		cfg.SnapLen = SnapLen
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = Timeout
	}

	ethproto := htons(ETH_P_ALL)
	log.Printf("DEBUG: ETH_P_ALL = 0x%04x (network byte order)", ethproto)

	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(ethproto))
	if err != nil {
		return nil, fmt.Errorf("socket creation failed: %w", err)
	}
	log.Printf("DEBUG: socket created fd=%d, AF_PACKET, SOCK_RAW, ETH_P_ALL", fd)

	ifIndex, err := getInterfaceIndex(cfg.Interface)
	if err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("get interface index failed: %w", err)
	}
	log.Printf("DEBUG: interface %s has index %d", cfg.Interface, ifIndex)

	// ORDEM CERTA: bind PRIMEIRO
	sockaddr := unix.SockaddrLinklayer{
		Protocol: ethproto,
		Ifindex:  ifIndex,
	}

	if err := unix.Bind(fd, &sockaddr); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("bind failed: %w", err)
	}
	log.Printf("DEBUG: socket bound to interface %s (index=%d)", cfg.Interface, ifIndex)

	// DEPOIS do bind: adicionar PACKET_MR_PROMISC
	mreq := unix.PacketMreq{
		Ifindex: int32(ifIndex),
		Type:    unix.PACKET_MR_PROMISC,
	}
	err = unix.SetsockoptPacketMreq(fd, unix.SOL_PACKET, unix.PACKET_ADD_MEMBERSHIP, &mreq)
	if err != nil {
		log.Printf("DEBUG: PACKET_ADD_MEMBERSHIP failed: %v (continuing anyway)", err)
	} else {
		log.Printf("DEBUG: PACKET_MR_PROMISC membership added AFTER bind")
	}

	// FORÇAR modo blocking explicitamente (remover non-blocking)
	log.Printf("DEBUG: forcing blocking mode (removing O_NONBLOCK)")
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("FcntlInt F_GETFL failed: %w", err)
	}
	flags &^= int(unix.O_NONBLOCK)
	_, err = unix.FcntlInt(uintptr(fd), unix.F_SETFL, flags)
	if err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("FcntlInt F_SETFL failed: %w", err)
	}
	log.Printf("DEBUG: socket now in blocking mode")

	if err := setBufferSize(fd, BufferSize); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("set buffer size failed: %w", err)
	}

	af := &AFPacket{
		iface:   cfg.Interface,
		fd:      fd,
		packets: make(chan *Packet, 1000),
		errors:  make(chan error, 10),
		done:    make(chan struct{}),
	}

	return af, nil
}

func getInterfaceIndex(iface string) (int, error) {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return 0, fmt.Errorf("InterfaceByName failed: %w", err)
	}
	return ifi.Index, nil
}

func setPromiscuous(fd int, iface string, enable bool) error {
	log.Printf("DEBUG: setting promiscuous mode on interface: %s (fd=%d)", iface, fd)

	var ifreq struct {
		name  [unix.IFNAMSIZ]byte
		flags uint16
	}
	copy(ifreq.name[:], iface)

	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(fd),
		uintptr(unix.SIOCGIFFLAGS),
		uintptr(unsafe.Pointer(&ifreq)),
	)
	if errno != 0 {
		return fmt.Errorf("SIOCGIFFLAGS ioctl failed: %w", errno)
	}

	log.Printf("DEBUG: current flags for %s: 0x%x", iface, ifreq.flags)

	if enable {
		ifreq.flags |= unix.IFF_PROMISC
		log.Printf("DEBUG: enabling PROMISC on %s", iface)
	} else {
		ifreq.flags &^= unix.IFF_PROMISC
		log.Printf("DEBUG: disabling PROMISC on %s", iface)
	}

	_, _, errno = unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(fd),
		uintptr(unix.SIOCSIFFLAGS),
		uintptr(unsafe.Pointer(&ifreq)),
	)
	if errno != 0 {
		return fmt.Errorf("SIOCSIFFLAGS ioctl failed: %w", errno)
	}

	log.Printf("DEBUG: promiscuous mode %s on %s", map[bool]string{true: "enabled", false: "disabled"}[enable], iface)
	return nil
}

func setBufferSize(fd int, size int) error {
	return unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, size)
}

func (a *AFPacket) Start() {
	a.wg.Add(1)
	go a.readLoop()
}

func (a *AFPacket) readLoop() {
	defer a.wg.Done()

	buf := make([]byte, MaxPacketSize)
	log.Printf("DEBUG: AF_PACKET read loop started, fd=%d (blocking mode)", a.fd)

	for {
		a.mu.RLock()
		if a.closed {
			log.Printf("DEBUG: AF_PACKET loop exiting due to closed")
			a.mu.RUnlock()
			return
		}

		// Modo blocking - recvfrom vai bloquear até receber dados
		log.Printf("DEBUG: calling recvfrom on fd=%d (blocking)", a.fd)
		n, _, err := unix.Recvfrom(a.fd, buf, 0)
		a.mu.RUnlock()

		if err != nil {
			errno, ok := err.(unix.Errno)
			if ok && (errno == unix.EAGAIN || errno == unix.EWOULDBLOCK) {
				log.Printf("DEBUG: recvfrom EAGAIN (should not happen in blocking mode)")
				time.Sleep(time.Millisecond * 10)
				continue
			}
			log.Printf("DEBUG: recvfrom error: %v (errno=%d)", err, int(errno))
			time.Sleep(time.Millisecond * 10)
			continue
		}

		if n == 0 {
			log.Printf("DEBUG: recv returned 0, continuing")
			continue
		}

		log.Printf("DEBUG: received packet from AF_PACKET, size=%d", n)

		packet := &Packet{
			Data:      make([]byte, n),
			Timestamp: time.Now(),
		}
		copy(packet.Data, buf[:n])

		select {
		case a.packets <- packet:
			log.Printf("DEBUG: packet sent to channel, size=%d", n)
		case <-a.done:
			return
		}
	}
}

func (a *AFPacket) Packets() <-chan *Packet {
	return a.packets
}

func (a *AFPacket) Errors() <-chan error {
	return a.errors
}

func (a *AFPacket) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.closed {
		return nil
	}

	close(a.done)

	if a.fd > 0 {
		unix.Close(a.fd)
		a.fd = -1
	}

	a.wg.Wait()
	close(a.packets)
	close(a.errors)

	a.closed = true
	return nil
}

func isEagain(err error) bool {
	errno, ok := err.(unix.Errno)
	if !ok {
		log.Printf("DEBUG: isEagain err is not unix.Errno, type=%T", err)
		return false
	}
	log.Printf("DEBUG: isEagain checking err=%v, errno=%d, EAGAIN=%d, EWOULDBLOCK=%d", err, int(errno), int(unix.EAGAIN), int(unix.EWOULDBLOCK))
	return errno == unix.EAGAIN || errno == unix.EWOULDBLOCK
}

func setNonblock(fd int, nonblock bool) error {
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if err != nil {
		return err
	}
	if nonblock {
		flags |= int(unix.O_NONBLOCK)
	} else {
		flags &= ^int(unix.O_NONBLOCK)
	}
	_, err = unix.FcntlInt(uintptr(fd), unix.F_SETFL, flags)
	return err
}

func htons(i uint16) uint16 {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, i)
	return binary.LittleEndian.Uint16(b)
}

var _ unsafe.Pointer
