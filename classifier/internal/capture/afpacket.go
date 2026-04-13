package capture

import (
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

	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, 0)
	if err != nil {
		return nil, fmt.Errorf("socket creation failed: %w", err)
	}
	log.Printf("DEBUG: socket created fd=%d, AF_INET, SOCK_RAW, protocol=0 (all)", fd)

	var one int = 1
	err = unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_HDRINCL, one)
	if err != nil {
		log.Printf("DEBUG: IP_HDRINCL failed: %v (continuing)", err)
	} else {
		log.Printf("DEBUG: IP_HDRINCL enabled")
	}

	if err := setBufferSize(fd, BufferSize); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("set buffer size failed: %w", err)
	}

	log.Printf("DEBUG: setting non-blocking mode")
	err = unix.SetNonblock(fd, true)
	if err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("set nonblock failed: %w", err)
	}

	log.Printf("DEBUG: socket set to non-blocking mode")

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
	log.Printf("DEBUG: AF_PACKET read loop started, fd=%d", a.fd)

	for {
		select {
		case <-a.done:
			log.Printf("DEBUG: AF_PACKET loop exiting due to done")
			return
		default:
		}

		a.mu.RLock()
		if a.closed {
			log.Printf("DEBUG: AF_PACKET loop exiting due to closed")
			a.mu.RUnlock()
			return
		}

		log.Printf("DEBUG: about to call recvfrom on fd=%d (non-blocking)", a.fd)
		n, _, err := unix.Recvfrom(a.fd, buf, 0)
		a.mu.RUnlock()

		if err != nil {
			errno, ok := err.(unix.Errno)
			if ok && (errno == unix.EAGAIN || errno == unix.EWOULDBLOCK) {
				log.Printf("DEBUG: recvfrom EAGAIN, no data available")
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

var _ unsafe.Pointer
