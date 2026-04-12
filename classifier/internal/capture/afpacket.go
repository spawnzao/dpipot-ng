package capture

import (
	"fmt"
	"log"
	"net"
	"sync"
	"syscall"
	"time"
	"unsafe"
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

	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, syscall.ETH_P_ALL)
	if err != nil {
		return nil, fmt.Errorf("socket creation failed: %w", err)
	}

	if err := setBufferSize(fd, BufferSize); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("set buffer size failed: %w", err)
	}

	ifIndex, err := getInterfaceIndex(cfg.Interface)
	if err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("get interface index failed: %w", err)
	}

	sockaddr := syscall.SockaddrLinklayer{
		Protocol: syscall.ETH_P_ALL,
		Ifindex:  ifIndex,
	}

	if err := syscall.Bind(fd, &sockaddr); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("bind failed: %w", err)
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

func setBufferSize(fd int, size int) error {
	return syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, size)
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

		log.Printf("DEBUG: about to call recvfrom on fd=%d", a.fd)
		n, _, err := syscall.Recvfrom(a.fd, buf, 0)
		a.mu.RUnlock()

		log.Printf("DEBUG: recvfrom returned n=%d, err=%v", n, err)

		if err != nil {
			log.Printf("DEBUG: recvfrom error: %v", err)
			if isEagain(err) {
				time.Sleep(time.Millisecond)
				continue
			}
			select {
			case a.errors <- fmt.Errorf("recvfrom failed: %w", err):
			case <-a.done:
			}
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
		syscall.Close(a.fd)
		a.fd = -1
	}

	a.wg.Wait()
	close(a.packets)
	close(a.errors)

	a.closed = true
	return nil
}

func isEagain(err error) bool {
	return err == syscall.EAGAIN || err == syscall.EWOULDBLOCK
}

var _ unsafe.Pointer
