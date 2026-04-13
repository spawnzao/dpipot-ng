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

	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(ethproto))
	if err != nil {
		return nil, fmt.Errorf("socket creation failed: %w", err)
	}

	ifIndex, err := getInterfaceIndex(cfg.Interface)
	if err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("get interface index failed: %w", err)
	}

	sockaddr := unix.SockaddrLinklayer{
		Protocol: ethproto,
		Ifindex:  ifIndex,
	}

	if err := unix.Bind(fd, &sockaddr); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("bind failed: %w", err)
	}

	mreq := unix.PacketMreq{
		Ifindex: int32(ifIndex),
		Type:    unix.PACKET_MR_PROMISC,
	}
	err = unix.SetsockoptPacketMreq(fd, unix.SOL_PACKET, unix.PACKET_ADD_MEMBERSHIP, &mreq)
	if err != nil {
		log.Printf("WARN: PACKET_ADD_MEMBERSHIP failed: %v", err)
	}

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

	for {
		a.mu.RLock()
		if a.closed {
			a.mu.RUnlock()
			return
		}

		n, _, err := unix.Recvfrom(a.fd, buf, 0)
		a.mu.RUnlock()

		if err != nil {
			errno, ok := err.(unix.Errno)
			if ok && (errno == unix.EAGAIN || errno == unix.EWOULDBLOCK) {
				time.Sleep(time.Millisecond * 10)
				continue
			}
			continue
		}

		if n == 0 {
			continue
		}

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
		unix.Close(a.fd)
		a.fd = -1
	}

	a.wg.Wait()
	close(a.packets)
	close(a.errors)

	a.closed = true
	return nil
}

func htons(i uint16) uint16 {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, i)
	return binary.LittleEndian.Uint16(b)
}

var _ unsafe.Pointer
