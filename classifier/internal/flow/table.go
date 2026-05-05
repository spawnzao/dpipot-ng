package flow

import (
	"bytes"
	"fmt"
	"net"
	"sync"
	"time"
)

type Entry struct {
	Protocol       string
	MasterProtocol string
	Category       uint32
	SrcIP          string
	SrcPort        uint16
	DstIP          string
	DstPort        uint16
	ProtocolNum    uint8
	LastSeen       time.Time
	FlowUUID       string // UUID único por conexão TCP; gerado no primeiro pacote
}

type Table struct {
	mu          sync.RWMutex
	entries     map[string]*Entry
	ttl         time.Duration
	cleanup     time.Duration
	lastCleanup time.Time
	stopCh      chan struct{}
}

type TableConfig struct {
	TTL          time.Duration
	CleanupEvery time.Duration
}

func NewTable(cfg TableConfig) *Table {
	if cfg.TTL == 0 {
		cfg.TTL = 5 * time.Minute
	}
	if cfg.CleanupEvery == 0 {
		cfg.CleanupEvery = 1 * time.Minute
	}

	t := &Table{
		entries:     make(map[string]*Entry),
		ttl:         cfg.TTL,
		cleanup:     cfg.CleanupEvery,
		lastCleanup: time.Now(),
		stopCh:      make(chan struct{}),
	}

	go t.cleanupLoop()

	return t
}

func NormalizeFlowID(srcIP, dstIP net.IP, srcPort, dstPort uint16, protocol uint8) string {
	srcIP4 := srcIP.To4()
	dstIP4 := dstIP.To4()

	if srcIP4 == nil {
		srcIP4 = srcIP
	}
	if dstIP4 == nil {
		dstIP4 = dstIP
	}

	src := fmt.Sprintf("%s:%d", srcIP4.String(), srcPort)
	dst := fmt.Sprintf("%s:%d", dstIP4.String(), dstPort)

	if bytes.Compare(srcIP4, dstIP4) > 0 || (bytes.Equal(srcIP4, dstIP4) && srcPort > dstPort) {
		src, dst = dst, src
	}

	return fmt.Sprintf("%s-%s-%d", src, dst, protocol)
}

func (t *Table) Get(flowID string) (*Entry, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	entry, ok := t.entries[flowID]
	if !ok {
		return nil, false
	}

	if time.Since(entry.LastSeen) > t.ttl {
		return nil, false
	}

	return entry, true
}

func (t *Table) Update(flowID string, entry *Entry) {
	t.mu.Lock()
	defer t.mu.Unlock()

	entry.LastSeen = time.Now()
	t.entries[flowID] = entry

	if time.Since(t.lastCleanup) > t.cleanup {
		t.cleanupLocked()
		t.lastCleanup = time.Now()
	}
}

func (t *Table) cleanupLoop() {
	ticker := time.NewTicker(t.cleanup)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			t.mu.Lock()
			t.cleanupLocked()
			t.mu.Unlock()
		case <-t.stopCh:
			return
		}
	}
}

func (t *Table) cleanupLocked() {
	now := time.Now()
	for flowID, entry := range t.entries {
		if now.Sub(entry.LastSeen) > t.ttl {
			delete(t.entries, flowID)
		}
	}
}

func (t *Table) Size() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.entries)
}

func (t *Table) Close() error {
	close(t.stopCh)
	return nil
}
