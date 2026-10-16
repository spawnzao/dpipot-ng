package flow

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

type Entry struct {
	Protocol       string
	MasterProtocol string
	Category       uint32
	LastSeen       time.Time
	FlowUUID       string // UUID único por conexão TCP; gerado no primeiro pacote

	// campos extraídos do cabeçalho IP/TCP do primeiro pacote
	TTL       uint8  // IP TTL (IPv4) / Hop Limit (IPv6)
	TOS       uint8  // IP Type of Service / Traffic Class
	TCPWindow uint16 // TCP window size (0 para UDP)
	IPVersion uint8  // 4 ou 6
}

type Table struct {
	mu          sync.RWMutex
	entries     map[string]*Entry
	ttl         time.Duration
	cleanup     time.Duration
	lastCleanup time.Time
	stopCh      chan struct{}
	// notifiers is keyed by flowID (tupleID); chan struct{} is closed (broadcast) when
	// the entry transitions from Unknown to a concrete protocol classification.
	notifiers sync.Map
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
	entry.LastSeen = time.Now()
	t.entries[flowID] = entry

	// Signal any WaitClassified waiter when the entry carries a concrete classification.
	// The load+close happens under the write lock so the waiter sees a consistent entry.
	var notifierCh chan struct{}
	if !isUnknownProto(entry.Protocol) {
		if ch, ok := t.notifiers.LoadAndDelete(flowID); ok {
			notifierCh = ch.(chan struct{})
		}
	}

	if time.Since(t.lastCleanup) > t.cleanup {
		t.cleanupLocked()
		t.lastCleanup = time.Now()
	}
	t.mu.Unlock()

	// Close outside the lock to avoid holding it during channel ops (no-op if nil).
	if notifierCh != nil {
		close(notifierCh)
	}
}

// isUnknownProto reports whether a protocol string represents an unclassified flow.
func isUnknownProto(s string) bool {
	return s == "" || strings.EqualFold(s, "unknown")
}

// classifiedEntry returns the entry for flowID if it exists, is not TTL-expired,
// and carries a concrete (non-Unknown) protocol classification.
func (t *Table) classifiedEntry(flowID string) (*Entry, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	e, ok := t.entries[flowID]
	if !ok || time.Since(e.LastSeen) > t.ttl {
		return nil, false
	}
	if isUnknownProto(e.Protocol) {
		return nil, false
	}
	return e, true
}

// WaitClassified blocks until the flow identified by flowID receives a concrete nDPI
// classification, or until ctx is cancelled (timeout). It returns the classified entry
// and true on success, or nil/false on timeout.
//
// WaitClassified is safe for concurrent use. Multiple goroutines waiting on the same
// flowID share a single notification channel and are all woken together.
func (t *Table) WaitClassified(ctx context.Context, flowID string) (*Entry, bool) {
	// Fast path: entry already classified.
	if e, ok := t.classifiedEntry(flowID); ok {
		return e, true
	}

	// Register a notifier channel. If another goroutine has already registered one for
	// this flowID, reuse it so a single Update() close wakes all waiters.
	ch := make(chan struct{})
	actual, _ := t.notifiers.LoadOrStore(flowID, ch)
	ch = actual.(chan struct{})

	// Double-check: Update() may have fired between the classifiedEntry call above
	// and LoadOrStore. If so, the notifier was never registered and ch is orphaned —
	// re-read under the read lock before blocking to avoid a permanent sleep.
	if e, ok := t.classifiedEntry(flowID); ok {
		t.notifiers.CompareAndDelete(flowID, ch)
		return e, true
	}

	select {
	case <-ch:
		// Update() classified the flow; re-read the entry.
		e, ok := t.classifiedEntry(flowID)
		return e, ok
	case <-ctx.Done():
		// Timed out; remove our registration if it's still ours.
		t.notifiers.CompareAndDelete(flowID, ch)
		return nil, false
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
