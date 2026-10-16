package metrics

import "sync/atomic"

// bucketBounds defines the upper bound (inclusive, nanoseconds) of each histogram bucket.
// Ratio ~5x per step covers 1µs to ~390ms; the final bucket is the overflow (unbounded).
var bucketBounds = [...]int64{
	1_000,        // 1µs
	5_000,        // 5µs
	25_000,       // 25µs
	125_000,      // 125µs
	625_000,      // 625µs
	3_125_000,    // 3.125ms
	15_625_000,   // 15.625ms
	78_125_000,   // 78.125ms
	390_625_000,  // 390.625ms
	// overflow bucket has no upper bound
}

const numBuckets = len(bucketBounds) + 1

// Histogram is a lock-free, fixed-bucket histogram of int64 nanosecond values.
// Observations are wait-free; SnapshotAndReset is linearisable at the bucket level
// (a handful of in-flight Observe calls at reset time may be attributed to either
// interval — acceptable for a monitoring workload).
type Histogram struct {
	counts [numBuckets]atomic.Int64
	sum    atomic.Int64
	n      atomic.Int64
}

// Observe records a single nanosecond sample.
func (h *Histogram) Observe(ns int64) {
	if ns < 0 {
		ns = 0
	}
	h.sum.Add(ns)
	h.n.Add(1)
	for i, bound := range bucketBounds {
		if ns <= bound {
			h.counts[i].Add(1)
			return
		}
	}
	h.counts[numBuckets-1].Add(1)
}

// HistogramSnapshot holds percentile estimates and aggregate stats for one interval.
type HistogramSnapshot struct {
	Count int64
	Sum   int64
	P50   int64 // nanoseconds; 0 when Count == 0
	P95   int64
	P99   int64
	P999  int64
}

// SnapshotAndReset drains all counters and returns percentile estimates for the interval.
func (h *Histogram) SnapshotAndReset() HistogramSnapshot {
	// Swap each bucket atomically; observations racing the reset land in the next interval.
	var counts [numBuckets]int64
	for i := range counts {
		counts[i] = h.counts[i].Swap(0)
	}
	sum := h.sum.Swap(0)
	n := h.n.Swap(0)

	total := int64(0)
	for _, c := range counts {
		total += c
	}
	if total == 0 {
		return HistogramSnapshot{}
	}

	return HistogramSnapshot{
		Count: n,
		Sum:   sum,
		P50:   bucketPercentile(counts[:], total, 0.50),
		P95:   bucketPercentile(counts[:], total, 0.95),
		P99:   bucketPercentile(counts[:], total, 0.99),
		P999:  bucketPercentile(counts[:], total, 0.999),
	}
}

// bucketPercentile returns the upper bound of the bucket at quantile q (0–1).
// For the overflow bucket it returns 2× the last finite bound as a sentinel.
func bucketPercentile(counts []int64, total int64, q float64) int64 {
	target := int64(float64(total)*q + 0.5)
	if target < 1 {
		target = 1
	}
	cumulative := int64(0)
	for i, c := range counts {
		cumulative += c
		if cumulative >= target {
			if i < len(bucketBounds) {
				return bucketBounds[i]
			}
			return bucketBounds[len(bucketBounds)-1] * 2
		}
	}
	return bucketBounds[len(bucketBounds)-1] * 2
}

// GaugeSampler tracks the distribution of a gauge (e.g. queue depth) over an interval.
type GaugeSampler struct {
	max   atomic.Int64
	sum   atomic.Int64
	count atomic.Int64
}

// Observe records one gauge reading.
func (g *GaugeSampler) Observe(v int64) {
	// Update max via CAS loop.
	for {
		cur := g.max.Load()
		if v <= cur || g.max.CompareAndSwap(cur, v) {
			break
		}
	}
	g.sum.Add(v)
	g.count.Add(1)
}

// GaugeSnapshot holds aggregate gauge stats for one interval.
type GaugeSnapshot struct {
	Max   int64
	Avg   int64
	Count int64
}

// SnapshotAndReset drains all accumulators and returns aggregate stats for the interval.
func (g *GaugeSampler) SnapshotAndReset() GaugeSnapshot {
	n := g.count.Swap(0)
	sum := g.sum.Swap(0)
	max := g.max.Swap(0)
	if n == 0 {
		return GaugeSnapshot{}
	}
	return GaugeSnapshot{Max: max, Avg: sum / n, Count: n}
}
