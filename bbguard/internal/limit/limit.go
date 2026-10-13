// Package limit provides the request pacing ARTEX has no equivalent of: its
// only rate limiting applies to LLM providers (agent/provider.go), not to
// target traffic, so N concurrent workers running real tooling can hammer a
// target as fast as the network allows. Programs expect otherwise.
package limit

import (
	"sync"
	"time"
)

// Limiter paces requests with two token buckets: one global, one per host.
// Both must yield a token before a request proceeds, so a single host cannot
// consume the whole global budget and a wide scope cannot bypass the per-host
// ceiling.
type Limiter struct {
	mu        sync.Mutex
	global    *bucket
	perHost   map[string]*bucket
	hostRPS   float64
	hostBurst float64
	now       func() time.Time
}

type bucket struct {
	tokens float64
	burst  float64
	rps    float64
	last   time.Time
}

// New builds a limiter. A non-positive rps disables that tier.
func New(globalRPS, globalBurst, hostRPS, hostBurst float64) *Limiter {
	l := &Limiter{
		perHost:   make(map[string]*bucket),
		hostRPS:   hostRPS,
		hostBurst: hostBurst,
		now:       time.Now,
	}
	if globalRPS > 0 {
		l.global = &bucket{tokens: globalBurst, burst: globalBurst, rps: globalRPS}
	}
	return l
}

// SetClock replaces the time source. Tests only.
func (l *Limiter) SetClock(f func() time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.now = f
}

// Reserve takes one token from every active tier and reports how long the
// caller must sleep before proceeding. ok is false when that wait would exceed
// maxWait; nothing is consumed in that case and the caller should reject the
// request rather than queue it, so backpressure reaches the agent instead of
// piling up goroutines.
func (l *Limiter) Reserve(host string, maxWait time.Duration) (time.Duration, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	var active []*bucket
	if l.global != nil {
		active = append(active, l.global)
	}
	if l.hostRPS > 0 {
		b, ok := l.perHost[host]
		if !ok {
			b = &bucket{tokens: l.hostBurst, burst: l.hostBurst, rps: l.hostRPS}
			l.perHost[host] = b
		}
		active = append(active, b)
	}
	if len(active) == 0 {
		return 0, true
	}

	// Refill first, then price the request against every tier before taking
	// anything: a partial reservation would leak tokens on rejection.
	var wait time.Duration
	for _, b := range active {
		b.refill(now)
		if w := b.waitFor(1); w > wait {
			wait = w
		}
	}
	if wait > maxWait {
		return 0, false
	}
	for _, b := range active {
		b.tokens -= 1
	}
	return wait, true
}

func (b *bucket) refill(now time.Time) {
	if b.last.IsZero() {
		b.last = now
		return
	}
	if elapsed := now.Sub(b.last).Seconds(); elapsed > 0 {
		b.tokens += elapsed * b.rps
		if b.tokens > b.burst {
			b.tokens = b.burst
		}
		b.last = now
	}
}

// waitFor is how long until the bucket holds n tokens.
func (b *bucket) waitFor(n float64) time.Duration {
	if b.tokens >= n {
		return 0
	}
	return time.Duration((n - b.tokens) / b.rps * float64(time.Second))
}

// Hosts reports how many per-host buckets are live, for /stats.
func (l *Limiter) Hosts() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.perHost)
}
