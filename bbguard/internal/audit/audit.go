// Package audit records every scope decision as JSON Lines. The log is the
// artifact that answers "what did my agents actually touch?" after a run — the
// question a program asks when something goes wrong, and the one ARTEX's own
// activity stream cannot answer for traffic that never reached its MITM proxy.
package audit

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

// Event is one proxied request decision.
type Event struct {
	TS      time.Time `json:"ts"`
	Program string    `json:"program,omitempty"`
	Method  string    `json:"method"`
	Host    string    `json:"host"`
	URL     string    `json:"url,omitempty"`
	Allowed bool      `json:"allowed"`
	Reason  string    `json:"reason"`
	Rule    string    `json:"rule,omitempty"`
	WaitMS  int64     `json:"wait_ms,omitempty"`
	Status  int       `json:"status,omitempty"`
	DryRun  bool      `json:"dry_run,omitempty"`
	Error   string    `json:"error,omitempty"`
}

// Log appends events to a file, and to stderr when no file is configured.
type Log struct {
	mu      sync.Mutex
	f       *os.File
	enc     *json.Encoder
	program string

	allowed   uint64
	denied    uint64
	throttled uint64
}

// Open creates or appends to path. An empty path logs to stderr.
func Open(path, program string) (*Log, error) {
	l := &Log{program: program}
	if path == "" {
		l.enc = json.NewEncoder(os.Stderr)
		return l, nil
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	l.f = f
	l.enc = json.NewEncoder(f)
	return l, nil
}

// Write records one event. Logging failures are deliberately ignored: losing
// an audit line must never drop a request on the floor mid-engagement.
func (l *Log) Write(e Event) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if e.TS.IsZero() {
		e.TS = time.Now().UTC()
	}
	e.Program = l.program
	switch {
	case !e.Allowed:
		l.denied++
	default:
		l.allowed++
		if e.WaitMS > 0 {
			l.throttled++
		}
	}
	_ = l.enc.Encode(e)
}

// Stats returns running counters for the /stats endpoint.
func (l *Log) Stats() map[string]uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return map[string]uint64{
		"allowed":   l.allowed,
		"denied":    l.denied,
		"throttled": l.throttled,
	}
}

// Close flushes the underlying file.
func (l *Log) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f != nil {
		return l.f.Close()
	}
	return nil
}
