package limit

import (
	"testing"
	"time"
)

func TestBurstThenThrottle(t *testing.T) {
	l := New(100, 100, 2, 2) // per-host: 2 rps, burst 2
	base := time.Unix(0, 0)
	l.SetClock(func() time.Time { return base })

	for i := 0; i < 2; i++ {
		if w, ok := l.Reserve("a.target.com", time.Second); !ok || w != 0 {
			t.Fatalf("burst request %d: wait=%v ok=%v; want immediate", i, w, ok)
		}
	}
	// Burst spent: the next one has to wait ~500ms for a 2 rps refill.
	w, ok := l.Reserve("a.target.com", time.Second)
	if !ok {
		t.Fatal("third request should be admitted with a wait, not rejected")
	}
	if w < 400*time.Millisecond || w > 600*time.Millisecond {
		t.Fatalf("wait = %v; want ~500ms", w)
	}
}

func TestRejectWhenWaitExceedsMax(t *testing.T) {
	l := New(0, 0, 1, 1)
	base := time.Unix(0, 0)
	l.SetClock(func() time.Time { return base })

	if _, ok := l.Reserve("h", time.Second); !ok {
		t.Fatal("first request should pass")
	}
	if _, ok := l.Reserve("h", 100*time.Millisecond); ok {
		t.Fatal("a 1s wait must be rejected when maxWait is 100ms")
	}
	// Rejection must not have consumed a token: once time advances enough,
	// the request succeeds.
	l.SetClock(func() time.Time { return base.Add(time.Second) })
	if w, ok := l.Reserve("h", 100*time.Millisecond); !ok || w != 0 {
		t.Fatalf("after refill: wait=%v ok=%v; want immediate", w, ok)
	}
}

func TestPerHostIsolation(t *testing.T) {
	l := New(0, 0, 1, 1)
	base := time.Unix(0, 0)
	l.SetClock(func() time.Time { return base })

	if _, ok := l.Reserve("a.com", 0); !ok {
		t.Fatal("a.com first request should pass")
	}
	if _, ok := l.Reserve("b.com", 0); !ok {
		t.Fatal("b.com must have its own bucket")
	}
	if _, ok := l.Reserve("a.com", 0); ok {
		t.Fatal("a.com budget is spent and should be rejected at maxWait=0")
	}
}

func TestGlobalCeilingBindsAcrossHosts(t *testing.T) {
	l := New(2, 2, 100, 100) // global: 2 rps burst 2; per-host effectively open
	base := time.Unix(0, 0)
	l.SetClock(func() time.Time { return base })

	if _, ok := l.Reserve("a.com", 0); !ok {
		t.Fatal("request 1 should pass")
	}
	if _, ok := l.Reserve("b.com", 0); !ok {
		t.Fatal("request 2 should pass")
	}
	if _, ok := l.Reserve("c.com", 0); ok {
		t.Fatal("global burst is spent; spreading across hosts must not bypass it")
	}
}

func TestRefillCapsAtBurst(t *testing.T) {
	l := New(0, 0, 1, 3)
	base := time.Unix(0, 0)
	l.SetClock(func() time.Time { return base })
	if _, ok := l.Reserve("h", 0); !ok {
		t.Fatal("priming request should pass")
	}
	// Idle for an hour: tokens must cap at burst (3), not accumulate to 3600.
	l.SetClock(func() time.Time { return base.Add(time.Hour) })
	for i := 0; i < 3; i++ {
		if _, ok := l.Reserve("h", 0); !ok {
			t.Fatalf("buffered request %d should pass", i)
		}
	}
	if _, ok := l.Reserve("h", 0); ok {
		t.Fatal("a long idle period must not bank more than burst tokens")
	}
}

func TestUnlimitedWhenBothTiersDisabled(t *testing.T) {
	l := New(0, 0, 0, 0)
	for i := 0; i < 100; i++ {
		if w, ok := l.Reserve("h", 0); !ok || w != 0 {
			t.Fatalf("limiting is off; request %d should be free", i)
		}
	}
}
