package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/duc161616/bbguard/internal/audit"
	"github.com/duc161616/bbguard/internal/limit"
	"github.com/duc161616/bbguard/internal/scope"
)

// newProxy wires a proxy the way main() does, against an in-process scope.
func newProxy(t *testing.T, cfg scope.Config, lim *limit.Limiter, allowPrivate bool) *proxy {
	t.Helper()
	sc, err := scope.New(cfg)
	if err != nil {
		t.Fatalf("scope.New: %v", err)
	}
	alog, err := audit.Open(t.TempDir()+"/audit.jsonl", cfg.Program)
	if err != nil {
		t.Fatalf("audit.Open: %v", err)
	}
	t.Cleanup(func() { alog.Close() })
	if lim == nil {
		lim = limit.New(0, 0, 0, 0)
	}
	p := &proxy{
		scope: sc, lim: lim, log: alog,
		dialer:       dialerForTest(),
		idHeader:     "X-Bug-Bounty",
		allowPrivate: allowPrivate,
		maxWait:      time.Second,
		started:      time.Now(),
	}
	p.transport = &http.Transport{Proxy: nil, DialContext: p.dial}
	return p
}

// clientVia returns an http client that routes everything through px.
func clientVia(t *testing.T, px *httptest.Server) *http.Client {
	t.Helper()
	u, err := url.Parse(px.URL)
	if err != nil {
		t.Fatalf("parse proxy url: %v", err)
	}
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(u),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // httptest self-signed origin
		},
	}
}

// TestInScopeRequestIsForwardedAndStamped covers the happy path: the request
// reaches the origin, and it carries the attribution the program needs.
func TestInScopeRequestIsForwardedAndStamped(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"ua": r.Header.Get("User-Agent"),
			"id": r.Header.Get("X-Bug-Bounty"),
		})
	}))
	defer origin.Close()

	p := newProxy(t, scope.Config{Program: "t", Handle: "duc161616", Allow: []string{"127.0.0.1"}}, nil, true)
	px := httptest.NewServer(p)
	defer px.Close()

	resp, err := clientVia(t, px).Get(origin.URL + "/anything")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status %d: %s", resp.StatusCode, b)
	}
	var got map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode echo: %v", err)
	}
	if got["id"] != "duc161616" {
		t.Errorf("X-Bug-Bounty = %q; want the researcher handle", got["id"])
	}
	if !strings.Contains(got["ua"], "(bugbounty:duc161616)") {
		t.Errorf("User-Agent = %q; want the attribution marker appended", got["ua"])
	}
}

// TestOutOfScopeHostIsBlocked is the control ARTEX is missing: the agent asked
// for a host outside the engagement and the request never left the box.
func TestOutOfScopeHostIsBlocked(t *testing.T) {
	p := newProxy(t, scope.Config{Program: "t", Allow: []string{"*.target.com"}}, nil, true)
	px := httptest.NewServer(p)
	defer px.Close()

	for _, target := range []string{
		"http://example.invalid/",
		"http://169.254.169.254/latest/meta-data/", // cloud metadata
		"http://target.com.evil.invalid/",          // suffix confusion
	} {
		resp, err := clientVia(t, px).Get(target)
		if err != nil {
			t.Fatalf("GET %s: %v", target, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("GET %s → %d; want 403. body=%s", target, resp.StatusCode, body)
		}
		if !strings.Contains(string(body), "bbguard") {
			t.Errorf("GET %s: block response should explain itself, got %q", target, body)
		}
	}
}

// TestConnectTunnelEnforcesScope proves HTTPS is covered too: the host is
// visible in the CONNECT line, so the tunnel is refused before it is built.
func TestConnectTunnelEnforcesScope(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "tunnelled")
	}))
	defer origin.Close()

	// In scope: the tunnel is established and the TLS request succeeds.
	p := newProxy(t, scope.Config{Program: "t", Allow: []string{"127.0.0.1"}}, nil, true)
	px := httptest.NewServer(p)
	defer px.Close()
	resp, err := clientVia(t, px).Get(origin.URL + "/")
	if err != nil {
		t.Fatalf("https through proxy: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(body), "tunnelled") {
		t.Fatalf("in-scope CONNECT: status %d body %q", resp.StatusCode, body)
	}

	// Out of scope: the CONNECT is refused, so the TLS handshake never happens
	// and the client surfaces a transport error.
	p2 := newProxy(t, scope.Config{Program: "t", Allow: []string{"*.target.com"}}, nil, true)
	px2 := httptest.NewServer(p2)
	defer px2.Close()
	if _, err := clientVia(t, px2).Get(origin.URL + "/"); err == nil {
		t.Fatal("out-of-scope CONNECT should fail, but the request succeeded")
	}
}

// TestRateLimitReturns429 shows pacing reaching the caller as backpressure
// rather than as an unbounded queue.
func TestRateLimitReturns429(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(204)
	}))
	defer origin.Close()

	// One token, no refill headroom, and no willingness to wait.
	p := newProxy(t, scope.Config{Program: "t", Allow: []string{"127.0.0.1"}}, limit.New(0, 0, 1, 1), true)
	p.maxWait = 0
	px := httptest.NewServer(p)
	defer px.Close()
	c := clientVia(t, px)

	var ok, limited int
	for i := 0; i < 5; i++ {
		resp, err := c.Get(origin.URL + "/")
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		resp.Body.Close()
		switch resp.StatusCode {
		case 204:
			ok++
		case http.StatusTooManyRequests:
			limited++
		default:
			t.Fatalf("request %d: unexpected status %d", i, resp.StatusCode)
		}
	}
	if ok == 0 {
		t.Error("the first request should have been admitted")
	}
	if limited == 0 {
		t.Error("later requests should have been rate limited with 429")
	}
}

// TestPrivateAddressBlockedWhenNotPermitted covers the pivot case: the name is
// in scope but it points into the operator's own network.
func TestPrivateAddressBlockedWhenNotPermitted(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer origin.Close()

	p := newProxy(t, scope.Config{Program: "t", Allow: []string{"127.0.0.1"}}, nil, false) // allowPrivate=false
	px := httptest.NewServer(p)
	defer px.Close()

	resp, err := clientVia(t, px).Get(origin.URL + "/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status %d; want 502 for an in-scope name resolving to loopback. body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "internal address") {
		t.Errorf("body should name the reason, got %q", body)
	}
}

// TestDryRunForwardsButFlags lets an operator calibrate a scope against a real
// run without breaking it — and records every host that would have been cut.
func TestDryRunForwardsButFlags(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer origin.Close()

	p := newProxy(t, scope.Config{Program: "t", Allow: []string{"*.target.com"}}, nil, true)
	p.dryRun = true
	px := httptest.NewServer(p)
	defer px.Close()

	resp, err := clientVia(t, px).Get(origin.URL + "/") // 127.0.0.1 is NOT in scope
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("dry-run should forward an out-of-scope request, got %d", resp.StatusCode)
	}
}

func TestAdminEndpoints(t *testing.T) {
	p := newProxy(t, scope.Config{Program: "acme", Handle: "h", Allow: []string{"*.target.com"}}, nil, true)
	px := httptest.NewServer(p)
	defer px.Close()

	// Direct (non-proxied) requests hit the admin surface.
	for path, want := range map[string]string{"/healthz": "ok", "/scope": "target.com", "/stats": "acme"} {
		resp, err := http.Get(px.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 || !strings.Contains(string(body), want) {
			t.Errorf("GET %s → %d %q; want 200 containing %q", path, resp.StatusCode, body, want)
		}
	}
}

// TestInfraTrafficIsNotPacedOrStamped pins the operational-traffic contract:
// ARTEX's own LLM calls must not consume the target's rate budget, and the
// researcher handle must not leak to a third-party API.
func TestInfraTrafficIsNotPacedOrStamped(t *testing.T) {
	var sawHandle bool
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Bug-Bounty") != "" {
			sawHandle = true
		}
		w.WriteHeader(204)
	}))
	defer origin.Close()

	// 127.0.0.1 is infra only; the target budget is one request with no refill.
	p := newProxy(t, scope.Config{
		Program: "t", Handle: "duc161616",
		Allow: []string{"*.target.com"},
		Infra: []string{"127.0.0.1"},
	}, limit.New(0, 0, 1, 1), true)
	p.maxWait = 0
	px := httptest.NewServer(p)
	defer px.Close()
	c := clientVia(t, px)

	// Ten infra requests in a row: pacing must never kick in.
	for i := 0; i < 10; i++ {
		resp, err := c.Get(origin.URL + "/")
		if err != nil {
			t.Fatalf("infra request %d: %v", i, err)
		}
		resp.Body.Close()
		if resp.StatusCode != 204 {
			t.Fatalf("infra request %d → %d; infra traffic must not be rate limited", i, resp.StatusCode)
		}
	}
	if sawHandle {
		t.Error("the researcher handle was sent to an infra host; it belongs on target traffic only")
	}
}
