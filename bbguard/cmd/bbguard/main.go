// Command bbguard is a deny-by-default egress proxy for bug bounty work.
//
// It supplies the three controls ARTEX does not have (see BUG-HUNTER-SETUP.md):
// a scope boundary enforced in code rather than in an LLM prompt, request
// pacing for targets, and an identifying header so a program can attribute the
// traffic. Point the agent's tooling at it, lock container egress to it, and an
// out-of-scope request fails with 403 no matter what the model decided to run.
//
//	bbguard -scope scope.json -addr 127.0.0.1:8899 -audit run.jsonl
//	HTTPS_PROXY=http://127.0.0.1:8899 curl https://api.target.com/
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/duc161616/bbguard/internal/audit"
	"github.com/duc161616/bbguard/internal/limit"
	"github.com/duc161616/bbguard/internal/scope"
)

// hopByHop headers are per-connection and must not be forwarded.
var hopByHop = []string{
	"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate",
	"Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade",
}

type proxy struct {
	scope        *scope.Scope
	lim          *limit.Limiter
	log          *audit.Log
	transport    *http.Transport
	dialer       *net.Dialer
	idHeader     string
	allowPrivate bool
	dryRun       bool
	maxWait      time.Duration
	started      time.Time
}

func main() {
	if err := run(); err != nil {
		log.Fatalf("bbguard: %v", err)
	}
}

func run() error {
	var (
		scopePath    = flag.String("scope", "scope.json", "scope definition file")
		addr         = flag.String("addr", "127.0.0.1:8899", "proxy listen address")
		auditPath    = flag.String("audit", "", "append decisions as JSON Lines to this file (default: stderr)")
		rps          = flag.Float64("rps", 8, "global requests/second ceiling (0 disables)")
		burst        = flag.Float64("burst", 16, "global burst allowance")
		hostRPS      = flag.Float64("host-rps", 3, "per-host requests/second ceiling (0 disables)")
		hostBurst    = flag.Float64("host-burst", 6, "per-host burst allowance")
		maxWait      = flag.Duration("max-wait", 2*time.Second, "longest a request may be paced before it is rejected with 429")
		idHeader     = flag.String("id-header", "X-Bug-Bounty", "identifying header added to plain-HTTP requests (empty disables)")
		allowPrivate = flag.Bool("allow-private", false, "permit targets that resolve to loopback, RFC1918 or link-local addresses")
		dryRun       = flag.Bool("dry-run", false, "log what would be blocked but forward everything (use to calibrate a scope, never on a live engagement)")
		timeout      = flag.Duration("timeout", 30*time.Second, "upstream dial and response-header timeout")
	)
	flag.Parse()

	sc, err := scope.Load(*scopePath)
	if err != nil {
		return err
	}
	alog, err := audit.Open(*auditPath, sc.Program())
	if err != nil {
		return fmt.Errorf("open audit log: %w", err)
	}
	defer alog.Close()

	p := &proxy{
		scope:        sc,
		lim:          limit.New(*rps, *burst, *hostRPS, *hostBurst),
		log:          alog,
		dialer:       &net.Dialer{Timeout: *timeout},
		idHeader:     *idHeader,
		allowPrivate: *allowPrivate,
		dryRun:       *dryRun,
		maxWait:      *maxWait,
		started:      time.Now(),
	}
	// Proxy: nil — this process is the egress point and must never chain to
	// an ambient HTTP_PROXY, which would loop straight back into itself.
	p.transport = &http.Transport{
		Proxy:                 nil,
		DialContext:           p.dial,
		ResponseHeaderTimeout: *timeout,
		MaxIdleConnsPerHost:   8,
		ForceAttemptHTTP2:     false,
	}

	srv := &http.Server{
		Addr:              *addr,
		Handler:           p,
		ReadHeaderTimeout: 15 * time.Second,
	}

	fmt.Fprintf(os.Stderr, "bbguard listening on %s\n", *addr)
	fmt.Fprintf(os.Stderr, "  program    %s (handle %q)\n", sc.Program(), sc.Handle())
	fmt.Fprintf(os.Stderr, "  scope      %d allow / %d deny / %d infra rules, default deny\n",
		len(sc.Summary()["allow"].([]string)), len(sc.Summary()["deny"].([]string)),
		len(sc.Summary()["infra"].([]string)))
	fmt.Fprintf(os.Stderr, "  pacing     %.3g rps global (burst %.3g), %.3g rps per host (burst %.3g)\n",
		*rps, *burst, *hostRPS, *hostBurst)
	if *dryRun {
		fmt.Fprintf(os.Stderr, "  !! DRY RUN: out-of-scope requests are forwarded, not blocked\n")
	}
	if *allowPrivate {
		fmt.Fprintf(os.Stderr, "  !! internal addresses permitted\n")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	errc := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errc <- err
		}
	}()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	sdCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(sdCtx)
	st := alog.Stats()
	fmt.Fprintf(os.Stderr, "\nbbguard stopped — allowed %d, denied %d, throttled %d\n",
		st["allowed"], st["denied"], st["throttled"])
	return nil
}

func (p *proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
		return
	}
	// A proxied request carries an absolute URI, so an empty URL.Host means
	// the client is talking to bbguard itself rather than through it.
	if r.URL.Host == "" {
		p.handleAdmin(w, r)
		return
	}
	p.handleHTTP(w, r)
}

// authorize runs the scope decision and the pacing decision for one host,
// writes the audit line, and reports whether the caller may proceed.
func (p *proxy) authorize(w http.ResponseWriter, r *http.Request, host, rawURL string) bool {
	d := p.scope.Check(host)
	ev := audit.Event{
		Method:  r.Method,
		Host:    scope.Normalize(host),
		URL:     rawURL,
		Allowed: d.Allowed,
		Reason:  d.Reason,
		Rule:    d.Rule,
	}
	if !d.Allowed {
		if !p.dryRun {
			ev.Status = http.StatusForbidden
			p.log.Write(ev)
			http.Error(w, fmt.Sprintf(
				"bbguard: %s is %s — refusing to send this request.\nScope is enforced here, not in the agent's prompt. Edit the scope file if this host really is in the engagement.\n",
				scope.Normalize(host), d.Reason), http.StatusForbidden)
			return false
		}
		ev.DryRun = true
		ev.Allowed = true
		ev.Reason = d.Reason + " (forwarded: dry-run)"
	}

	if d.Infra {
		// Operational traffic is not the target's problem: no pacing, and no
		// researcher handle leaked to a third-party API.
		p.log.Write(ev)
		return true
	}

	wait, ok := p.lim.Reserve(scope.Normalize(host), p.maxWait)
	if !ok {
		ev.Allowed = false
		ev.Reason = "rate limit: pacing delay would exceed max-wait"
		ev.Status = http.StatusTooManyRequests
		p.log.Write(ev)
		w.Header().Set("Retry-After", "1")
		http.Error(w, "bbguard: slow down — per-host or global rate ceiling reached\n", http.StatusTooManyRequests)
		return false
	}
	if wait > 0 {
		ev.WaitMS = wait.Milliseconds()
		select {
		case <-time.After(wait):
		case <-r.Context().Done():
			return false
		}
	}
	p.log.Write(ev)
	return true
}

func (p *proxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	if !p.authorize(w, r, r.URL.Host, r.URL.String()) {
		return
	}

	out := r.Clone(r.Context())
	out.RequestURI = ""
	for _, h := range hopByHop {
		out.Header.Del(h)
	}
	if !p.scope.Check(r.URL.Host).Infra {
		p.stamp(out)
	}

	resp, err := p.transport.RoundTrip(out)
	if err != nil {
		p.log.Write(audit.Event{
			Method: r.Method, Host: scope.Normalize(r.URL.Host), URL: r.URL.String(),
			Allowed: true, Reason: "upstream error", Error: err.Error(),
			Status: http.StatusBadGateway,
		})
		http.Error(w, "bbguard: upstream error: "+err.Error()+"\n", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for _, h := range hopByHop {
		resp.Header.Del(h)
	}
	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

// stamp adds the identifying header and user-agent marker so a program's blue
// team can attribute the traffic to the researcher instead of treating it as an
// attack. It only works for plain HTTP — a CONNECT tunnel is opaque, so for
// HTTPS the marker has to come from the tool (or from ARTEX's own MITM proxy
// sitting in front of bbguard).
func (p *proxy) stamp(r *http.Request) {
	handle := p.scope.Handle()
	if handle == "" {
		return
	}
	if p.idHeader != "" {
		r.Header.Set(p.idHeader, handle)
	}
	marker := "(bugbounty:" + handle + ")"
	if ua := r.Header.Get("User-Agent"); !strings.Contains(ua, marker) {
		if ua == "" {
			r.Header.Set("User-Agent", marker)
		} else {
			r.Header.Set("User-Agent", ua+" "+marker)
		}
	}
}

func (p *proxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	if !p.authorize(w, r, r.Host, "") {
		return
	}
	target := r.Host
	if _, _, err := net.SplitHostPort(target); err != nil {
		target = net.JoinHostPort(target, "443")
	}
	upstream, err := p.dial(r.Context(), "tcp", target)
	if err != nil {
		http.Error(w, "bbguard: dial failed: "+err.Error()+"\n", http.StatusBadGateway)
		return
	}
	defer upstream.Close()

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "bbguard: CONNECT needs a hijackable connection\n", http.StatusInternalServerError)
		return
	}
	client, _, err := hj.Hijack()
	if err != nil {
		http.Error(w, "bbguard: hijack failed\n", http.StatusInternalServerError)
		return
	}
	defer client.Close()

	if _, err := client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(upstream, client); done <- struct{}{} }()
	go func() { _, _ = io.Copy(client, upstream); done <- struct{}{} }()
	<-done
}

// dial resolves the target and refuses addresses inside the operator's own
// network. The scope check covers the name; this covers the address it points
// at, so a target whose DNS answers 127.0.0.1 or 169.254.169.254 cannot turn
// the agent into a pivot into the host running it.
func (p *proxy) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", host, err)
	}
	var lastErr error
	for _, ia := range ips {
		if !p.allowPrivate && isInternal(ia.IP) {
			lastErr = fmt.Errorf("%s resolves to internal address %s — blocked (pass -allow-private only for an engagement that really covers internal ranges)", host, ia.IP)
			continue
		}
		conn, err := p.dialer.DialContext(ctx, network, net.JoinHostPort(ia.IP.String(), port))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no usable address for %s", host)
	}
	return nil, lastErr
}

func isInternal(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsInterfaceLocalMulticast()
}

func (p *proxy) handleAdmin(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/healthz":
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintln(w, "ok")
	case "/scope":
		writeJSON(w, p.scope.Summary())
	case "/stats":
		st := p.log.Stats()
		writeJSON(w, map[string]any{
			"program":      p.scope.Program(),
			"uptime_sec":   int64(time.Since(p.started).Seconds()),
			"allowed":      st["allowed"],
			"denied":       st["denied"],
			"throttled":    st["throttled"],
			"host_buckets": p.lim.Hosts(),
			"dry_run":      p.dryRun,
		})
	default:
		http.Error(w, "bbguard: this is a proxy. Set HTTP_PROXY/HTTPS_PROXY to this address, or query /healthz, /scope, /stats.\n", http.StatusBadRequest)
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

// dialerForTest is the dialer used by tests; production builds the dialer in
// run() from the -timeout flag.
func dialerForTest() *net.Dialer { return &net.Dialer{Timeout: 5 * time.Second} }
