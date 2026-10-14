// Package scope implements deny-by-default host authorization for bug bounty
// engagements. It is the control ARTEX lacks: guard/guard.go notes the RoE
// authorization-scope mechanism was removed, and task_constraints are rendered
// into the LLM system prompt (agent/constraints.go) rather than enforced. An
// LLM instruction is a request; this package is a decision.
//
// Rules of the model, in order:
//
//  1. deny wins over allow, always;
//  2. nothing matches => denied (there is no implicit allow);
//  3. a domain rule never authorizes a bare IP literal, because an address may
//     serve hosts outside the engagement.
package scope

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
)

// Decision is the verdict for one host.
type Decision struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason"`
	Rule    string `json:"rule,omitempty"`
	// Infra marks a host the operator's own stack needs (the LLM API, a
	// collaborator callback) rather than part of the engagement. Such a host
	// is reachable but is not target traffic: it must not be paced with the
	// target budget, and it must not be stamped with the researcher handle.
	Infra bool `json:"infra,omitempty"`
}

// Config is the on-disk scope definition.
type Config struct {
	// Program is a label for the engagement, echoed into the audit log.
	Program string `json:"program"`
	// Handle is the researcher handle advertised to targets via the
	// identifying request header, so blue teams can attribute the traffic.
	Handle string `json:"handle"`
	// Allow and Deny hold host patterns: "example.com" (exact),
	// "*.example.com" (apex + any depth of subdomain), "10.0.0.0/8" (CIDR)
	// or "192.0.2.7" (single address).
	Allow []string `json:"allow"`
	Deny  []string `json:"deny"`
	// Infra holds operational hosts — the LLM provider, an OOB interaction
	// server — that the stack must reach to function. Keeping them out of
	// Allow is what stops ARTEX's own LLM calls from eating the target's
	// rate budget, and keeps the audit log readable as target traffic only.
	Infra []string `json:"infra"`
}

type ruleKind int

const (
	kindExact ruleKind = iota
	kindWildcard
	kindCIDR
	kindIP
)

type rule struct {
	raw  string
	kind ruleKind
	host string
	ipn  *net.IPNet
	ip   net.IP
}

// Scope evaluates hosts against a compiled rule set.
type Scope struct {
	cfg   Config
	allow []rule
	deny  []rule
	infra []rule
}

// Load reads and compiles a scope file.
func Load(path string) (*Scope, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read scope: %w", err)
	}
	var cfg Config
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parse scope %s: %w", path, err)
	}
	return New(cfg)
}

// New compiles cfg. An empty allow list is rejected: a scope that authorizes
// nothing is almost always a mistake, and failing loudly beats a proxy that
// silently denies every request.
func New(cfg Config) (*Scope, error) {
	if len(cfg.Allow) == 0 {
		return nil, fmt.Errorf("scope has an empty allow list: nothing would be reachable")
	}
	s := &Scope{cfg: cfg}
	for _, raw := range cfg.Allow {
		r, err := compile(raw)
		if err != nil {
			return nil, fmt.Errorf("allow rule %q: %w", raw, err)
		}
		s.allow = append(s.allow, r)
	}
	for _, raw := range cfg.Deny {
		r, err := compile(raw)
		if err != nil {
			return nil, fmt.Errorf("deny rule %q: %w", raw, err)
		}
		s.deny = append(s.deny, r)
	}
	for _, raw := range cfg.Infra {
		r, err := compile(raw)
		if err != nil {
			return nil, fmt.Errorf("infra rule %q: %w", raw, err)
		}
		s.infra = append(s.infra, r)
	}
	return s, nil
}

func compile(raw string) (rule, error) {
	t := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(raw)), ".")
	if t == "" {
		return rule{}, fmt.Errorf("empty rule")
	}
	switch {
	case strings.Contains(t, "/"):
		_, ipn, err := net.ParseCIDR(t)
		if err != nil {
			return rule{}, fmt.Errorf("not a CIDR: %w", err)
		}
		return rule{raw: raw, kind: kindCIDR, ipn: ipn}, nil
	case net.ParseIP(t) != nil:
		return rule{raw: raw, kind: kindIP, ip: net.ParseIP(t)}, nil
	case strings.HasPrefix(t, "*."):
		host := strings.TrimPrefix(t, "*.")
		if host == "" || strings.Contains(host, "*") {
			return rule{}, fmt.Errorf("malformed wildcard")
		}
		return rule{raw: raw, kind: kindWildcard, host: host}, nil
	case strings.Contains(t, "*"):
		return rule{}, fmt.Errorf("wildcards are only supported as a leading %q label", "*.")
	default:
		return rule{raw: raw, kind: kindExact, host: t}, nil
	}
}

// Normalize reduces anything host-shaped — a bare host, host:port, a full URL,
// a bracketed IPv6 literal, a value carrying userinfo — to a comparable host.
// Everything from the first "/", "?" or "#" is dropped, which is what defeats
// the "evil.com#.target.com" class of trick: the host is evil.com, and it gets
// evaluated as such.
func Normalize(hostport string) string {
	h := strings.TrimSpace(hostport)
	if h == "" {
		return ""
	}
	if i := strings.Index(h, "://"); i >= 0 {
		h = h[i+3:]
	}
	if i := strings.IndexAny(h, "/?#"); i >= 0 {
		h = h[:i]
	}
	if i := strings.LastIndex(h, "@"); i >= 0 {
		h = h[i+1:]
	}
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	h = strings.Trim(h, "[]")
	return strings.TrimSuffix(strings.ToLower(h), ".")
}

// Check evaluates one host. hostport may carry a port, a scheme or a path.
func (s *Scope) Check(hostport string) Decision {
	host := Normalize(hostport)
	if host == "" {
		return Decision{Allowed: false, Reason: "empty host"}
	}
	ip := net.ParseIP(host)

	for _, r := range s.deny {
		if r.matches(host, ip) {
			return Decision{Allowed: false, Reason: "out of scope (deny rule)", Rule: r.raw}
		}
	}
	for _, r := range s.allow {
		if r.matches(host, ip) {
			return Decision{Allowed: true, Reason: "in scope", Rule: r.raw}
		}
	}
	// Infra is checked after allow so a host listed in both is treated as
	// target traffic, which is the stricter of the two.
	for _, r := range s.infra {
		if r.matches(host, ip) {
			return Decision{Allowed: true, Reason: "infra (not target traffic)", Rule: r.raw, Infra: true}
		}
	}
	return Decision{Allowed: false, Reason: "not in scope (default deny)"}
}

func (r rule) matches(host string, ip net.IP) bool {
	isIP := ip != nil
	switch r.kind {
	case kindCIDR:
		return isIP && r.ipn.Contains(ip)
	case kindIP:
		return isIP && r.ip.Equal(ip)
	case kindExact:
		// A domain rule must not authorize an address literal.
		return !isIP && host == r.host
	case kindWildcard:
		return !isIP && (host == r.host || strings.HasSuffix(host, "."+r.host))
	}
	return false
}

// Program returns the engagement label.
func (s *Scope) Program() string { return s.cfg.Program }

// Handle returns the researcher handle advertised to targets.
func (s *Scope) Handle() string { return s.cfg.Handle }

// Summary describes the compiled rule set for logs and the /scope endpoint.
func (s *Scope) Summary() map[string]any {
	return map[string]any{
		"program": s.cfg.Program,
		"handle":  s.cfg.Handle,
		"allow":   s.cfg.Allow,
		"deny":    s.cfg.Deny,
		"infra":   s.cfg.Infra,
	}
}
