package scope

import "testing"

func testScope(t *testing.T) *Scope {
	t.Helper()
	s, err := New(Config{
		Program: "acme-vdp",
		Handle:  "researcher",
		Allow:   []string{"*.target.com", "api.partner.io", "192.0.2.0/24", "198.51.100.7"},
		Deny:    []string{"blog.target.com", "*.internal.target.com", "192.0.2.200"},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

func TestCheck(t *testing.T) {
	s := testScope(t)
	cases := []struct {
		host string
		want bool
		why  string
	}{
		// in scope
		{"target.com", true, "wildcard covers the apex"},
		{"www.target.com", true, "direct subdomain"},
		{"a.b.c.target.com", true, "nested subdomain"},
		{"WWW.TARGET.COM", true, "case insensitive"},
		{"www.target.com.", true, "trailing dot"},
		{"www.target.com:8443", true, "explicit port"},
		{"https://www.target.com/admin?x=1", true, "full URL"},
		{"api.partner.io", true, "exact rule"},
		{"192.0.2.5", true, "inside allowed CIDR"},
		{"198.51.100.7", true, "single allowed address"},

		// deny beats allow
		{"blog.target.com", false, "explicit deny"},
		{"BLOG.target.com:443", false, "deny is case/port insensitive"},
		{"vpn.internal.target.com", false, "wildcard deny"},
		{"internal.target.com", false, "wildcard deny covers its apex"},
		{"192.0.2.200", false, "address carved out of an allowed CIDR"},

		// default deny
		{"", false, "empty host"},
		{"example.com", false, "unrelated host"},
		{"partner.io", false, "exact rule does not imply the apex"},
		{"sub.api.partner.io", false, "exact rule does not imply subdomains"},
		{"192.0.3.5", false, "outside the allowed CIDR"},
		{"198.51.100.8", false, "adjacent to an allowed address"},

		// suffix-confusion attempts
		{"nottarget.com", false, "shares a suffix but not a label boundary"},
		{"eviltarget.com", false, "label-boundary check"},
		{"target.com.evil.com", false, "allowed host as a left-hand label"},
		{"www.target.com.evil.com", false, "allowed host buried in an attacker domain"},

		// parser-confusion attempts
		{"evil.com#.target.com", false, "fragment trick: the host is evil.com"},
		{"evil.com/.target.com", false, "path trick"},
		{"evil.com?x=.target.com", false, "query trick"},
		{"www.target.com@evil.com", false, "userinfo trick: the host is evil.com"},
		{"https://www.target.com@evil.com/", false, "userinfo trick inside a URL"},

		// a domain grant must never authorize a bare address
		{"93.184.216.34", false, "address literal is not covered by a domain rule"},
		{"[2001:db8::1]:443", false, "IPv6 literal is not covered by a domain rule"},
	}
	for _, c := range cases {
		got := s.Check(c.host)
		if got.Allowed != c.want {
			t.Errorf("Check(%q) = %v (%s, rule %q); want %v — %s",
				c.host, got.Allowed, got.Reason, got.Rule, c.want, c.why)
		}
	}
}

func TestDenyWinsRegardlessOfOrder(t *testing.T) {
	s, err := New(Config{
		Allow: []string{"*.target.com", "secret.target.com"},
		Deny:  []string{"secret.target.com"},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if d := s.Check("secret.target.com"); d.Allowed {
		t.Fatalf("an explicitly allowed host must still lose to a deny rule, got %+v", d)
	}
}

func TestEmptyAllowListRejected(t *testing.T) {
	if _, err := New(Config{Allow: nil, Deny: []string{"x.com"}}); err == nil {
		t.Fatal("a scope with no allow rules must be rejected at load time")
	}
}

func TestBadRules(t *testing.T) {
	for _, bad := range []string{"", "   ", "*", "*.", "ev*l.com", "a.*.com", "10.0.0.0/33", "192.0.2.0/abc"} {
		if _, err := New(Config{Allow: []string{bad}}); err == nil {
			t.Errorf("rule %q should have been rejected", bad)
		}
	}
}

func TestNormalize(t *testing.T) {
	cases := map[string]string{
		"Example.COM":              "example.com",
		"example.com.":             "example.com",
		"example.com:443":          "example.com",
		"http://example.com/a/b":   "example.com",
		"https://u:p@example.com/": "example.com",
		"[2001:db8::1]:8080":       "2001:db8::1",
		"2001:db8::1":              "2001:db8::1",
		"  example.com  ":          "example.com",
		"example.com?a=b":          "example.com",
		"example.com#frag":         "example.com",
		"":                         "",
	}
	for in, want := range cases {
		if got := Normalize(in); got != want {
			t.Errorf("Normalize(%q) = %q; want %q", in, got, want)
		}
	}
}

func TestInfraIsReachableButNotTargetTraffic(t *testing.T) {
	s, err := New(Config{
		Allow: []string{"*.target.com"},
		Deny:  []string{"blog.target.com"},
		Infra: []string{"api.anthropic.com", "*.oast.pro"},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	d := s.Check("api.anthropic.com")
	if !d.Allowed || !d.Infra {
		t.Fatalf("LLM provider should be allowed and flagged as infra, got %+v", d)
	}
	if d := s.Check("abc.oast.pro"); !d.Allowed || !d.Infra {
		t.Fatalf("OOB callback host should be infra, got %+v", d)
	}
	// Target traffic must not be mislabelled.
	if d := s.Check("www.target.com"); !d.Allowed || d.Infra {
		t.Fatalf("in-scope target should be allowed and NOT infra, got %+v", d)
	}
	// A host in both lists is treated as the stricter of the two: target.
	s2, _ := New(Config{Allow: []string{"both.com"}, Infra: []string{"both.com"}})
	if d := s2.Check("both.com"); !d.Allowed || d.Infra {
		t.Fatalf("a host in allow and infra must count as target traffic, got %+v", d)
	}
	// Deny still outranks infra.
	s3, _ := New(Config{Allow: []string{"x.com"}, Deny: []string{"evil.infra.com"}, Infra: []string{"*.infra.com"}})
	if d := s3.Check("evil.infra.com"); d.Allowed {
		t.Fatalf("deny must outrank infra, got %+v", d)
	}
}
