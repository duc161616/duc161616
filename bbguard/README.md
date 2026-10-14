# bbguard

Deny-by-default egress proxy for bug bounty work. It is the lock ARTEX is
missing: `guard/guard.go:4` records that the RoE authorization-scope mechanism
was removed, and `task_constraints` are rendered into the model's system prompt
(`agent/constraints.go`) rather than enforced — the author's own comment calls
it a *"tug-of-war"*. bbguard is not a tug-of-war. An out-of-scope request gets
403 regardless of what the model decided.

```
agent tool ──► ARTEX MITM :8788 ──► bbguard :8899 ──► internet
               (records evidence)    (scope + pacing + audit)
                                      ▲
                           the only egress route the container has
```

## What it enforces

| Control | Behaviour |
|---|---|
| **Scope** | Allowlist of hosts; nothing matched → denied. `deny` always beats `allow`. A domain rule never authorizes a bare IP, because an address may serve hosts outside the engagement. |
| **Pacing** | Two token buckets, global and per-host. Over budget → paced, then 429 past `-max-wait`, so backpressure reaches the agent instead of queueing goroutines. |
| **Attribution** | `X-Bug-Bounty: <handle>` plus a user-agent marker on plain HTTP, so a blue team can tell research from an attack. |
| **Internal addresses** | A target that resolves to loopback/RFC1918/link-local is refused, so a hostile DNS answer cannot turn the agent into a pivot into your own network. `169.254.169.254` is covered. |
| **Audit** | Every decision as a JSON line: what was asked for, whether it went out, which rule decided, how long it was paced. |
| **Infra hosts** | The LLM API and OOB callback servers are reachable but exempt from target pacing, and never receive your handle. |

## Scope file

```json
{
  "program": "acme-public-bbp",
  "handle": "duc161616",
  "allow": ["*.acme.com", "api.acme.io", "192.0.2.0/24"],
  "deny":  ["blog.acme.com", "*.corp.acme.com"],
  "infra": ["api.anthropic.com", "*.oast.pro"]
}
```

- `*.acme.com` matches the apex and any depth of subdomain. If the apex is out
  of scope, put it in `deny` — deny wins.
- `allow` may not be empty: a scope that reaches nothing is a mistake, and
  failing at startup beats a proxy that silently denies everything.
- Only a leading `*.` wildcard is supported; `ev*l.com` is rejected at load.

## Run

```bash
go build -o bbguard ./cmd/bbguard
./bbguard -scope scope.json -addr 127.0.0.1:8899 -audit run.jsonl

HTTPS_PROXY=http://127.0.0.1:8899 curl https://api.acme.com/   # 200
HTTPS_PROXY=http://127.0.0.1:8899 curl https://example.com/    # 403
curl -s localhost:8899/stats
```

Flags worth knowing: `-rps/-burst` and `-host-rps/-host-burst` (ceilings),
`-max-wait` (pace past this → 429), `-allow-private` (only for an engagement
that really covers internal ranges), `-dry-run` (forward everything but log
what would have been cut — for calibrating a scope, never for a live run).

## Limits — read these

- **A CONNECT tunnel is opaque.** For HTTPS, bbguard enforces scope and pacing
  on the host in the CONNECT line, but cannot add the identifying header. Put
  ARTEX's MITM proxy in front of it if you need the header on TLS traffic.
- **A proxy only binds tools that honour it.** `nmap` and `masscan` ignore
  `HTTP_PROXY` entirely. Lock container egress (`deploy/docker-compose.yml`)
  so those tools have no route at all; the `[BB] Né proxy` intercept rule
  catches attempts to unset the proxy, but the network lock is the real control.
- **Scope is only as good as what you typed.** bbguard cannot know a program's
  policy. Re-read the scope page before each session, and keep `-dry-run`
  output from the first run as your calibration.
- **It is not an authorization.** It stops accidents. It does not make testing
  lawful, and ARTEX's own license forbids use against online systems.

## Tests

```bash
go test ./...
```

20 tests. The scope suite includes the bypass attempts worth caring about —
suffix confusion (`target.com.evil.com`), userinfo (`www.target.com@evil.com`),
fragment and path tricks, and a bare IP against a domain-only grant. The
end-to-end suite drives a real proxy: forwarding and stamping, 403 on
out-of-scope, CONNECT refusal, 429 under load, loopback refusal, dry-run, and
the infra exemption.
