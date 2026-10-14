#!/usr/bin/env python3
"""Load bbkit intercept rules into a running ARTEX instance.

ARTEX ships exactly one enabled hard gate ('[内置] 破坏性系统命令'); its
data-exfil rule is seeded disabled because the curl|nc pattern misfires on
legitimate reverse shells (db/db.go:540). Everything bug-bounty-specific — the
proxy-bypass block above all — has to be added, which is what this does.

    python3 bbkit/load_rules.py --base http://localhost:8787 --token "$ARTEX_JWT"
    python3 bbkit/load_rules.py --base http://localhost:8787 --token "$T" --dry-run

Get the token from the browser: localStorage.getItem('artex_token').
Validate patterns first — ARTEX uses Go RE2, which rejects lookahead:
    go run ./bbkit/validate-rules bbkit/intercept-rules.json
"""
import argparse
import json
import sys
import urllib.error
import urllib.request

# Fields that exist for the validator, not for the API.
LOCAL_ONLY = ("should_match", "should_not_match", "_comment")


def post_rule(base, token, rule, timeout):
    body = json.dumps({k: v for k, v in rule.items() if k not in LOCAL_ONLY}).encode()
    req = urllib.request.Request(
        base.rstrip("/") + "/api/intercept/rules",
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": "Bearer " + token,
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status, r.read().decode("utf-8", "replace")[:300]


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--base", default="http://localhost:8787", help="ARTEX base URL")
    ap.add_argument("--token", help="JWT (localStorage 'artex_token'); omit with --dry-run")
    ap.add_argument("--rules", default="bbkit/intercept-rules.json")
    ap.add_argument("--timeout", type=float, default=15.0)
    ap.add_argument("--dry-run", action="store_true", help="print what would be sent and exit")
    args = ap.parse_args()

    with open(args.rules, encoding="utf-8") as fh:
        rules = json.load(fh)["rules"]

    if args.dry_run:
        for r in rules:
            print(f"{r['action'].upper():5} p{r['priority']:<4} {r['name']}")
            print(f"      {r['pattern'][:110]}")
        print(f"\n{len(rules)} rules would be sent to {args.base}")
        return 0

    if not args.token:
        print("error: --token is required (or use --dry-run)", file=sys.stderr)
        return 2

    ok = fail = 0
    for r in rules:
        try:
            status, body = post_rule(args.base, args.token, r, args.timeout)
            print(f"  [{status}] {r['name']}")
            ok += 1
        except urllib.error.HTTPError as e:
            detail = e.read().decode("utf-8", "replace")[:200]
            print(f"  [{e.code}] {r['name']}  -> {detail}", file=sys.stderr)
            fail += 1
        except OSError as e:
            print(f"  [err] {r['name']}  -> {e}", file=sys.stderr)
            fail += 1

    print(f"\nloaded {ok}, failed {fail}")
    print("Check them in the UI under Cấu hình → Chặn/Phê duyệt, and confirm the")
    print("proxy-bypass rule sits above everything else by priority.")
    return 1 if fail else 0


if __name__ == "__main__":
    sys.exit(main())
