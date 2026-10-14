#!/usr/bin/env python3
"""Triage an ARTEX findings export before anything reaches a bug bounty platform.

ARTEX findings come from the agent calling report_finding — an LLM's own claim,
not a verified vulnerability. Submitting those directly is how researchers get
banned for AI-generated noise. This splits the export into buckets so the only
things you spend time on are the ones that could plausibly survive triage, and
nothing is ever labelled "verified" by this tool: that word belongs to a human
who reproduced it.

Input is the JSON export (server/server.go:2178):

    curl -H "Authorization: Bearer $ARTEX_JWT" \
      'http://localhost:8787/api/exploration/findings/export?scope=all&format=json' \
      -o findings.json
    python3 bbkit/triage.py findings.json

Note the JSON export deliberately blanks req_head/resp_head
(server/server.go:2148), so full request/response bytes are NOT in this file.
For evidence use format=md-zip. This tool therefore reports whether a finding
*has* bound traffic evidence, not what is in it.
"""
import argparse
import json
import re
import sys
from collections import OrderedDict, defaultdict

# ARTEX treats these as settled; anything else means the agent never confirmed it.
CONFIRMED_STATUS = {"confirmed", "resolved", "fixed"}
DISMISSED_STATUS = {"false_positive", "ignored", "duplicate", "risk_accepted"}
# Traffic roles that can act as proof (db/finding_traffic.go:70).
PROOF_ROLES = {"proof", "verification"}

# Classes that programs reject as informational unless chained into real impact.
# ARTEX's LLM writes Chinese, so both languages are matched.
LOW_IMPACT = [
    (r"(missing|lack|no)\s+(security\s+)?header|x-frame-options|content-security-policy|\bcsp\b|hsts|x-content-type|referrer-policy|permissions-policy|缺少.*(头|header)|安全头", "missing security header"),
    (r"clickjack|frame\s*injection|点击劫持", "clickjacking"),
    (r"cookie.*(httponly|secure|samesite)|(httponly|secure|samesite).*cookie|cookie.*(标志|属性)", "cookie flag"),
    (r"\bspf\b|\bdmarc\b|\bdkim\b|邮件伪造", "email auth record"),
    (r"(ssl|tls)\s*(version|cipher|protocol|weak|certificate|证书|弱加密)|sweet32|beast|poodle|logjam", "TLS configuration"),
    (r"(version|banner|software|server)\s*(disclosure|leak|exposure|泄露)|指纹|版本泄露|banner", "version disclosure"),
    (r"directory\s*(listing|index|browsing)|目录(浏览|遍历列表)", "directory listing"),
    (r"(verbose|detailed|stack)\s*(error|trace)|error\s*message\s*disclos|报错信息|堆栈", "verbose error"),
    (r"autocomplete|password\s*field", "autocomplete"),
    (r"self[\s-]*xss|自身xss", "self-XSS"),
    (r"(logout|login)\s*csrf|csrf.*(logout|login)", "logout/login CSRF"),
    (r"open\s*redirect|url\s*redirect|跳转漏洞|开放重定向", "open redirect (alone)"),
    (r"(rate\s*limit|brute\s*force)\s*(missing|absent|no|lack)|缺少(速率|频率)限制", "missing rate limit"),
    (r"tabnabbing|target\s*=\s*_blank", "tabnabbing"),
    (r"(weak|no)\s*password\s*(policy|complexity)|密码策略", "password policy"),
    (r"mixed\s*content|混合内容", "mixed content"),
    (r"source\s*map|sourcemap|\.map\b", "source map"),
    (r"robots\.txt|\.well-known|crossdomain\.xml", "well-known file"),
    (r"(user|email|account)\s*enumerat|用户枚举|账号枚举", "user enumeration"),
    (r"host\s*header\s*injection", "host header injection (needs a chain)"),
    (r"internal\s*ip\s*disclos|内网ip泄露|private\s*ip", "internal IP disclosure"),
]
LOW_IMPACT = [(re.compile(p, re.I), label) for p, label in LOW_IMPACT]

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "": 4}

GATE = [
    "Can an attacker do this RIGHT NOW against a user who took no unusual action?",
    "Have YOU reproduced it by hand, outside the agent?",
    "Do you hold the exact request + response that proves it?",
    "Is concrete harm demonstrated (funds, PII, ATO, code execution) — not 'could'?",
    "Is every asset involved inside the program's written scope?",
    "Is it already public, known, or in the program's out-of-scope list?",
    "Would you bet your reputation on this report being valid?",
]


def asset_labels(f):
    out = []
    for a in f.get("assets") or []:
        label = a.get("label") or a.get("value") or a.get("name") or a.get("id") or ""
        if label:
            out.append(str(label).strip().lower())
    return sorted(set(out))


def low_impact_label(f):
    haystack = " ".join(str(f.get(k) or "") for k in ("vulnclass", "name", "summary"))
    for rx, label in LOW_IMPACT:
        if rx.search(haystack):
            return label
    return None


def has_proof_traffic(f):
    bindings = f.get("traffic_bindings") or []
    if any((b.get("role") or "").lower() in PROOF_ROLES for b in bindings):
        return True
    # traffic_count covers the case where bindings were trimmed from the payload.
    return bool(bindings) or int(f.get("traffic_count") or 0) > 0


def classify(f):
    status = (f.get("status") or "").lower()
    if status in DISMISSED_STATUS:
        return "DISMISSED", f"ARTEX marked it {status}"
    label = low_impact_label(f)
    if label:
        return "LIKELY_REJECTED", f"reads as {label} — informational at most programs unless you chain it"
    if status not in CONFIRMED_STATUS:
        return "NOT_CONFIRMED", f"status is {status or 'empty'}: the agent never confirmed this itself"
    if not has_proof_traffic(f):
        return "NEEDS_EVIDENCE", "no bound traffic: there is nothing to put in a report"
    if not asset_labels(f):
        return "NEEDS_EVIDENCE", "no asset anchored: the affected endpoint is unknown"
    return "NEEDS_MANUAL_VERIFICATION", "has evidence and an asset — reproduce it by hand next"


def dedupe(findings):
    """Cluster by vuln class + affected assets. Same bug on the same endpoint
    reported twice by two workers is one report, not two."""
    groups = defaultdict(list)
    for f in findings:
        cls = re.sub(r"\W+", "", (f.get("vulnclass") or f.get("name") or "").lower())
        groups[(cls, tuple(asset_labels(f)))].append(f)
    primaries, dups = [], []
    for members in groups.values():
        members.sort(key=lambda f: SEVERITY_ORDER.get((f.get("severity") or "").lower(), 4))
        primaries.append(members[0])
        for d in members[1:]:
            d["_duplicate_of"] = members[0].get("id")
            dups.append(d)
    return primaries, dups


def title(f):
    name = f.get("name") or f.get("vulnclass") or "(unnamed)"
    assets = asset_labels(f)
    where = assets[0] if assets else "unknown asset"
    return f"{name} @ {where}"


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("findings", help="findings JSON export (format=json)")
    ap.add_argument("--json-out", help="also write the triage result as JSON")
    ap.add_argument("--show", default="", help="only print this bucket")
    args = ap.parse_args()

    with open(args.findings, encoding="utf-8") as fh:
        data = json.load(fh)
    findings = data if isinstance(data, list) else data.get("findings", [])
    if not findings:
        print("no findings in export", file=sys.stderr)
        return 1

    primaries, dups = dedupe(findings)
    buckets = OrderedDict((b, []) for b in
                          ("NEEDS_MANUAL_VERIFICATION", "NEEDS_EVIDENCE", "NOT_CONFIRMED",
                           "LIKELY_REJECTED", "DISMISSED"))
    for f in primaries:
        bucket, why = classify(f)
        buckets[bucket].append((f, why))
    for b in buckets:
        buckets[b].sort(key=lambda t: SEVERITY_ORDER.get((t[0].get("severity") or "").lower(), 4))

    print(f"# ARTEX triage — {len(findings)} findings, {len(primaries)} after dedupe "
          f"({len(dups)} duplicate{'s' if len(dups) != 1 else ''} folded)\n")
    print("Nothing below is verified. The top bucket is the work queue; everything")
    print("else is either not ready or not worth your time.\n")

    for bucket, items in buckets.items():
        if args.show and bucket != args.show.upper():
            continue
        print(f"\n## {bucket} — {len(items)}")
        if not items:
            print("  (none)")
            continue
        for f, why in items:
            sev = (f.get("severity") or "?").upper()
            print(f"\n  [{sev}] {title(f)}")
            print(f"    id={f.get('id')} finding_id={f.get('finding_id') or '-'} "
                  f"task={f.get('task_id') or '-'} traffic={f.get('traffic_count') or 0}")
            print(f"    why: {why}")
            summary = (f.get("summary") or "").strip().replace("\n", " ")
            if summary:
                print(f"    agent's claim (unverified): {summary[:160]}")

    ready = buckets["NEEDS_MANUAL_VERIFICATION"]
    if ready and not args.show:
        print(f"\n\n## Gate — run this on each of the {len(ready)} queued findings")
        print("   A 'no' anywhere means drop it or go get the missing proof.\n")
        for i, q in enumerate(GATE, 1):
            print(f"   {i}. {q}")
        print("\n   Build a report only for what passes:")
        print("   python3 bbkit/report.py findings.json --id <id> > report.md")

    if args.json_out:
        out = {b: [{"finding": f, "reason": w} for f, w in items] for b, items in buckets.items()}
        out["duplicates"] = dups
        with open(args.json_out, "w", encoding="utf-8") as fh:
            json.dump(out, fh, ensure_ascii=False, indent=2)
        print(f"\n[wrote {args.json_out}]")
    return 0


if __name__ == "__main__":
    sys.exit(main())
