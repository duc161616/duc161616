#!/usr/bin/env python3
"""Draft a bug bounty report from one ARTEX finding.

What this does NOT do is turn the agent's claim into a submission. The agent's
summary goes in marked as an unverified claim, and every spot that needs your
own proof is left as an explicit TODO, because a report whose PoC you have not
run yourself is how a researcher burns their reputation.

    python3 bbkit/report.py findings.json --id 42 > report.md
    python3 bbkit/report.py findings.json --id 42 --format bugcrowd
    python3 bbkit/report.py findings.json --id 42 --evidence ./export/   # md-zip dir

Request/response bytes are absent from the JSON export by design
(server/server.go:2148). Pass --evidence pointing at an unzipped md-zip export
to pull real traffic in; otherwise the PoC section is left as a TODO.
"""
import argparse
import glob
import json
import os
import sys

TODO = "**TODO —** "

CVSS_HINT = {
    "critical": "9.0-10.0 — RCE, auth bypass at scale, mass PII exposure",
    "high": "7.0-8.9 — ATO, privilege escalation, significant data exposure",
    "medium": "4.0-6.9 — limited scope, or needs preconditions",
    "low": "0.1-3.9 — minimal impact; consider whether it is worth filing",
}


def load_finding(path, fid):
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    findings = data if isinstance(data, list) else data.get("findings", [])
    fid = str(fid)
    for f in findings:
        if str(f.get("id")) == fid or str(f.get("finding_id") or "") == fid:
            return f
    ids = ", ".join(str(f.get("id")) for f in findings[:20])
    raise SystemExit(f"finding {fid} not found. available: {ids}" + (" ..." if len(findings) > 20 else ""))


def assets(f):
    out = []
    for a in f.get("assets") or []:
        label = a.get("label") or a.get("value") or a.get("name") or a.get("id")
        typ = a.get("type") or "?"
        if label:
            out.append(f"{label} ({typ})")
    return out


def evidence_blocks(f, evidence_dir):
    """Render bound traffic. Heads are blanked in the JSON export, so without
    --evidence this returns the metadata and an explicit gap."""
    blocks = []
    for b in f.get("traffic_bindings") or []:
        snap = b.get("snapshot") or {}
        role = b.get("role") or "supporting"
        req, resp = snap.get("req_head") or "", snap.get("resp_head") or ""
        if not req and evidence_dir:
            req, resp = from_evidence_dir(evidence_dir, snap.get("id") or b.get("snapshot_id") or "")
        blocks.append({
            "role": role,
            "note": b.get("note") or "",
            "method": snap.get("method") or "?",
            "url": snap.get("url") or "?",
            "status": snap.get("status") or "?",
            "req": req,
            "resp": resp,
            "req_len": snap.get("req_len") or 0,
            "resp_len": snap.get("resp_len") or 0,
        })
    blocks.sort(key=lambda b: {"proof": 0, "verification": 1, "baseline": 2, "supporting": 3}.get(b["role"], 4))
    return blocks


def from_evidence_dir(evidence_dir, snapshot_id):
    """Best-effort lookup of raw exchange files in an unzipped md-zip export."""
    if not snapshot_id:
        return "", ""
    hits = glob.glob(os.path.join(evidence_dir, "**", f"*{snapshot_id}*"), recursive=True)
    req = resp = ""
    for h in hits:
        if not os.path.isfile(h):
            continue
        try:
            with open(h, encoding="utf-8", errors="replace") as fh:
                body = fh.read()
        except OSError:
            continue
        low = os.path.basename(h).lower()
        if "req" in low and not req:
            req = body
        elif "resp" in low and not resp:
            resp = body
    return req, resp


def render(f, fmt, evidence_dir):
    name = f.get("name") or f.get("vulnclass") or "(unnamed finding)"
    sev = (f.get("severity") or "").lower()
    ass = assets(f)
    blocks = evidence_blocks(f, evidence_dir)
    L = []
    w = L.append

    primary = ass[0].split(" (")[0] if ass else "TODO-endpoint"
    w(f"# {name} on {primary}")
    w("")
    w(f"> Drafted from ARTEX finding `{f.get('id')}`"
      + (f" (task `{f.get('task_id')}`)" if f.get("task_id") else "")
      + ". Not submittable until every TODO below is gone.")
    w("")

    w("## Summary")
    w("")
    w(TODO + "one or two sentences in your own words: what is broken, where, and what it lets an attacker do.")
    w("")
    claim = (f.get("summary") or "").strip()
    if claim:
        w("<details><summary>ARTEX agent's claim — unverified, do not paste into the report</summary>")
        w("")
        w("```")
        w(claim)
        w("```")
        w("</details>")
        w("")

    w("## Affected asset")
    w("")
    if ass:
        for a in ass:
            w(f"- `{a}`")
    else:
        w(TODO + "no asset was anchored to this finding — name the exact URL and parameter.")
    w("")
    w(TODO + "confirm each one appears in the program's written scope, and none in the out-of-scope list.")
    w("")

    w("## Steps to reproduce")
    w("")
    w(TODO + "numbered steps someone else can follow from a clean session. "
      "Start from 'log in as a normal user', not from agent state.")
    w("")
    w("1. ")
    w("2. ")
    w("3. ")
    w("")

    w("## Proof of concept")
    w("")
    if not blocks:
        w(TODO + "no traffic is bound to this finding. Reproduce by hand and paste the raw "
          "request and response. A report without them gets closed as not reproducible.")
        w("")
    for i, b in enumerate(blocks, 1):
        w(f"### {i}. {b['role']} — `{b['method']} {b['url']}` → {b['status']}")
        if b["note"]:
            w("")
            w(f"_{b['note']}_")
        w("")
        if b["req"]:
            w("```http")
            w(b["req"].rstrip())
            w("```")
        else:
            w(TODO + f"raw request not in this export ({b['req_len']} bytes recorded). "
              "Re-export with `format=md-zip`, or re-run the request yourself and paste it.")
        w("")
        if b["resp"]:
            w("```http")
            w(b["resp"].rstrip()[:4000])
            w("```")
        else:
            w(TODO + f"raw response not in this export ({b['resp_len']} bytes recorded).")
        w("")

    ev = (f.get("evidence") or "").strip()
    if ev:
        w("<details><summary>ARTEX evidence notes — unverified</summary>")
        w("")
        w("```")
        w(ev[:3000])
        w("```")
        w("</details>")
        w("")

    w("## Impact")
    w("")
    w(TODO + "what an attacker achieves, concretely. Name the victim, the data or money, "
      "and the scale. 'Could potentially' is not an impact statement.")
    w("")

    w("## Severity")
    w("")
    w(f"Agent assigned: **{sev or 'unset'}**" + (f" — {CVSS_HINT[sev]}" if sev in CVSS_HINT else ""))
    w("")
    w(TODO + "set your own severity from demonstrated impact and justify it. "
      "Inflated severity costs you more credibility than it gains bounty.")
    w("")

    w("## Remediation")
    w("")
    w(TODO + "specific fix for this code path, not 'validate all input'.")
    w("")

    if fmt == "bugcrowd":
        w("## VRT category")
        w("")
        w(TODO + "pick the Bugcrowd VRT entry and paste its path.")
        w("")

    w("---")
    w("")
    w("### Pre-submit checklist")
    w("")
    for item in (
        "I reproduced this myself, by hand, outside ARTEX",
        "The raw request and response above are from my own run",
        "Every affected asset is in the written scope",
        "I checked the program's out-of-scope and known-issues lists",
        "I searched disclosed reports for a duplicate",
        "The impact statement describes real harm, demonstrated",
        "No TODO remains above this line",
    ):
        w(f"- [ ] {item}")
    w("")
    return "\n".join(L)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("findings")
    ap.add_argument("--id", required=True, help="finding id or finding_id")
    ap.add_argument("--format", choices=("hackerone", "bugcrowd"), default="hackerone")
    ap.add_argument("--evidence", help="directory of an unzipped md-zip export, to pull raw traffic from")
    args = ap.parse_args()
    f = load_finding(args.findings, args.id)
    sys.stdout.write(render(f, args.format, args.evidence) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
