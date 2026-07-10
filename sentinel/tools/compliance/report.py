#!/usr/bin/env python3
"""Generate a markdown compliance report from a sentinel audit JSONL export.

Python (stdlib only) on purpose: compliance teams run this offline against an
exported log, with no Go toolchain and no sentinel deployment. The report
covers:

  - chain integrity (re-verified here, independently of sentinel: the hash
    chain plus the out-of-band anchor sidecar that catches tail-truncation)
  - decision breakdown (allow / challenge / deny) and top risk reasons
  - authentication failure trends by hour
  - accounts hit by lockouts
  - top risky source IPs (failures + denials)

Usage: report.py <audit.jsonl> [output.md] [--allow-missing-anchors]
With no output path the report goes to stdout. Exit status 1 if the export
does not verify — a report over a tampered log is worse than no report.
"""
import sys
from collections import Counter

import verify_chain


def _details(rec):
    return rec.get("details") or {}


def build_report(records, verdict):
    """Render the report. verdict is (ok, reason) from verify_chain.verify_export.

    The verdict is passed in rather than recomputed here: a report must not
    reach its own conclusion about integrity from the chain walk alone, which
    cannot see tail-truncation.
    """
    ok, reason = verdict

    decisions = [r for r in records if r.get("type") == "sentinel.decision"]
    results = [r for r in records if r.get("type") == "auth.result"]
    anchors = [r for r in records if r.get("type") == "sentinel.anchor"]

    by_decision = Counter(r.get("action", "?") for r in decisions)
    reasons = Counter()
    for r in decisions:
        for reason_tag in filter(None, _details(r).get("reasons", "").split(",")):
            reasons[reason_tag] += 1

    failures = [r for r in results if r.get("action") == "failure"]
    successes = [r for r in results if r.get("action") == "success"]
    fail_by_hour = Counter(r.get("ts", "")[:13] for r in failures)
    fail_by_account = Counter(r.get("actor", "?") for r in failures)

    lockouts = Counter()
    for r in decisions:
        if "locked_out" in _details(r).get("reasons", ""):
            lockouts[r.get("actor", "?")] += 1

    risky_ips = Counter()
    for r in failures:
        risky_ips[_details(r).get("ip", "?")] += 1
    for r in decisions:
        if r.get("action") == "deny":
            risky_ips[_details(r).get("ip", "?")] += 1

    lines = []
    out = lines.append
    out("# Sentinel compliance report")
    out("")
    span = "(empty log)"
    if records:
        span = "%s — %s" % (records[0].get("ts", "?"), records[-1].get("ts", "?"))
    out("- Records: **%d** (%s)" % (len(records), span))
    out("- Anchors: %d" % len(anchors))
    if ok:
        head = records[-1]["hash"] if records else "-"
        out("- Chain integrity: **INTACT** (head `%s`)" % head)
    else:
        out("- Chain integrity: **BROKEN** — %s" % reason)
    out("")

    out("## Decisions")
    out("")
    out("| Decision | Count |")
    out("|---|---|")
    for dec in ("allow", "challenge", "deny"):
        out("| %s | %d |" % (dec, by_decision.get(dec, 0)))
    out("")
    if reasons:
        out("Top decision reasons:")
        out("")
        for tag, n in reasons.most_common(10):
            out("- `%s` × %d" % (tag, n))
        out("")

    out("## Authentication failures")
    out("")
    out("- Failures: %d, successes: %d" % (len(failures), len(successes)))
    out("")
    if fail_by_hour:
        out("Trend by hour (UTC):")
        out("")
        out("| Hour | Failures |")
        out("|---|---|")
        for hour in sorted(fail_by_hour):
            out("| %s | %d |" % (hour, fail_by_hour[hour]))
        out("")
    if fail_by_account:
        out("Most-targeted accounts:")
        out("")
        for acct, n in fail_by_account.most_common(10):
            out("- `%s` × %d" % (acct, n))
        out("")

    out("## Lockouts")
    out("")
    if lockouts:
        for acct, n in lockouts.most_common():
            out("- `%s`: %d lockout denial(s)" % (acct, n))
    else:
        out("No lockouts in this period.")
    out("")

    out("## Risky source IPs")
    out("")
    if risky_ips:
        out("| IP | Failures + denials |")
        out("|---|---|")
        for ip, n in risky_ips.most_common(10):
            out("| %s | %d |" % (ip, n))
    else:
        out("None observed.")
    out("")

    return "\n".join(lines), ok


def main(argv):
    allow_missing = "--allow-missing-anchors" in argv
    argv = [a for a in argv if a != "--allow-missing-anchors"]
    if len(argv) not in (2, 3):
        print(__doc__.strip(), file=sys.stderr)
        return 2
    try:
        records = verify_chain.load(argv[1])
        verdict = verify_chain.verify_export(argv[1], records, allow_missing)
    except (OSError, ValueError) as e:
        print("ERROR: %s" % e, file=sys.stderr)
        return 1
    report, ok = build_report(records, verdict)
    if len(argv) == 3:
        with open(argv[2], "w", encoding="utf-8") as f:
            f.write(report)
    else:
        print(report)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
