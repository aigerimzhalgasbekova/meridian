#!/usr/bin/env python3
"""Standalone verifier for sentinel's hash-chained audit log (JSONL export).

Reimplements the chain rules of sentinel/audit in pure stdlib Python, so an
auditor needs neither Go nor sentinel itself to check log integrity —
cross-language verification is the point.

Chain rules (must match sentinel/audit/audit.go exactly):
  hash = hex(sha256(prev_hash_hex_bytes || canonical_json_bytes))
where canonical JSON is compact, keys sorted, fields
(action, actor, details, prev, seq, ts, type), string escaping identical to
Go's encoding/json with HTML escaping disabled.

Usage: verify_chain.py <audit.jsonl>
Exit status: 0 chain intact, 1 broken or unreadable.
"""
import hashlib
import json
import sys

GENESIS = "0" * 64

# Go's encoding/json (SetEscapeHTML(false)) escapes: " \ \n \r \t as
# two-char sequences, other control chars as \u00xx (lowercase hex), and
# U+2028/U+2029. Everything else — including non-ASCII — is raw UTF-8.
_TWO_CHAR = {'"': '\\"', "\\": "\\\\", "\n": "\\n", "\r": "\\r", "\t": "\\t"}


def _jstr(s):
    out = ['"']
    for ch in s:
        if ch in _TWO_CHAR:
            out.append(_TWO_CHAR[ch])
        elif ord(ch) < 0x20 or ch in "\u2028\u2029":
            out.append("\\u%04x" % ord(ch))
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def canonical(rec):
    """Canonical JSON bytes of a record, hash field excluded."""
    d = rec.get("details") or {}
    details = "{" + ",".join(
        "%s:%s" % (_jstr(k), _jstr(d[k])) for k in sorted(d)
    ) + "}"
    body = ",".join([
        '"action":' + _jstr(rec.get("action", "")),
        '"actor":' + _jstr(rec.get("actor", "")),
        '"details":' + details,
        '"prev":' + _jstr(rec["prev"]),
        '"seq":%d' % int(rec["seq"]),
        '"ts":' + _jstr(rec["ts"]),
        '"type":' + _jstr(rec.get("type", "")),
    ])
    return ("{" + body + "}").encode("utf-8")


def record_hash(rec):
    h = hashlib.sha256()
    h.update(rec["prev"].encode("ascii"))
    h.update(canonical(rec))
    return h.hexdigest()


def load(path):
    records = []
    with open(path, encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as e:
                raise ValueError("%s line %d: %s" % (path, lineno, e))
    return records


def verify(records):
    """Return (ok, broken_seq, reason) for the first broken link."""
    prev_hash = GENESIS
    prev_seq = None
    for i, rec in enumerate(records):
        seq = int(rec["seq"])
        if prev_seq is None:
            prev_seq = seq - 1
        if seq != prev_seq + 1:
            return False, seq, "sequence gap: expected %d, got %d" % (prev_seq + 1, seq)
        if rec["prev"] != prev_hash:
            return False, seq, "prev does not match previous record hash"
        if record_hash(rec) != rec["hash"]:
            return False, seq, "stored hash does not match recomputation"
        prev_seq, prev_hash = seq, rec["hash"]
    return True, None, None


def main(argv):
    if len(argv) != 2:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    try:
        records = load(argv[1])
    except (OSError, ValueError) as e:
        print("ERROR: %s" % e, file=sys.stderr)
        return 1
    ok, seq, reason = verify(records)
    if ok:
        print("OK: chain of %d records intact (head %s)"
              % (len(records), records[-1]["hash"][:16] + "..." if records else "empty"))
        return 0
    print("BROKEN at seq %s: %s" % (seq, reason))
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
