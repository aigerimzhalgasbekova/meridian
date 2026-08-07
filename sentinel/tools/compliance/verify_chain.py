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

Usage: verify_chain.py <audit.jsonl> [--allow-missing-anchors]
Expects the out-of-band anchor sidecar <audit.jsonl>.anchors beside the log;
its absence fails closed. Exit status: 0 chain intact, 1 broken or unreadable.
"""
import hashlib
import json
import os
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


def check_anchors(records, anchors):
    """Cross-check the chain head against the last out-of-band anchor.

    Anchors live in a separate append-only sidecar, so tail-truncating the
    main log cannot also delete them. If the last anchor vouches for a
    (seq, hash) the truncated log no longer contains, the loss is detected.
    Returns (ok, reason).
    """
    if not records and not anchors:
        return True, None  # nothing logged yet, so nothing to vouch for
    if not anchors:
        return False, "anchor sidecar is empty (deleted or truncated?)"
    last = anchors[-1]
    head_seq = int(last["head_seq"])
    head_hash = last["head_hash"]
    by_seq = {int(r["seq"]): r for r in records}
    rec = by_seq.get(head_seq)
    if rec is None:
        return False, "anchor vouches for seq %d, absent from log (truncated?)" % head_seq
    if rec["hash"] != head_hash:
        return False, "anchor hash mismatch at seq %d" % head_seq
    return True, None


def verify_export(path, records, allow_missing_anchors=False):
    """Verify a whole export: the chain walk *and* the anchor cross-check.

    Both halves are required. A prefix of a valid chain is itself a valid
    chain, so the walk alone cannot see tail-truncation — only the sidecar
    can. Every entry point that pronounces on a log's integrity must call
    this, never verify() on its own.

    Raises OSError/ValueError if the sidecar is unreadable. Returns
    (ok, reason).
    """
    ok, seq, reason = verify(records)
    if not ok:
        return False, "chain broken at seq %s: %s" % (seq, reason)
    # The sidecar's absence fails closed: deleting it would otherwise restore
    # the very blind spot it exists to remove.
    anchor_path = path + ".anchors"
    if not os.path.exists(anchor_path):
        if allow_missing_anchors:
            return True, None
        return False, ("anchor sidecar %s missing (deleted?); pass "
                       "--allow-missing-anchors only for pre-sidecar logs"
                       % anchor_path)
    return check_anchors(records, load(anchor_path))


def main(argv):
    # --allow-missing-anchors exists only for logs written before the sidecar
    # was introduced. Never pass it when verifying a live audit log: a missing
    # sidecar is indistinguishable from an attacker deleting the evidence.
    allow_missing = "--allow-missing-anchors" in argv
    argv = [a for a in argv if a != "--allow-missing-anchors"]
    if len(argv) != 2:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    try:
        records = load(argv[1])
        ok, reason = verify_export(argv[1], records, allow_missing)
    except (OSError, ValueError) as e:
        print("ERROR: %s" % e, file=sys.stderr)
        return 1
    if not ok:
        print("BROKEN: %s" % reason)
        return 1
    print("OK: chain of %d records intact (head %s)"
          % (len(records), records[-1]["hash"][:16] + "..." if records else "empty"))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
