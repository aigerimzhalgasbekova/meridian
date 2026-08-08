"""Tests for verify_chain.py and report.py against the Go-generated fixture.

The fixture (testdata/sample_audit.jsonl) was produced by sentinel's Go audit
package with a fixed clock — verifying it here IS the cross-language proof
that the Python chain rules match the Go ones.
"""
import copy
import json
import os
import shutil
import tempfile
import unittest

import report
import verify_chain

FIXTURE = os.path.join(os.path.dirname(__file__), "testdata", "sample_audit.jsonl")


class VerifyChainTest(unittest.TestCase):
    def setUp(self):
        self.records = verify_chain.load(FIXTURE)

    def test_go_generated_chain_verifies(self):
        ok, seq, reason = verify_chain.verify(self.records)
        self.assertTrue(ok, "fixture broken at %s: %s" % (seq, reason))
        self.assertGreater(len(self.records), 20)

    def test_hashes_recompute_exactly(self):
        # Every stored hash must equal the Python recomputation — this is the
        # byte-level canonical-JSON compatibility check.
        for rec in self.records:
            self.assertEqual(verify_chain.record_hash(rec), rec["hash"],
                             "hash mismatch at seq %s" % rec["seq"])

    def test_tampered_field_detected(self):
        recs = copy.deepcopy(self.records)
        recs[5]["actor"] = "eve"
        ok, seq, _ = verify_chain.verify(recs)
        self.assertFalse(ok)
        self.assertEqual(seq, recs[5]["seq"])

    def test_deleted_record_detected(self):
        recs = self.records[:5] + self.records[6:]
        ok, seq, reason = verify_chain.verify(recs)
        self.assertFalse(ok)
        self.assertIn("sequence gap", reason)

    def test_reordered_records_detected(self):
        recs = copy.deepcopy(self.records)
        recs[3], recs[4] = recs[4], recs[3]
        ok, _, _ = verify_chain.verify(recs)
        self.assertFalse(ok)

    def test_rewritten_suffix_detected(self):
        # Attacker rewrites a record AND recomputes its hash: the next
        # record's prev no longer matches.
        recs = copy.deepcopy(self.records)
        recs[5]["actor"] = "eve"
        recs[5]["hash"] = verify_chain.record_hash(recs[5])
        ok, seq, reason = verify_chain.verify(recs)
        self.assertFalse(ok)
        self.assertEqual(seq, recs[6]["seq"])
        self.assertIn("prev", reason)

    def test_empty_chain_is_ok(self):
        ok, _, _ = verify_chain.verify([])
        self.assertTrue(ok)

    def test_canonical_escaping_matches_go(self):
        # Go's encoder escapes control chars and leaves UTF-8 raw.
        rec = {"seq": 1, "ts": "t", "type": "x", "actor": "a\tb\"c\\d\né",
               "action": "", "details": {"k": "v"}, "prev": verify_chain.GENESIS}
        c = verify_chain.canonical(rec).decode("utf-8")
        self.assertIn('a\\tb\\"c\\\\d\\né', c)
        self.assertNotIn("\n", c)


class ReportTest(unittest.TestCase):
    def setUp(self):
        self.records = verify_chain.load(FIXTURE)

    def test_report_sections_and_counts(self):
        md, ok = report.build_report(self.records, (True, None, 0))
        self.assertTrue(ok)
        self.assertIn("Chain integrity: **INTACT**", md)
        for section in ("# Sentinel compliance report", "## Decisions",
                        "## Authentication failures", "## Lockouts",
                        "## Risky source IPs"):
            self.assertIn(section, md)
        # Fixture facts: bob locked out, 233.252.0.66 is the top risky IP,
        # carol got challenged for impossible travel.
        self.assertIn("`bob`", md)
        self.assertIn("233.252.0.66", md)
        self.assertIn("risk:impossible_travel", md)
        self.assertIn("locked_out:account", md)

    def test_report_flags_broken_chain(self):
        recs = copy.deepcopy(self.records)
        recs[2]["action"] = "tampered"
        md, ok = report.build_report(recs, verify_chain.verify_export(FIXTURE, recs))
        self.assertFalse(ok)
        self.assertIn("chain broken at seq", md)

    def test_report_on_empty_log(self):
        md, ok = report.build_report([], (True, None, 0))
        self.assertTrue(ok)
        self.assertIn("Records: **0**", md)

    def test_report_rejects_tail_truncated_log(self):
        # The report used to call verify() alone, so a truncated log — a valid
        # prefix of a valid chain — was pronounced INTACT with exit 0. Only the
        # sidecar sees the missing tail, so report.main must cross-check it.
        with tempfile.TemporaryDirectory() as tmp:
            log = os.path.join(tmp, "audit.jsonl")
            out = os.path.join(tmp, "report.md")
            shutil.copy(FIXTURE + ".anchors", log + ".anchors")
            with open(FIXTURE, encoding="utf-8") as src, \
                    open(log, "w", encoding="utf-8") as dst:
                dst.writelines(src.readlines()[:20])
            self.assertEqual(report.main(["report.py", log, out]), 1)
            with open(out, encoding="utf-8") as f:
                self.assertIn("Chain integrity: **BROKEN**", f.read())

    def test_report_accepts_the_intact_fixture(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "report.md")
            self.assertEqual(report.main(["report.py", FIXTURE, out]), 0)


class AnchorTest(unittest.TestCase):
    """The out-of-band anchor cross-check that gives truncation resistance."""

    def setUp(self):
        self.records = verify_chain.load(FIXTURE)

    def _anchor_for(self, rec):
        return {"head_seq": rec["seq"], "head_hash": rec["hash"], "ts": rec["ts"]}

    def test_matching_anchor_ok(self):
        anchors = [self._anchor_for(self.records[-1])]
        ok, reason, _ = verify_chain.check_anchors(self.records, anchors)
        self.assertTrue(ok, reason)

    def test_truncation_detected_by_anchor(self):
        # Anchor vouches for the current head; drop the tail below it.
        anchors = [self._anchor_for(self.records[-1])]
        truncated = self.records[:-3]
        ok, reason, _ = verify_chain.check_anchors(truncated, anchors)
        self.assertFalse(ok)
        self.assertIn("truncated", reason)

    def test_unvouched_tail_is_reported(self):
        # Only the LAST anchor is cross-checked, so records past it are a blind
        # spot: an attacker can delete them and append fabricated ones, and the
        # verifier still says OK. The size of that window must be reported
        # rather than swallowed.
        anchors = [self._anchor_for(self.records[-4])]
        ok, reason, unvouched = verify_chain.check_anchors(self.records, anchors)
        self.assertTrue(ok, reason)
        self.assertEqual(unvouched, 3)

    def test_empty_anchors_fails_closed(self):
        # An emptied sidecar is indistinguishable from an attacker deleting the
        # evidence, so it must not verify as intact.
        ok, reason, _ = verify_chain.check_anchors(self.records, [])
        self.assertFalse(ok)
        self.assertIn("empty", reason)


if __name__ == "__main__":
    unittest.main()
