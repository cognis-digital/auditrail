"""Feature test suite for AUDITRAIL additive capabilities.

Covers the Merkle-tree membership layer (:mod:`auditrail.merkle`), the
descriptive-statistics and one-call ``scan`` APIs (:mod:`auditrail.core`), and
the new CLI subcommands (``stats`` / ``root`` / ``prove`` / ``verify-proof``).

Standard library only, fully offline. Every test asserts real behavior of the
integrity model — tamper detection, proof soundness, and CLI exit codes.
"""
import hashlib
import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from auditrail.core import (
    AuditEvent,
    build_chain,
    load_events,
    scan,
    summarize,
    to_json,
    _canonical_json,
)
from auditrail.merkle import (
    EMPTY_ROOT,
    InclusionProof,
    ProofError,
    ProofStep,
    inclusion_proof,
    leaf_hash,
    merkle_attest,
    merkle_levels,
    merkle_root,
    verify_inclusion,
)
from auditrail.cli import main

SAMPLE_EVENTS = [
    {"ts": "2026-06-08T09:00:00Z", "actor": "alice", "action": "login"},
    {"ts": "2026-06-08T09:01:00Z", "actor": "alice", "action": "read", "resource": "r1"},
    {"ts": "2026-06-08T09:02:00Z", "actor": "bob", "action": "delete", "resource": "r1"},
]
SAMPLE = json.dumps(SAMPLE_EVENTS)


def _events(n):
    return load_events(json.dumps(
        [{"ts": f"2026-01-01T00:00:{i:02d}Z", "actor": f"u{i % 3}", "action": f"a{i}"}
         for i in range(n)]
    ))


class TestLeafHash(unittest.TestCase):
    def test_leaf_is_sha256_hex(self):
        ev = load_events(SAMPLE)[0]
        h = leaf_hash(ev)
        self.assertEqual(len(h), 64)
        int(h, 16)

    def test_leaf_domain_separated_from_chain(self):
        # A Merkle leaf must not equal the plain canonical-json sha256 (would allow
        # confusing a leaf with a chain digest). The 0x00 prefix guarantees this.
        ev = load_events(SAMPLE)[0]
        plain = hashlib.sha256(_canonical_json(ev.canonical()).encode("utf-8")).hexdigest()
        self.assertNotEqual(leaf_hash(ev), plain)

    def test_leaf_deterministic(self):
        ev = load_events(SAMPLE)[0]
        self.assertEqual(leaf_hash(ev), leaf_hash(ev))

    def test_distinct_events_distinct_leaves(self):
        evs = load_events(SAMPLE)
        leaves = {leaf_hash(e) for e in evs}
        self.assertEqual(len(leaves), 3)


class TestMerkleRoot(unittest.TestCase):
    def test_empty_root_sentinel(self):
        self.assertEqual(merkle_root([]), EMPTY_ROOT)
        self.assertEqual(merkle_levels([]), [])

    def test_single_leaf_root_is_leaf(self):
        evs = _events(1)
        self.assertEqual(merkle_root(evs), leaf_hash(evs[0]))

    def test_root_is_sha256_hex(self):
        r = merkle_root(_events(5))
        self.assertEqual(len(r), 64)
        int(r, 16)

    def test_root_deterministic(self):
        self.assertEqual(merkle_root(_events(7)), merkle_root(_events(7)))

    def test_root_order_sensitive(self):
        evs = _events(4)
        reordered = [evs[1], evs[0], evs[2], evs[3]]
        self.assertNotEqual(merkle_root(evs), merkle_root(reordered))

    def test_root_content_sensitive(self):
        evs = _events(4)
        base = merkle_root(evs)
        evs2 = list(evs)
        evs2[2] = AuditEvent(ts=evs[2].ts, actor="tampered", action=evs[2].action, extra=evs[2].extra)
        self.assertNotEqual(merkle_root(evs2), base)

    def test_levels_shrink_to_root(self):
        levels = merkle_levels(_events(5))
        self.assertEqual(len(levels[0]), 5)
        self.assertEqual(len(levels[-1]), 1)
        # Each level at most ceil(prev/2)
        for lo, hi in zip(levels, levels[1:]):
            self.assertLessEqual(len(hi), (len(lo) + 1) // 2)

    def test_odd_promotion_stable(self):
        # 3 leaves: the last is promoted; root must still be reproducible.
        self.assertEqual(merkle_root(_events(3)), merkle_root(_events(3)))


class TestInclusionProof(unittest.TestCase):
    def test_proof_verifies_all_positions(self):
        for n in (1, 2, 3, 4, 5, 8, 9, 16, 17):
            evs = _events(n)
            root = merkle_root(evs)
            for i in range(n):
                proof = inclusion_proof(evs, i)
                self.assertTrue(verify_inclusion(proof, root),
                                f"proof failed for index {i} of {n}")

    def test_proof_leaf_matches(self):
        evs = _events(6)
        proof = inclusion_proof(evs, 4)
        self.assertEqual(proof.leaf, leaf_hash(evs[4]))
        self.assertEqual(proof.leaf_count, 6)

    def test_proof_path_length_logarithmic(self):
        evs = _events(16)
        proof = inclusion_proof(evs, 0)
        self.assertEqual(len(proof.path), 4)  # log2(16)

    def test_proof_out_of_range(self):
        evs = _events(3)
        with self.assertRaises(IndexError):
            inclusion_proof(evs, 3)
        with self.assertRaises(IndexError):
            inclusion_proof(evs, -1)

    def test_wrong_root_rejected(self):
        evs = _events(5)
        proof = inclusion_proof(evs, 2)
        self.assertFalse(verify_inclusion(proof, "f" * 64))

    def test_tampered_leaf_rejected(self):
        evs = _events(5)
        proof = inclusion_proof(evs, 2)
        bad = InclusionProof(index=proof.index, leaf="a" * 64, root=proof.root,
                             leaf_count=proof.leaf_count, path=proof.path)
        self.assertFalse(verify_inclusion(bad, proof.root))

    def test_tampered_sibling_rejected(self):
        evs = _events(5)
        proof = inclusion_proof(evs, 2)
        steps = list(proof.path)
        steps[0] = ProofStep(sibling="b" * 64, position=steps[0].position)
        bad = InclusionProof(index=proof.index, leaf=proof.leaf, root=proof.root,
                             leaf_count=proof.leaf_count, path=tuple(steps))
        self.assertFalse(verify_inclusion(bad, proof.root))

    def test_self_consistent_verify(self):
        # Without an explicit root, the proof checks against its own carried root.
        evs = _events(7)
        self.assertTrue(verify_inclusion(inclusion_proof(evs, 3)))

    def test_proof_for_one_index_does_not_verify_another(self):
        evs = _events(8)
        p2 = inclusion_proof(evs, 2)
        # Swap in leaf of index 5 but keep index-2 path -> must fail.
        forged = InclusionProof(index=2, leaf=leaf_hash(evs[5]), root=p2.root,
                                leaf_count=8, path=p2.path)
        self.assertFalse(verify_inclusion(forged, p2.root))


class TestProofSerialization(unittest.TestCase):
    def test_roundtrip(self):
        evs = _events(9)
        proof = inclusion_proof(evs, 6)
        d = proof.as_dict()
        restored = InclusionProof.from_dict(d)
        self.assertEqual(restored.index, proof.index)
        self.assertEqual(restored.leaf, proof.leaf)
        self.assertEqual(restored.root, proof.root)
        self.assertEqual([s.as_dict() for s in restored.path],
                         [s.as_dict() for s in proof.path])
        self.assertTrue(verify_inclusion(restored, proof.root))

    def test_json_roundtrip(self):
        evs = _events(5)
        proof = inclusion_proof(evs, 1)
        restored = InclusionProof.from_dict(json.loads(json.dumps(proof.as_dict())))
        self.assertTrue(verify_inclusion(restored))

    def test_as_dict_kind(self):
        d = inclusion_proof(_events(3), 0).as_dict()
        self.assertEqual(d["kind"], "auditrail-merkle-inclusion")

    def test_from_dict_missing_field(self):
        with self.assertRaises(ProofError):
            InclusionProof.from_dict({"index": 0, "leaf": "a" * 64})

    def test_from_dict_not_object(self):
        with self.assertRaises(ProofError):
            InclusionProof.from_dict(["not", "a", "dict"])

    def test_step_bad_position(self):
        with self.assertRaises(ProofError):
            ProofStep.from_dict({"sibling": "a" * 64, "position": "X"})

    def test_step_bad_sibling_length(self):
        with self.assertRaises(ProofError):
            ProofStep.from_dict({"sibling": "abc", "position": "L"})


class TestMerkleAttest(unittest.TestCase):
    def test_manifest_fields(self):
        m = merkle_attest(_events(4), source="s.jsonl")
        self.assertEqual(m["kind"], "auditrail-merkle-attestation")
        self.assertEqual(m["leaf_count"], 4)
        self.assertEqual(m["root"], merkle_root(_events(4)))
        self.assertEqual(m["source"], "s.jsonl")

    def test_empty_manifest(self):
        m = merkle_attest([])
        self.assertEqual(m["leaf_count"], 0)
        self.assertEqual(m["root"], EMPTY_ROOT)


class TestSummarize(unittest.TestCase):
    def setUp(self):
        self.chain = build_chain(load_events(SAMPLE))
        self.s = summarize(self.chain)

    def test_counts(self):
        self.assertEqual(self.s["event_count"], 3)
        self.assertEqual(self.s["distinct_actors"], 2)
        self.assertEqual(self.s["distinct_actions"], 3)

    def test_actor_tally(self):
        self.assertEqual(self.s["actors"]["alice"], 2)
        self.assertEqual(self.s["actors"]["bob"], 1)

    def test_actors_sorted_by_count_desc(self):
        counts = list(self.s["actors"].values())
        self.assertEqual(counts, sorted(counts, reverse=True))

    def test_time_span(self):
        self.assertEqual(self.s["first_ts"], "2026-06-08T09:00:00Z")
        self.assertEqual(self.s["last_ts"], "2026-06-08T09:02:00Z")

    def test_head_included(self):
        self.assertEqual(self.s["head"], self.chain.head)

    def test_empty_chain(self):
        s = summarize(build_chain([]))
        self.assertEqual(s["event_count"], 0)
        self.assertIsNone(s["first_ts"])
        self.assertEqual(s["actors"], {})


class TestScanAPI(unittest.TestCase):
    def test_scan_inline_json(self):
        report = scan(SAMPLE)
        self.assertTrue(report["intact"])
        self.assertEqual(report["event_count"], 3)
        self.assertEqual(report["source"], "<inline>")
        self.assertEqual(report["breaks"], [])

    def test_scan_file(self):
        fd, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(SAMPLE)
        self.addCleanup(lambda: os.remove(path))
        report = scan(path)
        self.assertEqual(report["source"], path)
        self.assertTrue(report["intact"])

    def test_to_json_roundtrip(self):
        report = scan(SAMPLE)
        restored = json.loads(to_json(report))
        self.assertEqual(restored["head"], report["head"])

    def test_scan_reports_breaks_key(self):
        self.assertIn("breaks", scan(SAMPLE))


class _CLIBase(unittest.TestCase):
    def _write(self, body, suffix=".json"):
        fd, path = tempfile.mkstemp(suffix=suffix)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(body)
        self.addCleanup(lambda: os.path.exists(path) and os.remove(path))
        return path

    def _run(self, argv, stdin=None):
        buf, err = io.StringIO(), io.StringIO()
        old = sys.stdin
        if stdin is not None:
            sys.stdin = io.StringIO(stdin)
        try:
            with redirect_stdout(buf), redirect_stderr(err):
                code = main(argv)
        finally:
            sys.stdin = old
        return code, buf.getvalue(), err.getvalue()


class TestCLIStats(_CLIBase):
    def test_stats_json(self):
        path = self._write(SAMPLE)
        code, out, _ = self._run(["--format", "json", "stats", path])
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertEqual(data["event_count"], 3)
        self.assertEqual(data["actors"]["alice"], 2)

    def test_stats_table(self):
        path = self._write(SAMPLE)
        code, out, _ = self._run(["stats", path])
        self.assertEqual(code, 0)
        self.assertIn("distinct_actors=2", out)
        self.assertIn("alice", out)


class TestCLIRoot(_CLIBase):
    def test_root_json(self):
        path = self._write(SAMPLE)
        code, out, _ = self._run(["--format", "json", "root", path])
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertEqual(data["root"], merkle_root(load_events(SAMPLE)))
        self.assertEqual(data["leaf_count"], 3)

    def test_root_table(self):
        path = self._write(SAMPLE)
        code, out, _ = self._run(["root", path])
        self.assertIn("root", out)


class TestCLIProve(_CLIBase):
    def test_prove_then_verify_proof_json(self):
        path = self._write(SAMPLE)
        code, out, _ = self._run(["--format", "json", "prove", path, "--index", "1"])
        self.assertEqual(code, 0)
        proof = json.loads(out)
        self.assertEqual(proof["index"], 1)
        self.assertEqual(proof["kind"], "auditrail-merkle-inclusion")
        # Feed the proof back into verify-proof via stdin.
        code2, out2, _ = self._run(["--format", "json", "verify-proof", "-"], stdin=json.dumps(proof))
        self.assertEqual(code2, 0)
        self.assertTrue(json.loads(out2)["verified"])

    def test_prove_out_of_range_exit1(self):
        path = self._write(SAMPLE)
        code, _, err = self._run(["prove", path, "--index", "9"])
        self.assertEqual(code, 1)
        self.assertIn("error", err)

    def test_prove_table(self):
        path = self._write(SAMPLE)
        code, out, _ = self._run(["prove", path, "--index", "0"])
        self.assertEqual(code, 0)
        self.assertIn("leaf", out)
        self.assertIn("root", out)


class TestCLIVerifyProof(_CLIBase):
    def _make_proof(self, index=1):
        proof = inclusion_proof(load_events(SAMPLE), index)
        return proof

    def test_valid_proof_exit0(self):
        proof = self._make_proof()
        path = self._write(json.dumps(proof.as_dict()))
        code, out, _ = self._run(["verify-proof", path])
        self.assertEqual(code, 0)
        self.assertIn("VALID", out)

    def test_tampered_proof_exit2(self):
        proof = self._make_proof()
        d = proof.as_dict()
        d["leaf"] = "a" * 64  # forge the leaf
        path = self._write(json.dumps(d))
        code, out, _ = self._run(["verify-proof", path])
        self.assertEqual(code, 2)
        self.assertIn("INVALID", out)

    def test_wrong_root_flag_exit2(self):
        proof = self._make_proof()
        path = self._write(json.dumps(proof.as_dict()))
        code, _, _ = self._run(["verify-proof", path, "--root", "f" * 64])
        self.assertEqual(code, 2)

    def test_malformed_proof_exit1(self):
        path = self._write('{"index": 0}')
        code, _, err = self._run(["verify-proof", path])
        self.assertEqual(code, 1)
        self.assertIn("error", err)

    def test_invalid_json_exit1(self):
        path = self._write("{not json")
        code, _, _ = self._run(["verify-proof", path])
        self.assertEqual(code, 1)


class TestCLIBackwardCompat(_CLIBase):
    """Existing subcommands keep their exact contract after the additions."""

    REFERENCE_HEAD = "8ae3d48a5736f485bd64d7d812d5255a5548962684e79a85d05bbbfac1ea94d3"

    def test_chain_head_unchanged(self):
        path = self._write(SAMPLE)
        code, out, _ = self._run(["--format", "json", "chain", path])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["head"], self.REFERENCE_HEAD)

    def test_verify_still_exit0(self):
        path = self._write(SAMPLE)
        self.assertEqual(self._run(["verify", path])[0], 0)

    def test_attest_still_exit0(self):
        path = self._write(SAMPLE)
        self.assertEqual(self._run(["--format", "json", "attest", path])[0], 0)


if __name__ == "__main__":
    unittest.main()
