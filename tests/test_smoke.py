"""Smoke tests for AUDITRAIL. Standard library only, no network."""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from auditrail import TOOL_NAME, TOOL_VERSION
from auditrail.core import (
    GENESIS,
    AuditEvent,
    attest,
    build_chain,
    load_events,
    verify_chain,
)
from auditrail.cli import main

SAMPLE = json.dumps(
    [
        {"ts": "2026-06-08T09:00:00Z", "actor": "alice", "action": "login"},
        {"ts": "2026-06-08T09:01:00Z", "actor": "alice", "action": "read", "resource": "r1"},
        {"ts": "2026-06-08T09:02:00Z", "actor": "bob", "action": "delete", "resource": "r1"},
    ]
)


class TestCore(unittest.TestCase):
    def test_meta(self):
        self.assertEqual(TOOL_NAME, "auditrail")
        self.assertTrue(TOOL_VERSION)

    def test_build_and_verify_intact(self):
        events = load_events(SAMPLE)
        chain = build_chain(events)
        self.assertEqual(len(chain), 3)
        self.assertEqual(chain.links[0].prev, GENESIS)
        self.assertEqual(verify_chain(chain), [])
        self.assertNotEqual(chain.head, GENESIS)

    def test_deterministic_head(self):
        h1 = build_chain(load_events(SAMPLE)).head
        h2 = build_chain(load_events(SAMPLE)).head
        self.assertEqual(h1, h2)

    def test_tamper_detected(self):
        events = load_events(SAMPLE)
        chain = build_chain(events)
        # Tamper: rewrite a middle event's actor, keep the original digests.
        links = list(chain.links)
        bad_event = AuditEvent(ts=events[1].ts, actor="mallory", action=events[1].action,
                               extra=events[1].extra)
        links[1] = type(links[1])(index=1, prev=links[1].prev,
                                  digest=links[1].digest, event=bad_event)
        tampered = type(chain)(links=tuple(links))
        breaks = verify_chain(tampered)
        self.assertTrue(breaks)
        self.assertEqual(breaks[0]["index"], 1)

    def test_jsonl_parsing(self):
        jsonl = "\n".join(json.dumps(json.loads(x)) for x in [
            '{"ts":"t1","actor":"a","action":"x"}',
            '{"ts":"t2","actor":"b","action":"y"}',
        ])
        events = load_events(jsonl)
        self.assertEqual(len(events), 2)

    def test_missing_field_rejected(self):
        with self.assertRaises(ValueError):
            load_events('[{"actor": "a", "action": "x"}]')

    def test_attest_manifest(self):
        chain = build_chain(load_events(SAMPLE))
        m = attest(chain, source="sample")
        self.assertTrue(m["intact"])
        self.assertEqual(m["event_count"], 3)
        self.assertEqual(m["head"], chain.head)
        self.assertIn("manifest_digest", m)
        self.assertEqual(sorted(m["distinct_actors"]), ["alice", "bob"])


class TestCLI(unittest.TestCase):
    def _write(self, body):
        import tempfile
        fd, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(body)
        self.addCleanup(lambda: os.remove(path))
        return path

    def test_chain_ok(self):
        path = self._write(SAMPLE)
        self.assertEqual(main(["--format", "json", "chain", path]), 0)

    def test_verify_ok(self):
        path = self._write(SAMPLE)
        self.assertEqual(main(["verify", path]), 0)

    def test_attest_ok(self):
        path = self._write(SAMPLE)
        self.assertEqual(main(["--format", "json", "attest", path]), 0)

    def test_bad_input_exit1(self):
        path = self._write('[{"actor":"a"}]')
        self.assertEqual(main(["verify", path]), 1)

    def test_missing_file_exit1(self):
        self.assertEqual(main(["verify", "/no/such/file_auditrail.json"]), 1)


if __name__ == "__main__":
    unittest.main()
