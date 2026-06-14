"""Smoke tests for AUDITRAIL. Standard library only, no network."""
import io
import json
import os
import sys
import tempfile
import unittest
import unittest.mock as mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from auditrail import TOOL_NAME, TOOL_VERSION
from auditrail.core import (
    GENESIS,
    AuditEvent,
    attest,
    build_chain,
    load_events,
    load_events_from_path,
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


class TestHardening(unittest.TestCase):
    """Tests covering error paths and edge cases added during hardening."""

    def _write(self, body: str) -> str:
        fd, path = tempfile.mkstemp(suffix=".jsonl")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(body)
        self.addCleanup(lambda: os.remove(path))
        return path

    # --- core: _parse_records / load_events ---

    def test_malformed_json_array_raises_value_error(self):
        """A JSON array that is syntactically broken must raise ValueError, not JSONDecodeError."""
        with self.assertRaises(ValueError) as ctx:
            load_events("[{broken json")
        self.assertIn("malformed JSON array", str(ctx.exception))

    def test_empty_input_returns_empty_chain(self):
        """Empty input (whitespace-only) produces a zero-length chain with head == GENESIS."""
        events = load_events("   ")
        chain = build_chain(events)
        self.assertEqual(len(chain), 0)
        self.assertEqual(chain.head, GENESIS)

    def test_non_dict_array_element_rejected(self):
        """Array elements that are not objects must be rejected with a clear message."""
        with self.assertRaises(ValueError) as ctx:
            load_events("[1, 2, 3]")
        self.assertIn("event 0 is not an object", str(ctx.exception))

    def test_null_required_field_rejected(self):
        """An event with null ts must be rejected (None is treated as missing)."""
        with self.assertRaises(ValueError) as ctx:
            load_events('[{"ts": null, "actor": "a", "action": "x"}]')
        self.assertIn("ts", str(ctx.exception))

    def test_empty_string_required_field_rejected(self):
        """An event with an empty-string actor must be rejected."""
        with self.assertRaises(ValueError) as ctx:
            load_events('[{"ts": "t", "actor": "", "action": "x"}]')
        self.assertIn("actor", str(ctx.exception))

    def test_load_events_from_path_missing_file(self):
        """load_events_from_path raises FileNotFoundError for a non-existent path."""
        with self.assertRaises(FileNotFoundError):
            load_events_from_path("/no/such/path_auditrail_test.jsonl")

    def test_attest_empty_chain(self):
        """attest() on an empty chain must not raise and must report 0 events."""
        chain = build_chain([])
        m = attest(chain, source="<test>")
        self.assertEqual(m["event_count"], 0)
        self.assertIsNone(m["first_ts"])
        self.assertIsNone(m["last_ts"])
        self.assertTrue(m["intact"])
        self.assertEqual(m["distinct_actors"], [])

    # --- cli: I/O error paths ---

    def test_cli_oserror_on_stdin_returns_exit1(self):
        """An OSError reading stdin must print to stderr and return exit code 1."""
        bad_stdin = mock.MagicMock()
        bad_stdin.read.side_effect = OSError("broken pipe")
        with mock.patch("sys.stdin", bad_stdin):
            result = main(["chain", "-"])
        self.assertEqual(result, 1)

    def test_cli_empty_stdin_chain_exits0(self):
        """Empty stdin is valid (zero events); chain subcommand must exit 0."""
        with mock.patch("sys.stdin", io.StringIO("")):
            result = main(["--format", "json", "chain", "-"])
        self.assertEqual(result, 0)

    def test_cli_malformed_json_file_exits1(self):
        """A file containing malformed JSON must produce exit code 1, not a traceback."""
        path = self._write("[{invalid json here")
        result = main(["verify", path])
        self.assertEqual(result, 1)

    def test_mcp_server_imports_cleanly(self):
        """mcp_server module must import without error (no missing symbols)."""
        import importlib
        import auditrail.mcp_server  # noqa: F401
        mod = importlib.import_module("auditrail.mcp_server")
        self.assertTrue(callable(getattr(mod, "serve", None)))


if __name__ == "__main__":
    unittest.main()
