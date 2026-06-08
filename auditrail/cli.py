"""Command-line interface for AUDITRAIL.

Subcommands:
  chain    Build the hash chain and print every link.
  verify   Recompute the chain and report tamper breaks (exit 2 if broken).
  attest   Emit a compliance attestation manifest.

Input may be a file path or '-' / omitted for stdin. Accepts a JSON array of
events or newline-delimited JSON (JSONL). Each event needs ts/actor/action.
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from auditrail import TOOL_NAME, TOOL_VERSION
from auditrail.core import (
    attest,
    build_chain,
    load_events,
    load_events_from_path,
    verify_chain,
)


def _read_input(path: str | None) -> tuple[str, str]:
    """Return (text, source-label)."""
    if path in (None, "-"):
        return sys.stdin.read(), "<stdin>"
    return _read_file(path), path


def _read_file(path: str) -> str:
    events = load_events_from_path(path)  # validates existence + parse early
    # Re-serialize is wasteful; instead just read raw again is unnecessary.
    # load_events_from_path already returns events, but cli needs raw text path
    # handling kept simple: return canonical reconstruction.
    return json.dumps([e.canonical() for e in events])


def _emit(obj: Any, fmt: str) -> None:
    if fmt == "json":
        print(json.dumps(obj, indent=2, sort_keys=False))
        return
    _emit_table(obj)


def _emit_table(obj: Any) -> None:
    if isinstance(obj, dict) and "links" in obj:
        print(f"{'IDX':>3}  {'DIGEST (sha256, head 12)':<26}  {'TS':<20}  ACTOR / ACTION")
        print("-" * 78)
        for lk in obj["links"]:
            print(
                f"{lk['index']:>3}  {lk['digest'][:24]:<26}  {lk['ts']:<20}  "
                f"{lk['actor']} / {lk['action']}"
            )
        print(f"\nhead = {obj['head']}")
    elif isinstance(obj, dict) and "intact" in obj and "breaks" in obj:
        status = "INTACT" if obj["intact"] else f"BROKEN ({obj['break_count']} break(s))"
        print(f"chain status: {status}   events={obj['event_count']}")
        for b in obj["breaks"]:
            print(f"  ! index {b['index']}: {b['reason']} (action={b.get('action')})")
    elif isinstance(obj, dict):  # attestation manifest
        for k, v in obj.items():
            if isinstance(v, list):
                v = ", ".join(str(x) for x in v)
            print(f"{k:>16}: {v}")
    else:
        print(json.dumps(obj, indent=2))


def _build_args(argv: list[str] | None) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog=TOOL_NAME, description="Tamper-evident audit-log aggregator.")
    p.add_argument("--version", action="version", version=f"{TOOL_NAME} {TOOL_VERSION}")
    p.add_argument("--format", choices=("table", "json"), default="table", help="output format")
    sub = p.add_subparsers(dest="cmd", required=True)
    for name, help_ in (
        ("chain", "build and print the hash chain"),
        ("verify", "verify chain integrity, exit 2 on tamper"),
        ("attest", "emit a compliance attestation manifest"),
    ):
        sp = sub.add_parser(name, help=help_)
        sp.add_argument("input", nargs="?", default="-", help="events file path, or '-' for stdin")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _build_args(argv)
    try:
        text, source = _read_input(args.input)
        events = load_events(text)
    except (ValueError, FileNotFoundError, json.JSONDecodeError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    chain = build_chain(events)

    if args.cmd == "chain":
        out = {
            "head": chain.head,
            "event_count": len(chain),
            "links": [
                {
                    "index": lk.index,
                    "prev": lk.prev,
                    "digest": lk.digest,
                    "ts": lk.event.ts,
                    "actor": lk.event.actor,
                    "action": lk.event.action,
                }
                for lk in chain.links
            ],
        }
        _emit(out, args.format)
        return 0

    if args.cmd == "verify":
        breaks = verify_chain(chain)
        out = {
            "intact": not breaks,
            "event_count": len(chain),
            "break_count": len(breaks),
            "head": chain.head,
            "breaks": breaks,
        }
        _emit(out, args.format)
        return 0 if not breaks else 2

    if args.cmd == "attest":
        manifest = attest(chain, source=source)
        _emit(manifest, args.format)
        return 0 if manifest["intact"] else 2

    print("error: unknown command", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
