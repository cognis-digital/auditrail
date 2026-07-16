"""Command-line interface for AUDITRAIL.

Subcommands:
  chain         Build the hash chain and print every link.
  verify        Recompute the chain and report tamper breaks (exit 2 if broken).
  attest        Emit a compliance attestation manifest.
  stats         Summarize actors, actions, and time span of the events.
  root          Emit the Merkle root (membership-witness fingerprint).
  prove         Emit an O(log n) inclusion proof for one event index.
  verify-proof  Verify an inclusion proof against its root (exit 2 if invalid).
  mcp           Start the MCP stdio server (requires the 'mcp' extra).

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
    summarize,
    verify_chain,
)
from auditrail.merkle import (
    InclusionProof,
    ProofError,
    inclusion_proof,
    merkle_attest,
    verify_inclusion,
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


def _read_raw(path: str | None) -> tuple[str, str]:
    """Read raw text (no event validation) for proof inputs."""
    if path in (None, "-"):
        return sys.stdin.read(), "<stdin>"
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read(), path


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
    elif isinstance(obj, dict) and "actors" in obj and "actions" in obj:  # stats
        print(f"events={obj['event_count']}  distinct_actors={obj['distinct_actors']}  "
              f"distinct_actions={obj['distinct_actions']}")
        print(f"span: {obj['first_ts']} -> {obj['last_ts']}")
        print("top actors:")
        for actor, n in list(obj["actors"].items())[:10]:
            print(f"  {n:>6}  {actor}")
        print("top actions:")
        for action, n in list(obj["actions"].items())[:10]:
            print(f"  {n:>6}  {action}")
        print(f"\nhead = {obj['head']}")
    elif isinstance(obj, dict) and obj.get("kind") == "auditrail-merkle-attestation":
        print(f"leaf_count = {obj['leaf_count']}")
        print(f"root       = {obj['root']}")
    elif isinstance(obj, dict) and obj.get("kind") == "auditrail-merkle-inclusion":
        print(f"index      = {obj['index']}  (of {obj['leaf_count']} leaves)")
        print(f"leaf       = {obj['leaf']}")
        print(f"root       = {obj['root']}")
        print(f"path ({len(obj['path'])} step(s)):")
        for step in obj["path"]:
            print(f"  {step['position']}  {step['sibling']}")
    elif isinstance(obj, dict) and "verified" in obj and "root" in obj:  # verify-proof
        status = "VALID" if obj["verified"] else "INVALID"
        print(f"proof status: {status}   index={obj.get('index')}   root={obj['root']}")
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
        ("stats", "summarize actors, actions, and time span"),
        ("root", "emit the Merkle root over the events"),
    ):
        sp = sub.add_parser(name, help=help_)
        sp.add_argument("input", nargs="?", default="-", help="events file path, or '-' for stdin")

    prove = sub.add_parser("prove", help="emit an inclusion proof for one event index")
    prove.add_argument("input", nargs="?", default="-", help="events file path, or '-' for stdin")
    prove.add_argument("--index", type=int, required=True, help="0-based event index to prove")

    vp = sub.add_parser("verify-proof", help="verify an inclusion proof (exit 2 if invalid)")
    vp.add_argument("input", nargs="?", default="-", help="proof JSON file, or '-' for stdin")
    vp.add_argument("--root", default=None, help="expected root (overrides the proof's own root)")

    sub.add_parser("mcp", help="start the MCP stdio server (requires the 'mcp' extra)")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _build_args(argv)

    # Commands that do not consume an event stream are handled up front.
    if args.cmd == "mcp":
        from auditrail.mcp_server import serve
        return serve()

    if args.cmd == "verify-proof":
        try:
            text, _ = _read_raw(args.input)
            raw = json.loads(text)
            proof = InclusionProof.from_dict(raw)
            ok = verify_inclusion(proof, root=args.root)
        except (ValueError, FileNotFoundError, json.JSONDecodeError, ProofError) as e:
            print(f"error: {e}", file=sys.stderr)
            return 1
        out = {
            "verified": bool(ok),
            "index": proof.index,
            "root": args.root or proof.root,
            "leaf": proof.leaf,
            "leaf_count": proof.leaf_count,
        }
        _emit(out, args.format)
        return 0 if ok else 2

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

    if args.cmd == "stats":
        _emit(summarize(chain), args.format)
        return 0

    if args.cmd == "root":
        _emit(merkle_attest(events, source=source), args.format)
        return 0

    if args.cmd == "prove":
        try:
            proof = inclusion_proof(events, args.index)
        except IndexError as e:
            print(f"error: {e}", file=sys.stderr)
            return 1
        _emit(proof.as_dict(), args.format)
        return 0

    print("error: unknown command", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
