# AUDITRAIL — Usage guide

`auditrail` reads audit-log events and proves they were not altered after the
fact. This guide covers every subcommand, input format, exit code, and the
Python API. All processing is local and offline — no network calls.

## Input

Every command that consumes events accepts a **file path** or `-` / nothing for
**stdin**. Two wire formats are supported and are interchangeable (they produce
the identical head/root):

- **JSON array** — `[{...}, {...}]`
- **JSONL / NDJSON** — one JSON object per line (blank lines ignored)

Each event must carry the compliance core triple:

| Field    | Meaning        | Required |
|----------|----------------|----------|
| `ts`     | when (timestamp string) | yes |
| `actor`  | who            | yes |
| `action` | what           | yes |
| *any other key* | folded into the hashed payload (e.g. `resource`, `ip`, `result`) | no |

Extra keys can **never** shadow the core triple — an attacker-supplied `actor`
inside the extras is ignored in favor of the real one.

## Subcommands

### `chain` — build and print the hash chain

```console
$ auditrail chain events.jsonl
IDX  DIGEST (sha256, head 12)    TS                    ACTOR / ACTION
------------------------------------------------------------------------------
  0  6ef71dd9f4ea34cc6673fbe8    2026-06-08T09:00:00Z  alice / login
  1  1a98deef3d33d1adeaeda0fd    2026-06-08T09:01:00Z  alice / read
  2  8ae3d48a5736f485bd64d7d8    2026-06-08T09:02:00Z  bob / delete

head = 8ae3d48a5736f485bd64d7d812d5255a5548962684e79a85d05bbbfac1ea94d3
```

### `verify` — recompute the chain and report tamper

Exit `0` if intact, **`2` if tampered**, `1` on bad input. Designed for CI gates
and cron checks.

```console
$ auditrail verify tampered.jsonl
chain status: BROKEN (1 break(s))   events=3
  ! index 1: digest mismatch (content altered) (action=read)
```

### `attest` — emit a retainable attestation manifest

```console
$ auditrail attest events.jsonl --format json > attestation.json
```

Retain the `head` (and optional `manifest_digest`). Recompute later — if the
head still matches, the log is provably unchanged.

### `stats` — summarize the log *(new)*

Descriptive statistics over the events: per-actor and per-action tallies, distinct
counts, and time span. Reads the same events; performs no I/O beyond input.

```console
$ auditrail stats events.jsonl
events=3  distinct_actors=2  distinct_actions=3
span: 2026-06-08T09:00:00Z -> 2026-06-08T09:02:00Z
top actors:
       2  alice
       1  bob
...
```

### `root` — emit the Merkle root *(new)*

An alternative tamper-evident fingerprint computed as a binary Merkle tree over
the same canonical events (see [ARCHITECTURE.md](ARCHITECTURE.md)).

```console
$ auditrail root events.jsonl --format json
{ "kind": "auditrail-merkle-attestation", "leaf_count": 3, "root": "861671e8…", ... }
```

### `prove` — inclusion proof for one event *(new)*

Produces a compact O(log n) **audit path** proving that a single event is a leaf
of the tree committed to by `root` — without revealing the other events.

```console
$ auditrail prove events.jsonl --index 1 --format json > proof.json
```

### `verify-proof` — check an inclusion proof *(new)*

Recomputes the root from the proof's leaf + path. Exit `0` if valid, **`2` if it
fails to reproduce the root**, `1` on malformed input. Pass `--root` to pin an
expected root explicitly.

```console
$ auditrail verify-proof proof.json
proof status: VALID   index=1   root=861671e8…

$ auditrail prove events.jsonl --index 1 --format json | auditrail verify-proof -
```

### `mcp` — start the MCP stdio server *(new wiring)*

Exposes the one-call `scan` as an MCP tool. Requires the optional extra:
`pip install "cognis-auditrail[mcp]"`.

## Exit codes

| Code | Meaning |
|------|---------|
| `0`  | success / intact / valid proof |
| `1`  | bad input (missing file, invalid JSON, missing required field, malformed proof) |
| `2`  | integrity failure (`verify` tampered chain, `verify-proof` bad proof, `attest` broken chain) |

## Python API

```python
from auditrail import (
    load_events, build_chain, verify_chain, attest, summarize,
    merkle_root, inclusion_proof, verify_inclusion, scan, to_json,
)

events = load_events(open("events.jsonl", encoding="utf-8").read())
chain = build_chain(events)
assert verify_chain(chain) == []          # [] == intact
head = chain.head                          # retain this
manifest = attest(chain, source="events.jsonl")

# Membership proof for a single event
proof = inclusion_proof(events, 1)
assert verify_inclusion(proof, merkle_root(events))

# One-call report (path or inline JSON/JSONL); also the MCP tool body
report = scan("events.jsonl")
print(to_json(report))
```
