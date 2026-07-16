# AUDITRAIL — Architecture

> Tamper-evident audit-log aggregator with hash-chained attestation

`auditrail` turns a stream of audit-log events into cryptographic integrity
evidence. It is a pure-standard-library Python package with **no network calls,
no active scanning, and no remote log collection** — it reads event files you
give it and computes deterministic digests.

```
events (JSON array / JSONL)
        │
        ▼
  load_events ──▶ AuditEvent[]  (validate core triple, fold extras)
        │
        ├──▶ build_chain ──▶ HashChain ──▶ head digest      (ordering witness)
        │                         │
        │                         ├──▶ verify_chain ──▶ break records / []
        │                         ├──▶ attest       ──▶ attestation manifest
        │                         └──▶ summarize    ──▶ actor/action/time stats
        │
        └──▶ merkle_root / inclusion_proof ──▶ Merkle root + audit paths
                                                            (membership witness)
```

Two independent integrity structures are built over the **same canonical
events**, so they corroborate each other:

## 1. Linear hash chain — `auditrail/core.py`

The primary structure is a per-event hash chain (a degenerate Merkle chain):

```
digest_0 = sha256( GENESIS      || 0x1f || canonical_json(event_0) )
digest_i = sha256( digest_{i-1} || 0x1f || canonical_json(event_i) )
```

- **GENESIS** is a fixed all-zero 64-hex seed.
- **canonical_json** = sorted keys, no whitespace, stable separators — so the
  digest is byte-stable across machines, OSes, and language ports.
- The **head** (digest of the last link) is the chain's fingerprint. Because
  each link binds *all* prior content, any retroactive edit, deletion,
  insertion, or reordering invalidates every downstream digest.
- `verify_chain` recomputes every link and returns a list of **break records**
  (empty == intact) naming the index, reason (digest mismatch vs prev-pointer
  mismatch), expected vs stored digest, and the offending action — so a reviewer
  can localize the tamper.

The chain is the canonical **ordering** witness: it detects anything that
changes *what* happened or *in what order*.

## 2. Merkle tree — `auditrail/merkle.py`

A binary Merkle tree over the same canonical events adds a **membership**
witness: a compact O(log n) proof that one specific event belongs to the log,
without transmitting the other events. Domain separation follows the RFC 6962
convention to stop second-preimage attacks that confuse leaves with nodes:

```
leaf_hash = sha256( 0x00 || canonical_json(event) )
node_hash = sha256( 0x01 || left_digest || right_digest )
```

- Digests are combined as raw 32-byte values and surfaced as lowercase hex.
- An odd trailing node is **promoted** (carried up unchanged) rather than
  duplicated, avoiding the duplicate-leaf ambiguity (CVE-2012-2459).
- `inclusion_proof(events, i)` returns the audit path (sibling digests + L/R
  position). `verify_inclusion(proof, root)` replays the path and compares.
- Proofs serialize to/from JSON (`InclusionProof.as_dict` / `.from_dict`) so a
  verifier who holds only the trusted `root` can validate a single event.

## 3. Attestation

`attest(chain)` produces a self-describing manifest — head, genesis, event
count, distinct actors, time span, intact flag, break count — and hashes it into
a `manifest_digest`. `merkle_attest(events)` produces the Merkle equivalent.
Retain these values as compliance evidence; recompute later to prove the log was
not modified after attestation.

## Interfaces

- **CLI** (`auditrail/cli.py`): `chain` · `verify` · `attest` · `stats` · `root`
  · `prove` · `verify-proof` · `mcp`. Table and JSON output; exit `2` on tamper.
- **Python API** (`auditrail/__init__.py`): all core + Merkle functions, plus the
  one-call `scan(target)` / `to_json(obj)` helpers.
- **MCP server** (`auditrail/mcp_server.py`): exposes `scan` as an MCP tool.
- **Connector** (`auditrail/connect.py`): optional `cognis-connect` emitter.

## Design invariants

- **Deterministic**: identical events → identical head/root on every platform and
  [language port](../.github/workflows/ports.yml). The reference head
  `8ae3d48a…ea94d3` is asserted in CI.
- **Additive & backward-compatible**: the chain contract and existing CLI output
  are frozen; new structures (Merkle, stats) sit alongside them.
- **Offline & dependency-free** at runtime (standard library only).

Extend by adding a function + tests in `auditrail/`, and a docs note here. See
[CONTRIBUTING.md](../CONTRIBUTING.md).
