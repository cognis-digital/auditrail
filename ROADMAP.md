# AUDITRAIL — Roadmap

Direction for the tamper-evident audit-log aggregator. Priorities are shaped by
issues and PRs — see [CONTRIBUTING.md](CONTRIBUTING.md).

## Now — shipped

- Deterministic SHA-256 **hash chain** with byte-stable canonical JSON.
- `chain` / `verify` / `attest` CLI (table + JSON), exit `2` on tamper.
- **Merkle-tree membership layer**: `root`, `prove`, `verify-proof` — O(log n)
  inclusion proofs with RFC-6962 domain separation.
- `stats` descriptive summary; one-call `scan()` / `to_json()` API.
- MCP server wiring (`auditrail mcp`); `cognis-connect` emitter.
- Cross-language ports (Python, JS, Go, Rust, shell) reproducing the reference head.
- CI: unit tests + lint on push/PR; ports parity check.

## Next (v0.2)

- **Signed attestations** — optional detached signature over the head/root
  (Ed25519), so an attestation is non-repudiable, not just tamper-evident.
- **Streaming/append mode** — incremental chain extension with a checkpointed
  head so long-running logs don't require a full replay.
- **More input adapters** — CSV and syslog/RFC-5424 normalizers into the core
  triple, plus a pluggable field-mapping config.
- **Consistency proofs** — prove that one tree/chain is a prefix-extension of an
  earlier attested one (append-only guarantee across attestations).

## Mid-term (v0.3+)

- **Merkle range/multi-proofs** — batch inclusion proofs for many indices.
- **Time-anchoring hooks** — optional RFC-3161 / transparency-log anchoring of the
  head for third-party timestamping (kept strictly opt-in and offline-by-default).
- **Output formats** — CSV/NDJSON export of chains and break reports; JSON Schema
  for the manifest and proof envelopes.
- **Performance** — chunked hashing and memory-bounded verification for
  multi-gigabyte logs; benchmark suite.

## Long-term (v1.0)

- PyPI release and versioned stability guarantees for the manifest/proof formats.
- Plugin API for custom normalizers, exporters, and attestation backends.
- Commercial / production licensing and support (licensing@cognis.digital).

Open an issue or PR to shape priorities.
