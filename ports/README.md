# Ports of auditrail

The AUDITRAIL core — the SHA-256 **hash chain** and its `chain` / `verify` /
`attest` command surface — ported across languages so you can drop integrity
verification into any stack or ship a single static binary.

**Every port reproduces the identical reference head** over the worked-example
events from the main README:

```
8ae3d48a5736f485bd64d7d812d5255a5548962684e79a85d05bbbfac1ea94d3
```

This is enforced in CI by [`../.github/workflows/ports.yml`](../.github/workflows/ports.yml):
each port builds, runs its smoke test, and asserts that constant.

| Language | Path | Run | Smoke test |
|---|---|---|---|
| Python (reference) | `../auditrail/` | `auditrail verify events.jsonl` | `python -m pytest` |
| JavaScript / Node  | `javascript/` | `node javascript/index.js verify events.jsonl` | `node javascript/test.js` |
| Go                 | `go/` | `cd go && go run . verify ../../events.jsonl` | `go test ./...` |
| Rust               | `rust/` | `cd rust && cargo run -- verify ../../events.jsonl` | `cargo test` |
| POSIX shell        | `shell/` | `sh shell/auditrail.sh verify events.jsonl` | `sh shell/test.sh` |

## Design notes

- **Canonical JSON.** All ports serialize event payloads with sorted keys and no
  whitespace, matching Python's `json.dumps(sort_keys=True, separators=(",",":"))`,
  so the digests are byte-identical.
- **Digest material.** `digest_i = sha256(prev_digest || 0x1f || canonical_json(event_i))`,
  genesis = 64 zero hex chars.
- **Zero external dependencies.** The Rust port implements SHA-256 (FIPS 180-4)
  and a small JSON parser inline; the shell port uses `sha256sum`/`shasum` plus an
  embedded `awk` canonicalizer. Go and Node use only their standard libraries.

All commands are **passive and offline** — they read the events you pass and make
no network calls.

Contributions of additional ports (Ruby, C#, Bun, Deno, WASM) are welcome — see
../CONTRIBUTING.md.
