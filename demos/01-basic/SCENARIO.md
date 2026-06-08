# Demo 01 - Basic: detecting a tampered audit log

A compliance reviewer receives `access_log.jsonl`, an export of access-control
events from an internal system. Each line is one audit event with the required
`ts` / `actor` / `action` triple plus context fields.

## 1. Build the chain and capture the head digest

```sh
python -m auditrail chain demos/01-basic/access_log.jsonl
python -m auditrail attest demos/01-basic/access_log.jsonl --format json
```

The `head` value in the attestation manifest is the tamper-evident fingerprint
of the entire log. Retain it as compliance evidence (e.g. in a ticket or WORM
store). Re-running `attest` on the unmodified file always reproduces the same
`head`.

## 2. Verify integrity

```sh
python -m auditrail verify demos/01-basic/access_log.jsonl
```

Exit code `0` and `chain status: INTACT` mean no event was added, removed,
reordered, or edited.

## 3. Simulate tampering

Edit any field of any line in `access_log.jsonl` (for example, change the
`actor` on the "grant admin" event to hide who did it, or delete a line), then
re-run `verify`:

```sh
python -m auditrail verify demos/01-basic/access_log.jsonl
```

Now the chain reports `BROKEN`, names the first affected `index`, and exits with
code `2` -- because every link's digest binds the full content of all prior
events, the alteration cascades and cannot be hidden without recomputing the
retained `head`.
