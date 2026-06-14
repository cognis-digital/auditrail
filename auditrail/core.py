"""Core engine for AUDITRAIL.

The integrity model is a per-event hash chain (a degenerate Merkle chain):

    digest_i = sha256( prev_digest || canonical_json(event_i) )

with the genesis link using a fixed all-zero seed. Because each digest binds
the full content of every prior event, tampering with any field of any event
(or inserting/deleting/reordering events) invalidates every downstream digest,
which `verify_chain` detects and pinpoints.

The attestation manifest captures the chain head digest plus metadata, giving
compliance reviewers a single value to retain as evidence of integrity.
"""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable

GENESIS = "0" * 64

# Fields that must be present on every audit event. Compliance frameworks
# (SOC 2 CC7.2, PCI-DSS 10.2/10.3) require who/what/when at minimum.
REQUIRED_FIELDS = ("ts", "actor", "action")


class ChainBreak(Exception):
    """Raised when the integrity chain cannot be verified."""


@dataclass(frozen=True)
class AuditEvent:
    """A single normalized audit-log event."""

    ts: str
    actor: str
    action: str
    extra: dict[str, Any] = field(default_factory=dict)

    def canonical(self) -> dict[str, Any]:
        """Return a deterministic dict representation for hashing."""
        payload: dict[str, Any] = {"ts": self.ts, "actor": self.actor, "action": self.action}
        # Merge extras but never let them shadow the core triple.
        for k, v in self.extra.items():
            if k not in payload:
                payload[k] = v
        return payload

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "AuditEvent":
        missing = [f for f in REQUIRED_FIELDS if f not in raw or raw[f] in (None, "")]
        if missing:
            raise ValueError(f"event missing required field(s): {', '.join(missing)}")
        extra = {k: v for k, v in raw.items() if k not in REQUIRED_FIELDS}
        return cls(ts=str(raw["ts"]), actor=str(raw["actor"]), action=str(raw["action"]), extra=extra)


@dataclass(frozen=True)
class Link:
    """One link in the hash chain."""

    index: int
    prev: str
    digest: str
    event: AuditEvent


@dataclass(frozen=True)
class HashChain:
    """An immutable hash-chained sequence of audit events."""

    links: tuple[Link, ...]

    @property
    def head(self) -> str:
        """Digest of the final link (the chain's tamper-evident fingerprint)."""
        return self.links[-1].digest if self.links else GENESIS

    def __len__(self) -> int:
        return len(self.links)


def _canonical_json(obj: Any) -> str:
    """Canonical JSON: sorted keys, no whitespace, stable separators."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _link_digest(prev: str, event: AuditEvent) -> str:
    material = prev + "\x1f" + _canonical_json(event.canonical())
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def build_chain(events: Iterable[AuditEvent]) -> HashChain:
    """Construct a hash chain from an ordered iterable of events."""
    links: list[Link] = []
    prev = GENESIS
    for i, ev in enumerate(events):
        digest = _link_digest(prev, ev)
        links.append(Link(index=i, prev=prev, digest=digest, event=ev))
        prev = digest
    return HashChain(links=tuple(links))


def verify_chain(chain: HashChain) -> list[dict[str, Any]]:
    """Recompute every link and report any break.

    Returns a list of break records (empty == intact). Each record names the
    index, the expected vs. stored digest, and the offending event so a
    reviewer can locate the tampered row.
    """
    breaks: list[dict[str, Any]] = []
    prev = GENESIS
    for link in chain.links:
        if link.prev != prev:
            breaks.append(
                {
                    "index": link.index,
                    "reason": "prev-pointer mismatch",
                    "expected_prev": prev,
                    "stored_prev": link.prev,
                    "action": link.event.action,
                }
            )
        recomputed = _link_digest(link.prev, link.event)
        if recomputed != link.digest:
            breaks.append(
                {
                    "index": link.index,
                    "reason": "digest mismatch (content altered)",
                    "expected_digest": recomputed,
                    "stored_digest": link.digest,
                    "action": link.event.action,
                }
            )
            prev = link.digest  # continue from stored to surface independent breaks
        else:
            prev = recomputed
    return breaks


def attest(chain: HashChain, source: str = "<stdin>") -> dict[str, Any]:
    """Produce a compliance attestation manifest for a chain.

    The manifest is itself self-describing and is hashed so it can be retained
    as evidence; recomputing the chain later and matching `head` proves the
    log was not modified after attestation.
    """
    breaks = verify_chain(chain)
    actors = sorted({lk.event.actor for lk in chain.links})
    first_ts = chain.links[0].event.ts if chain.links else None
    last_ts = chain.links[-1].event.ts if chain.links else None
    manifest: dict[str, Any] = {
        "tool": "auditrail",
        "version": "1.0.0",
        "source": source,
        "attested_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "event_count": len(chain),
        "genesis": GENESIS,
        "head": chain.head,
        "first_ts": first_ts,
        "last_ts": last_ts,
        "distinct_actors": actors,
        "intact": not breaks,
        "break_count": len(breaks),
    }
    manifest["manifest_digest"] = hashlib.sha256(
        _canonical_json({k: v for k, v in manifest.items()}).encode("utf-8")
    ).hexdigest()
    return manifest


def _parse_records(text: str) -> list[dict[str, Any]]:
    """Parse either a JSON array or newline-delimited JSON (JSONL)."""
    text = text.strip()
    if not text:
        return []
    if text[0] == "[":
        try:
            data = json.loads(text)
        except json.JSONDecodeError as e:
            raise ValueError(f"malformed JSON array: {e}") from e
        if not isinstance(data, list):
            raise ValueError("top-level JSON must be an array of events")
        return data
    records: list[dict[str, Any]] = []
    for lineno, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError as e:
            raise ValueError(f"line {lineno}: invalid JSON: {e}") from e
    return records


def load_events(text: str) -> list[AuditEvent]:
    """Load and validate audit events from JSON-array or JSONL text."""
    events: list[AuditEvent] = []
    for i, raw in enumerate(_parse_records(text)):
        if not isinstance(raw, dict):
            raise ValueError(f"event {i} is not an object")
        events.append(AuditEvent.from_dict(raw))
    return events


def load_events_from_path(path: str) -> list[AuditEvent]:
    if not os.path.isfile(path):
        raise FileNotFoundError(f"no such file: {path}")
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return load_events(fh.read())
    except OSError as e:
        raise OSError(f"cannot read {path}: {e}") from e
