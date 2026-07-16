"""Merkle-tree attestation for AUDITRAIL.

The core engine (:mod:`auditrail.core`) binds events into a *linear* hash chain.
That chain proves the whole log is intact with a single head digest, but proving
that one specific event belongs to the log requires replaying every event up to
it — O(n) data.

This module adds a complementary **binary Merkle tree** over the same canonical
events. It yields:

* a single ``root`` digest (an alternative tamper-evident fingerprint), and
* compact **inclusion proofs**: an O(log n) audit path that proves a single
  event is a leaf of the tree committed to by ``root`` — without revealing or
  transmitting the other events.

Domain separation follows the RFC 6962 convention to prevent second-preimage
attacks that confuse leaves with internal nodes:

    leaf_hash   = sha256( 0x00 || canonical_json(event) )
    node_hash   = sha256( 0x01 || left_digest || right_digest )

Digests are combined as raw 32-byte values and surfaced as lowercase hex. When a
level has an odd number of nodes, the final node is **promoted** unchanged to the
next level (rather than duplicated), which avoids the duplicate-leaf ambiguity
(CVE-2012-2459) at the cost of a slightly unbalanced tree.

This module is additive: it does not alter the linear chain or any existing
behavior. The chain remains the canonical ordering witness; the Merkle tree is a
membership witness layered on top.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

from auditrail.core import AuditEvent, _canonical_json

_LEAF_PREFIX = b"\x00"
_NODE_PREFIX = b"\x01"

# Root of the empty tree: a fixed, self-describing sentinel (never collides with
# a real leaf/node digest because those are always sha256 outputs).
EMPTY_ROOT = "0" * 64


class ProofError(Exception):
    """Raised when an inclusion proof is malformed or fails to verify."""


def leaf_hash(event: AuditEvent) -> str:
    """Return the domain-separated leaf digest (hex) for one event."""
    material = _LEAF_PREFIX + _canonical_json(event.canonical()).encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def _node_hash(left_hex: str, right_hex: str) -> str:
    material = _NODE_PREFIX + bytes.fromhex(left_hex) + bytes.fromhex(right_hex)
    return hashlib.sha256(material).hexdigest()


@dataclass(frozen=True)
class ProofStep:
    """One sibling on the audit path from a leaf up to the root."""

    sibling: str  # hex digest of the sibling node
    position: str  # "L" if the sibling sits on the left, else "R"

    def as_dict(self) -> dict[str, str]:
        return {"sibling": self.sibling, "position": self.position}

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "ProofStep":
        try:
            sibling = str(raw["sibling"])
            position = str(raw["position"])
        except (KeyError, TypeError) as exc:
            raise ProofError(f"malformed proof step: {raw!r}") from exc
        if position not in ("L", "R"):
            raise ProofError(f"proof step position must be 'L' or 'R', got {position!r}")
        if len(sibling) != 64:
            raise ProofError("proof step sibling must be a 64-hex digest")
        return cls(sibling=sibling, position=position)


@dataclass(frozen=True)
class InclusionProof:
    """A self-contained proof that a leaf is committed to by ``root``."""

    index: int
    leaf: str
    root: str
    leaf_count: int
    path: tuple[ProofStep, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": "auditrail-merkle-inclusion",
            "index": self.index,
            "leaf": self.leaf,
            "root": self.root,
            "leaf_count": self.leaf_count,
            "path": [s.as_dict() for s in self.path],
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "InclusionProof":
        if not isinstance(raw, dict):
            raise ProofError("proof must be a JSON object")
        try:
            index = int(raw["index"])
            leaf = str(raw["leaf"])
            root = str(raw["root"])
            leaf_count = int(raw["leaf_count"])
            path_raw = raw["path"]
        except (KeyError, TypeError, ValueError) as exc:
            raise ProofError(f"proof missing required field: {exc}") from exc
        if not isinstance(path_raw, list):
            raise ProofError("proof 'path' must be a list")
        path = tuple(ProofStep.from_dict(p) for p in path_raw)
        return cls(index=index, leaf=leaf, root=root, leaf_count=leaf_count, path=path)


def merkle_levels(events: list[AuditEvent]) -> list[list[str]]:
    """Return every level of the tree, bottom (leaves) to top (root).

    ``levels[0]`` is the list of leaf digests; ``levels[-1]`` is ``[root]``.
    Returns ``[]`` for an empty input.
    """
    if not events:
        return []
    level = [leaf_hash(ev) for ev in events]
    levels = [level]
    while len(level) > 1:
        nxt: list[str] = []
        for i in range(0, len(level), 2):
            if i + 1 < len(level):
                nxt.append(_node_hash(level[i], level[i + 1]))
            else:
                nxt.append(level[i])  # promote the odd trailing node unchanged
        levels.append(nxt)
        level = nxt
    return levels


def merkle_root(events: list[AuditEvent]) -> str:
    """Return the Merkle root (hex) over an ordered list of events."""
    levels = merkle_levels(events)
    if not levels:
        return EMPTY_ROOT
    return levels[-1][0]


def inclusion_proof(events: list[AuditEvent], index: int) -> InclusionProof:
    """Build an inclusion proof for the event at ``index``.

    Raises :class:`IndexError` if ``index`` is out of range.
    """
    n = len(events)
    if index < 0 or index >= n:
        raise IndexError(f"event index {index} out of range for {n} event(s)")
    levels = merkle_levels(events)
    path: list[ProofStep] = []
    pos = index
    for level in levels[:-1]:  # every level except the root
        if pos % 2 == 0:
            sib = pos + 1
            if sib < len(level):
                path.append(ProofStep(sibling=level[sib], position="R"))
            # else: node promoted, no sibling at this level
        else:
            path.append(ProofStep(sibling=level[pos - 1], position="L"))
        pos //= 2
    return InclusionProof(
        index=index,
        leaf=levels[0][index],
        root=levels[-1][0],
        leaf_count=n,
        path=tuple(path),
    )


def verify_inclusion(proof: InclusionProof, root: str | None = None) -> bool:
    """Recompute the root from a proof's leaf + audit path and compare.

    If ``root`` is given, the proof must reproduce it; otherwise the proof is
    checked against the ``root`` it carries (self-consistency).
    """
    expected = root if root is not None else proof.root
    acc = proof.leaf
    if len(proof.leaf) != 64:
        raise ProofError("proof leaf must be a 64-hex digest")
    for step in proof.path:
        if step.position == "L":
            acc = _node_hash(step.sibling, acc)
        else:
            acc = _node_hash(acc, step.sibling)
    return acc == expected


def merkle_attest(events: list[AuditEvent], source: str = "<stdin>") -> dict[str, Any]:
    """Return a compact Merkle attestation manifest for a set of events."""
    return {
        "tool": "auditrail",
        "kind": "auditrail-merkle-attestation",
        "source": source,
        "leaf_count": len(events),
        "root": merkle_root(events),
        "empty_root": EMPTY_ROOT,
    }
