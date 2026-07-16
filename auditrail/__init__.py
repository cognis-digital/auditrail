"""AUDITRAIL - Tamper-evident audit-log aggregator with hash-chained attestation.

Aggregates audit log events into a Merkle-style hash chain so that any
retroactive modification, deletion, or reordering of events is detectable.
Produces signed-style attestation manifests for compliance evidence.
"""
from auditrail.core import (
    AuditEvent,
    HashChain,
    ChainBreak,
    build_chain,
    verify_chain,
    attest,
    load_events,
    load_events_from_path,
    summarize,
    scan,
    to_json,
)
from auditrail.merkle import (
    InclusionProof,
    ProofError,
    ProofStep,
    inclusion_proof,
    leaf_hash,
    merkle_attest,
    merkle_root,
    verify_inclusion,
)

TOOL_NAME = "auditrail"
TOOL_VERSION = "1.0.0"

__all__ = [
    "AuditEvent",
    "HashChain",
    "ChainBreak",
    "build_chain",
    "verify_chain",
    "attest",
    "load_events",
    "load_events_from_path",
    "summarize",
    "scan",
    "to_json",
    "InclusionProof",
    "ProofError",
    "ProofStep",
    "inclusion_proof",
    "leaf_hash",
    "merkle_attest",
    "merkle_root",
    "verify_inclusion",
    "TOOL_NAME",
    "TOOL_VERSION",
]
