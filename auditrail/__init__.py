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
    "TOOL_NAME",
    "TOOL_VERSION",
]
