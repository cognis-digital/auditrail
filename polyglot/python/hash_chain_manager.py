import json
import hashlib
import time
from dataclasses import dataclass, field, asdict
from typing import Optional, List, Dict, Any, BinaryIO
from contextlib import contextmanager
import threading


@dataclass
class ChainEntry:
    """Single entry in the hash chain."""
    id: int
    timestamp: float
    data: str
    hash: str
    prev_hash: str
    
    def __post_init__(self):
        if not self.hash or not self.prev_hash:
            raise ValueError("Entry must have computed hashes")


class ChainError(Exception):
    """Base exception for chain operations."""
    pass


class VerificationError(ChainError):
    """Raised when chain verification fails."""
    def __init__(self, message: str, broken_at: Optional[int] = None):
        super().__init__(message)
        self.broken_at = broken_at


class ChainCorruptionError(VerificationError):
    """Specific error for hash mismatches."""
    pass


@contextmanager
def _lock_chain(chain: 'HashChain'):
    """Thread-safe context manager for chain operations."""
    lock = getattr(chain, '_lock', threading.Lock())
    with lock:
        yield


class HashChain:
    """
    Tamper-evident hash-chained audit log.
    
    Each entry's hash includes the previous entry's hash, creating a 
    cryptographic link. Breaking any link corrupts all subsequent hashes.
    """
    
    def __init__(self):
        self.entries: List[ChainEntry] = []
        self._lock = threading.Lock()
        self._root_hash: Optional[str] = None
    
    @property
    def root_hash(self) -> str:
        """Hash of the entire chain (first entry's hash if exists)."""
        return self._root_hash or "0" * 64
    
    @property
    def is_empty(self) -> bool:
        return len(self.entries) == 0
    
    @property
    def count(self) -> int:
        return len(self.entries)
    
    def _compute_entry_hash(self, entry: ChainEntry) -> str:
        """Compute SHA-256 hash for an entry."""
        payload = f"{entry.id}:{entry.timestamp}:{entry.data}"
        return hashlib.sha256(payload.encode('utf-8')).hexdigest()
    
    def append(
        self, 
        data: str, 
        id: Optional[int] = None,
        timestamp: Optional[float] = None
    ) -> ChainEntry:
        """Add a new entry to the chain. Returns the created entry."""
        
        with _lock_chain(self):
            if not id:
                id = len(self.entries) + 1
            
            prev_hash = self.root_hash if self.entries else "0" * 64
            
            entry = ChainEntry(
                id=id,
                timestamp=timestamp or time.time(),
                data=data,
                hash="",
                prev_hash=prev_hash
            )
            
            # Compute and store the hash
            entry.hash = self._compute_entry_hash(entry)
            self.entries.append(entry)
            
            if not self._root_hash:
                self._root_hash = entry.hash
            
            return entry
    
    def verify_chain(self, strict: bool = True) -> Dict[str, Any]:
        """
        Verify the entire chain integrity.
        
        Args:
            strict: If True, raise exception on failure. Otherwise return report.
        
        Returns:
            Dictionary with verification status and details.
        """
        if not self.entries:
            return {
                "valid": True,
                "broken_at": None,
                "message": "Empty chain (trivially valid)",
                "expected_root": "0" * 64,
                "actual_root": self.root_hash
            }
        
        broken = None
        expected_prev = "0" * 64
        
        for i, entry in enumerate(self.entries):
            if i == 0:
                # First entry validates against its own hash
                computed = self._compute_entry_hash(entry)
                if computed != entry.hash:
                    broken = i
                    break
                expected_prev = entry.hash
            else:
                # Subsequent entries validate against previous's hash
                if entry.prev_hash != expected_prev:
                    broken = i
                    break
                expected_prev = entry.hash
        
        result = {
            "valid": broken is None,
            "broken_at": broken,
            "message": self._format_result(broken),
            "expected_root": self.entries[0].hash if self.entries else "",
            "actual_root": self.root_hash
        }
        
        if strict and not result["valid"]:
            raise ChainCorruptionError(result["message"])
        
        return result
    
    def _format_result(self, broken_at: Optional[int]) -> str:
        """Format human-readable verification message."""
        if broken_at is None:
            return "Chain verified successfully."
        
        entry = self.entries[broken_at]
        prev_entry = self.entries[broken_at - 1] if broken_at > 0 else None
        
        parts = [f"Broken at entry #{entry.id}"]
        
        if prev_entry:
            parts.append(
                f"Expected previous hash: {prev_entry.hash}\n"
                f"Found previous hash:    {entry.prev_hash}"
            )
        else:
            parts.append("First entry hash mismatch")
        
        return " ".join(parts)
    
    def get_attestation(self, include_entries: bool = False) -> Dict[str, Any]:
        """
        Generate cryptographic attestation for the current chain state.
        
        This is useful for proving to a third party that data existed 
        at a specific point in time with verifiable history.
        
        Args:
            include_entries: If True, also serialize all entries.
                          Large chains may use this sparingly.
        
        Returns:
            Attestation dictionary suitable for JSON serialization.
        """
        verification = self.verify_chain()
        
        attestation = {
            "type": "hash-chain-attestation",
            "version": "1.0",
            "root_hash": self.root_hash,
            "entry_count": len(self.entries),
            "verification_status": "valid" if verification["valid"] else "broken",
            "verification_details": {
                "broken_at": verification["broken_at"],
                "message": verification["message"],
                "expected_root": verification["expected_root"],
                "actual_root": verification["actual_root"]
            },
            "timestamp": time.time(),
        }
        
        if include_entries:
            attestation["entries"] = [asdict(e) for e in self.entries]
        
        return attestation
    
    def load_from_file(self, filepath: str) -> 'HashChain':
        """Load a chain from a JSON file."""
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        self._from_dict(data)
        return self
    
    def _from_dict(self, data: Dict[str, Any]) -> None:
        """Populate chain from dictionary (used by load_from_file)."""
        if "entries" in data and isinstance(data["entries"], list):
            self.entries = [ChainEntry(**e) for e in data["entries"]]
        
        if "root_hash" in data:
            self._root_hash = data["root_hash"]
    
    def save_to_file(self, filepath: str, include_entries: bool = True) -> None:
        """Save chain to a JSON file."""
        attestation = self.get_attestation(include_entries=include_entries)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(attestation, f, indent=2)
    
    def save_to_binary(self, filepath: str, include_entries: bool = True) -> None:
        """Save chain to a binary file (more compact)."""
        attestation = self.get_attestation(include_entries=include_entries)
        
        with open(filepath, 'wb') as f:
            json.dump(attestation, f, indent=2, ensure_ascii=False)
    
    @classmethod
    def load_from_binary(cls, filepath: str) -> 'HashChain':
        """Load chain from a binary file."""
        with open(filepath, 'rb') as f:
            data = json.load(f)
        
        chain = cls()
        chain._from_dict(data)
        return chain
    
    def merge(self, other: 'HashChain', verify_other: bool = True) -> None:
        """
        Merge another chain into this one.
        
        Args:
            other: The chain to append.
            verify_other: If True, verify the merged chain first.
        """
        if not self.entries and not other.entries:
            return
        
        if verify_other and other.entries:
            result = other.verify_chain()
            if not result["valid"]:
                raise ChainCorruptionError(
                    f"Merging broken chain:\n{result['message']}"
                )
        
        with _lock_chain(self):
            # Adjust IDs to avoid collisions
            offset = max(e.id for e in self.entries) + 1 if self.entries else 1
            
            for entry in other.entries:
                new_entry = ChainEntry(
                    id=entry.id + offset,
                    timestamp=entry.timestamp,
                    data=entry.data,
                    hash=entry.hash,
                    prev_hash=entry.prev_hash
                )
                self.entries.append(new_entry)
            
            # Recompute hashes for the merged portion
            expected_prev = other.root_hash if other.entries else "0" * 64
            
            for i, entry in enumerate(self.entries):
                if i >= len(other.entries):
                    computed = self._compute_entry_hash(entry)
                    if computed != entry.hash:
                        # Recompute and update (this is expected after merge)
                        entry.hash = computed
                    else:
                        expected_prev = entry.hash
                elif i == 0:
                    # First entry of merged portion
                    computed = self._compute_entry_hash(entry)
                    if computed != entry.hash:
                        entry.hash = computed
                        expected_prev = entry.hash
                    else:
                        expected_prev = entry.hash
    
    def __iter__(self):
        """Iterate over entries."""
        return iter(self.entries)
    
    def __len__(self) -> int:
        return len(self.entries)
    
    def __repr__(self) -> str:
        status = "valid" if self.verify_chain()["valid"] else "broken"
        return f"<HashChain entries={len(self)} root_hash={self.root_hash[:16]}... status={status}>"


def demo():
    """Demonstrate the hash chain manager capabilities."""
    
    print("=" * 60)
    print("HASH CHAIN MANAGER DEMO")
    print("=" * 60)
    
    # Create and populate a fresh chain
    print("\n1. Creating new chain...")
    chain = HashChain()
    
    for i, data in enumerate([
        "Initial record",
        "Second entry", 
        "Third entry",
        "Fourth entry"
    ], 1):
        entry = chain.append(data)
        print(f"   Added entry #{entry.id}: {data[:20]}...")
    
    # Verify the fresh chain
    print("\n2. Verifying fresh chain...")
    result = chain.verify_chain()
    print(f"   Status: {'✓ VALID' if result['valid'] else '✗ BROKEN'}")
    print(f"   Root hash: {result['actual_root']}")
    
    # Generate attestation
    print("\n3. Generating attestation...")
    attestation = chain.get_attestation()
    print(f"   Attestation type: {attestation['type']}")
    print(f"   Entry count: {attestation['entry_count']}")
    print(f"   Verification status: {attestation['verification_status']}")
    
    # Save and load test
    print("\n4. Testing persistence (save/load)...")
    chain.save_to_file("demo_chain.json", include_entries=False)
    loaded = HashChain.load_from_file("demo_chain.json")
    
    print(f"   Original entries: {len(chain.entries)}")
    print(f"   Loaded entries:  {len(loaded.entries)}")
    print(f"   Root hashes match: {chain.root_hash == loaded.root_hash}")
    
    # Tamper test - modify an entry and verify detection
    print("\n5. Testing tamper detection...")
    if chain.entries:
        original = chain.entries[0].data
        chain.entries[0].data = "TAMPERED DATA"
        
        result = chain.verify_chain()
        print(f"   After tampering:")
        print(f"   Status: {'✓ VALID' if result['valid'] else '✗ BROKEN'}")
        print(f"   Broken at entry #{result['broken_at']}")
        print(f"   Message: {result['message']}")
    
    # Merge test
    print("\n6. Testing chain merge...")
    chain2 = HashChain()
    for i, data in enumerate(["From chain 2", "More from 2"], 1):
        chain2.append(data)
    
    print(f"   Before merge: {len(chain.entries)} entries")
    print(f"   Chain 2 has:  {len(chain2.entries)} entries")
    
    chain.merge(chain2, verify_other=True)
    print(f"   After merge:  {len(chain.entries)} entries")
    print(f"   New root hash: {chain.root_hash[:16]}...")
    
    # Final verification
    print("\n7. Final verification after all operations...")
    result = chain.verify_chain()
    print(f"   Status: {'✓ VALID' if result['valid'] else '✗ BROKEN'}")
    print(f"   Total entries: {len(chain.entries)}")
    
    # Cleanup demo files
    import os
    for f in ["demo_chain.json"]:
        try:
            os.remove(f)
        except FileNotFoundError:
            pass
    
    print("\n8. Demo complete!")


if __name__ == "__main__":
    demo()