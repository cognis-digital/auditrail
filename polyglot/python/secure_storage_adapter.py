import hashlib
import json
import os
import time
from dataclasses import dataclass, field, asdict
from typing import List, Optional, Dict, Any


@dataclass
class Record:
    """Single audit record with cryptographic binding."""
    sequence_id: int
    timestamp: float
    payload: str
    expected_hash: str = ""

    def compute_hash(self) -> str:
        """Compute SHA-256 hash of this record's content."""
        content = f"{self.sequence_id}:{self.timestamp}:{self.payload}"
        return hashlib.sha256(content.encode("utf-8")).hexdigest()


class SecureStorageAdapter:
    """
    Tamper-evident audit-log aggregator with hash-chained attestation.

    Each record's hash becomes part of the next, creating an immutable chain.
    Any modification to any record breaks the entire chain.
    """

    def __init__(self, genesis_hash: str = ""):
        self.records: List[Record] = []
        self.current_chain_hash: str = genesis_hash
        self.sequence_counter: int = 1

    def _chain_hash(self, previous: str, record: Record) -> str:
        """Compute hash of (previous_chain + current_record)."""
        content = f"{previous}:{record.compute_hash()}"
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    def append(self, payload: str, metadata: Optional[Dict[str, Any]] = None) -> Record:
        """Add a new record to the chain."""
        if not self.records:
            # Genesis record - starts with provided or default genesis hash
            prev_hash = self.current_chain_hash or hashlib.sha256(b"genesis").hexdigest()
        else:
            prev_hash = self.records[-1].compute_hash()

        record = Record(
            sequence_id=self.sequence_counter,
            timestamp=time.time(),
            payload=payload,
            expected_hash=prev_hash  # Previous hash binds this record
        )

        new_chain_hash = self._chain_hash(prev_hash, record)
        record.expected_hash = new_chain_hash

        self.records.append(record)
        self.current_chain_hash = new_chain_hash
        self.sequence_counter += 1

        return record

    def get_chain(self) -> List[Record]:
        """Return a copy of all records in order."""
        return list(self.records)

    def verify_integrity(self) -> bool:
        """Verify that the entire chain is unbroken."""
        if not self.records:
            return True  # Empty chain is valid

        expected = hashlib.sha256(b"genesis").hexdigest()
        for record in self.records:
            computed = self._chain_hash(expected, record)
            if computed != record.expected_hash:
                return False
            expected = record.expected_hash

        return True

    def load_from_file(self, path: str) -> bool:
        """Load state from a JSON file."""
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)

            self.records = []
            for item in data.get("records", []):
                record = Record(
                    sequence_id=item["sequence_id"],
                    timestamp=item["timestamp"],
                    payload=item["payload"],
                    expected_hash=item["expected_hash"]
                )
                self.records.append(record)

            self.current_chain_hash = data.get("current_chain_hash", "")
            self.sequence_counter = len(self.records) + 1

            return True
        except (FileNotFoundError, json.JSONDecodeError):
            return False

    def save_to_file(self, path: str) -> bool:
        """Persist current state to a JSON file."""
        try:
            data = {
                "records": [asdict(r) for r in self.records],
                "current_chain_hash": self.current_chain_hash,
                "sequence_counter": self.sequence_counter
            }
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            return True
        except IOError:
            return False

    def get_attestation_report(self) -> Dict[str, Any]:
        """Generate a human-readable integrity report."""
        total_records = len(self.records)
        is_valid = self.verify_integrity()

        # Find first broken link if any
        break_point = None
        expected = hashlib.sha256(b"genesis").hexdigest()
        for i, record in enumerate(self.records):
            computed = self._chain_hash(expected, record)
            if computed != record.expected_hash:
                break_point = i
                break
            expected = record.expected_hash

        report = {
            "total_records": total_records,
            "integrity_valid": is_valid,
            "break_point": break_point,
            "current_chain_hash": self.current_chain_hash,
            "genesis_hash": hashlib.sha256(b"genesis").hexdigest() if not self.records else "",
        }

        return report


def main():
    """Self-contained demo demonstrating the adapter."""
    import sys

    # Create a new storage adapter
    adapter = SecureStorageAdapter(genesis_hash="a1b2c3d4e5f6")

    print("=" * 60)
    print("Secure Storage Adapter Demo")
    print("=" * 60)

    # Append some records
    for i in range(5):
        payload = f"Transaction #{i+1}: User action at {time.strftime('%H:%M:%S')}"
        record = adapter.append(payload, {"user_id": "demo_user"})
        print(f"\nRecord {record.sequence_id}:")
        print(f"  Payload: {payload[:50]}...")
        print(f"  Expected hash (for next): {record.expected_hash[:16]}...")

    # Verify integrity
    print("\n" + "=" * 60)
    print("Integrity Check:")
    print("=" * 60)
    is_valid = adapter.verify_integrity()
    report = adapter.get_attestation_report()

    print(f"Total records: {report['total_records']}")
    print(f"Chain integrity valid: {'YES' if is_valid else 'NO'}")
    print(f"Current chain hash: {adapter.current_chain_hash[:32]}...")

    # Simulate tampering
    print("\n" + "=" * 60)
    print("Tamper Simulation:")
    print("=" * 60)

    original_record = adapter.records[1]
    original_payload = original_record.payload
    tampered_payload = "MODIFIED PAYLOAD!"

    # Tamper with the record
    adapter.records[1].payload = tampered_payload

    # Verify - should fail now
    print(f"Original payload: {original_payload[:40]}...")
    print(f"Tampered payload: {tampered_payload}")
    
    is_valid_after_tamper = adapter.verify_integrity()
    report_after = adapter.get_attestation_report()

    print(f"\nIntegrity after tampering: {'VALID (bad!)' if is_valid_after_tamper else 'BROKEN (good)'}")
    print(f"Break point detected at record index: {report_after['break_point']}")

    # Restore and verify again
    adapter.records[1].payload = original_payload
    is_valid_restored = adapter.verify_integrity()
    print(f"\nIntegrity after restoration: {'VALID' if is_valid_restored else 'BROKEN'}")

    # Persistence demo
    print("\n" + "=" * 60)
    print("Persistence Demo:")
    print("=" * 60)

    test_path = "/tmp/secure_storage_adapter_test.json"

    adapter.save_to_file(test_path)
    print(f"\nSaved state to: {test_path}")

    # Create new instance and load
    fresh_adapter = SecureStorageAdapter()
    loaded_ok = fresh_adapter.load_from_file(test_path)

    if loaded_ok:
        print("Loaded state successfully!")
        print(f"Records count: {len(fresh_adapter.records)}")
        
        # Verify loaded chain is intact
        loaded_valid = fresh_adapter.verify_integrity()
        print(f"Loaded chain integrity: {'VALID' if loaded_valid else 'BROKEN'}")

    os.remove(test_path)  # Cleanup

    print("\n" + "=" * 60)
    print("Demo complete.")
    print("=" * 60)


if __name__ == "__main__":
    main()