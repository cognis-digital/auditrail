import hashlib
import json
import os
import threading
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Callable


@dataclass(order=True)
class LogEntry:
    """Single log entry with tamper-evident hash chain."""
    sequence: int = field(compare=False)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    source: str = ""
    level: str = "INFO"
    message: str = ""
    data: Dict[str, Any] = field(default_factory=dict, compare=False)
    parent_hash: str = ""  # Hash of previous entry (chain)
    self_hash: str = ""   # Hash of this entry's content + parent_hash
    
    def __post_init__(self):
        if not self.parent_hash and self.sequence > 0:
            raise ValueError("Entry with sequence > 0 must have parent_hash")
        
        self._compute_self_hash()
    
    def _compute_self_hash(self) -> None:
        """Compute SHA-256 hash of entry content."""
        content = f"{self.parent_hash}:{self.timestamp}:{self.source}:{self.level}:{self.message}"
        for k, v in sorted(self.data.items()):
            content += f":{k}={json.dumps(v)}"
        self.self_hash = hashlib.sha256(content.encode('utf-8')).hexdigest()


class AuditTrail:
    """Tamper-evident audit-log aggregator with hash-chained attestation."""
    
    def __init__(self, 
                 name: str = "default",
                 storage_path: Optional[str] = None,
                 max_entries: int = 10000):
        self.name = name
        self.storage_path = storage_path or f"{name}_audit.json"
        self.max_entries = max_entries
        self.lock = threading.RLock()
        self.entries: List[LogEntry] = []
        self.sequence_counter = 0
        self.root_hash: Optional[str] = None
        
    def ingest(self, 
               source: str, 
               level: str = "INFO", 
               message: str, 
               data: Optional[Dict[str, Any]] = None) -> LogEntry:
        """Add a single log entry to the trail."""
        with self.lock:
            if not data:
                data = {}
            
            entry = LogEntry(
                sequence=self.sequence_counter + 1,
                source=source,
                level=level,
                message=message,
                data=data,
                parent_hash=self.entries[-1].self_hash if self.entries else ""
            )
            
            self.entries.append(entry)
            self.sequence_counter += 1
            
            # Trim to max_entries
            if len(self.entries) > self.max_entries:
                self._trim_to_max()
            
            return entry
    
    def ingest_batch(self, 
                     entries: List[Dict[str, Any]]) -> List[LogEntry]:
        """Ingest multiple log entries efficiently."""
        with self.lock:
            batch = []
            for item in entries:
                source = item.get('source', 'batch')
                level = item.get('level', 'INFO')
                message = item.get('message', '')
                data = item.get('data', {})
                
                entry = LogEntry(
                    sequence=self.sequence_counter + 1,
                    source=source,
                    level=level,
                    message=message,
                    data=data,
                    parent_hash=self.entries[-1].self_hash if self.entries else ""
                )
                batch.append(entry)
                self.entries.append(entry)
                self.sequence_counter += 1
            
            # Trim and return created entries
            if len(self.entries) > self.max_entries:
                self._trim_to_max()
            
            return batch
    
    def _trim_to_max(self):
        """Remove oldest entries to maintain max size."""
        while len(self.entries) > self.max_entries:
            removed = self.entries.pop(0)
            # Update parent_hash of next entry
            if self.entries and not self.entries[0].parent_hash:
                self.entries[0].parent_hash = removed.self_hash
    
    def verify_chain(self) -> bool:
        """Verify the entire hash chain is intact."""
        with self.lock:
            expected_root = ""
            
            for entry in self.entries:
                if entry.parent_hash != expected_root:
                    return False
                expected_root = entry.self_hash
            
            # Last entry's hash should match computed root
            last_entry = self.entries[-1] if self.entries else None
            if last_entry and last_entry.self_hash != expected_root:
                return False
            
            return True
    
    def get_attestation(self) -> Dict[str, Any]:
        """Get cryptographic attestation of current trail state."""
        with self.lock:
            root = self.entries[-1].self_hash if self.entries else ""
            
            return {
                "name": self.name,
                "sequence": self.sequence_counter,
                "root_hash": root,
                "entry_count": len(self.entries),
                "verified": self.verify_chain(),
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
    
    def get_entry_by_sequence(self, sequence: int) -> Optional[LogEntry]:
        """Find entry by sequence number."""
        with self.lock:
            for entry in self.entries:
                if entry.sequence == sequence:
                    return entry
            return None
    
    def get_entries_range(self, start: int, end: int) -> List[Dict[str, Any]]:
        """Get entries in a range as dictionaries."""
        with self.lock:
            result = []
            for entry in self.entries[start:end]:
                d = {k: v for k, v in asdict(entry).items()}
                if isinstance(d['data'], dict):
                    d['data'] = json.dumps(d['data'])
                result.append(d)
            return result
    
    def export(self, path: Optional[str] = None) -> str:
        """Export trail to JSON file."""
        with self.lock:
            data = {
                "name": self.name,
                "sequence": self.sequence_counter,
                "root_hash": self.entries[-1].self_hash if self.entries else "",
                "entries": [asdict(e) for e in self.entries],
                "exported_at": datetime.now(timezone.utc).isoformat()
            }
            
            target = path or self.storage_path
            with open(target, 'w') as f:
                json.dump(data, f, indent=2)
            
            return target
    
    def import_from(self, path: str) -> bool:
        """Import trail from JSON file."""
        try:
            with open(path, 'r') as f:
                data = json.load(f)
            
            self.name = data.get('name', 'imported')
            self.sequence_counter = data.get('sequence', 0)
            self.entries = [LogEntry(**e) for e in data.get('entries', [])]
            
            # Recompute hashes to ensure consistency
            for entry in self.entries:
                entry._compute_self_hash()
            
            return True
        except (FileNotFoundError, json.JSONDecodeError):
            return False
    
    def __len__(self) -> int:
        with self.lock:
            return len(self.entries)


# =============================================================================
# Demo / Entry Point
# =============================================================================

def main():
    """Demonstrate the AuditTrail functionality."""
    
    print("=" * 60)
    print("AUDITRAIL - Tamper-Evident Log Ingestion Demo")
    print("=" * 60)
    
    # Create trail
    trail = AuditTrail(name="demo_trail", max_entries=100)
    
    # Define test events
    events = [
        {"source": "app_server", "level": "INFO", "message": "Application started"},
        {"source": "auth_service", "level": "DEBUG", "message": "User session created: user_123"},
        {"source": "payment_gateway", "level": "WARN", "message": "Retry attempt 2/3 for transaction TX-998877"},
        {"source": "app_server", "level": "ERROR", "message": "Database connection timeout"},
        {"source": "scheduler", "level": "INFO", "message": "Scheduled task completed: cleanup_old_logs"},
    ]
    
    # Ingest batch
    print("\n1. Ingesting batch of events...")
    ingested = trail.ingest_batch(events)
    print(f"   - Ingested {len(ingested)} entries")
    print(f"   - Sequence range: 1-{trail.sequence_counter}")
    
    # Verify chain integrity
    print("\n2. Verifying hash chain...")
    is_valid = trail.verify_chain()
    print(f"   - Chain valid: {is_valid}")
    
    # Get attestation
    print("\n3. Getting cryptographic attestation...")
    attestation = trail.get_attestation()
    print(f"   - Root hash: {attestation['root_hash'][:16]}...")
    print(f"   - Entry count: {attestation['entry_count']}")
    
    # Export to file
    print("\n4. Exporting trail...")
    export_path = trail.export("demo_trail.json")
    print(f"   - Saved to: {export_path}")
    
    # Import back and verify
    print("\n5. Testing import/export roundtrip...")
    imported = AuditTrail(name="imported_demo")
    result = imported.import_from(export_path)
    print(f"   - Import successful: {result}")
    print(f"   - Entries match: {len(imported.entries) == len(trail.entries)}")
    
    # Verify imported chain
    print("\n6. Verifying imported trail...")
    import_valid = imported.verify_chain()
    print(f"   - Imported chain valid: {import_valid}")
    
    # Print sample entries
    print("\n7. Sample entries (first 3):")
    for entry in trail.entries[:3]:
        print(f"   [{entry.sequence}] {entry.level}: {entry.message[:50]}...")
    
    print("\n" + "=" * 60)
    print("Demo complete.")
    print("=" * 60)


if __name__ == "__main__":
    main()