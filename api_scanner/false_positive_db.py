"""
False Positive Database for managing known false positives.
"""

import json
import logging
import hashlib
from pathlib import Path
from datetime import datetime
from typing import List
from .models import FalsePositiveEntry, Vulnerability, Alert

logger = logging.getLogger(__name__)


class FalsePositiveDatabase:
    """Manages false positive entries"""
    
    def __init__(self):
        self.entries: List[FalsePositiveEntry] = []
    
    def mark_false_positive(self, alert: Alert, marked_by: str) -> None:
        """Mark an alert as false positive"""
        evidence_hash = hashlib.sha256(alert.vulnerability.evidence.encode()).hexdigest()
        
        entry = FalsePositiveEntry(
            vulnerability_type=alert.vulnerability.type,
            endpoint=alert.vulnerability.endpoint,
            evidence_hash=evidence_hash,
            marked_by=marked_by,
            timestamp=datetime.now()
        )
        
        self.entries.append(entry)
        logger.info(f"Marked false positive: {alert.vulnerability.type} at {alert.vulnerability.endpoint}")
    
    def is_false_positive(self, vulnerability: Vulnerability) -> bool:
        """Check if vulnerability is a known false positive"""
        evidence_hash = hashlib.sha256(vulnerability.evidence.encode()).hexdigest()
        
        for entry in self.entries:
            if (entry.vulnerability_type == vulnerability.type and
                entry.endpoint == vulnerability.endpoint and
                entry.evidence_hash == evidence_hash):
                return True
        
        return False
    
    def load(self, db_path: str) -> None:
        """Load false positive database from disk"""
        try:
            path = Path(db_path)
            if not path.exists():
                logger.info(f"False positive database not found at {db_path}, starting with empty database")
                return
            
            with open(db_path, 'r') as f:
                data = json.load(f)
            
            self.entries = []
            for entry_data in data.get('entries', []):
                entry = FalsePositiveEntry(
                    vulnerability_type=entry_data['vulnerability_type'],
                    endpoint=entry_data['endpoint'],
                    evidence_hash=entry_data['evidence_hash'],
                    marked_by=entry_data['marked_by'],
                    timestamp=datetime.fromisoformat(entry_data['timestamp'])
                )
                self.entries.append(entry)
            
            logger.info(f"Loaded {len(self.entries)} false positive entries from {db_path}")
        
        except Exception as e:
            logger.error(f"Error loading false positive database: {e}")
            self.entries = []
    
    def save(self, db_path: str) -> None:
        """Persist false positive database to disk"""
        try:
            # Ensure directory exists
            path = Path(db_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            
            data = {
                'version': '1.0',
                'entries': [
                    {
                        'vulnerability_type': entry.vulnerability_type,
                        'endpoint': entry.endpoint,
                        'evidence_hash': entry.evidence_hash,
                        'marked_by': entry.marked_by,
                        'timestamp': entry.timestamp.isoformat()
                    }
                    for entry in self.entries
                ]
            }
            
            with open(db_path, 'w') as f:
                json.dump(data, f, indent=2)
            
            logger.info(f"Saved {len(self.entries)} false positive entries to {db_path}")
        
        except Exception as e:
            logger.error(f"Error saving false positive database: {e}")
            raise
