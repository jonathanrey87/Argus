"""Shared identity helpers for normalized security findings."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import PurePath

FINGERPRINT_VERSION = 1


def fingerprint(category: str, file: str, evidence: str) -> str:
    """Create a checkout-independent identity for a finding across scans."""
    normalized_category = " ".join(category.casefold().split())
    normalized_file = PurePath(file).as_posix().casefold()
    normalized_evidence = re.sub(r"\s+", " ", evidence).strip()
    identity = "\0".join(
        (
            str(FINGERPRINT_VERSION),
            normalized_category,
            normalized_file,
            normalized_evidence,
        )
    )
    return f"asx-{hashlib.sha256(identity.encode('utf-8')).hexdigest()[:24]}"


@dataclass
class Finding:
    """Normalized finding shared by native analyzers and external importers."""

    category: str
    severity: str
    file: str
    full_path: str
    line: int
    evidence: str
    note: str
    confidence: int = 50
    reason: str = ""
    source: str = "astranyx"
    rule_id: str = ""
    fingerprint: str = field(init=False)

    def __post_init__(self):
        identity = self.rule_id or self.category
        self.fingerprint = fingerprint(identity, self.file, self.evidence)
