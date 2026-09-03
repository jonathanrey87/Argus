"""Shared identity helpers for normalized security findings."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import PurePath

from astranyx.mobile.masvs import infer_group
from astranyx.scoring.cvss import assess

FINGERPRINT_VERSION = 1
REVIEW_STATES = {
    "accepted_risk",
    "confirmed",
    "needs_validation",
    "not_tested",
    "rejected",
}
CVSS_SOURCES = {"analyzer", "manual", "not_assessed", "upstream"}


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
    review_state: str = "needs_validation"
    review_note: str = ""
    masvs: list[str] = field(default_factory=list)
    masvs_mapping: str = "unmapped"
    cvss_vector: str = ""
    cvss_score: float | None = None
    cvss_severity: str | None = None
    cvss_source: str = "not_assessed"
    fingerprint: str = field(init=False)

    def __post_init__(self):
        identity = self.rule_id or self.category
        self.fingerprint = fingerprint(identity, self.file, self.evidence)
        if not self.masvs:
            self.masvs = infer_group(self.rule_id, self.category, self.reason)
            if self.masvs:
                self.masvs_mapping = "inferred"
        if self.cvss_source not in CVSS_SOURCES:
            raise ValueError(f"invalid CVSS source: {self.cvss_source}")
        if self.cvss_vector:
            if self.cvss_source == "not_assessed":
                raise ValueError("a CVSS vector requires explicit provenance")
            result = assess(self.cvss_vector)
            self.cvss_vector = result.vector
            self.cvss_score = result.score
            self.cvss_severity = result.severity
        elif self.cvss_source != "not_assessed":
            raise ValueError("CVSS provenance requires a vector")
        else:
            self.cvss_score = None
            self.cvss_severity = None

    def assess_cvss(self, vector: str, source: str = "manual") -> None:
        """Attach a validated score without inferring any missing metric."""
        if source not in CVSS_SOURCES - {"not_assessed"}:
            raise ValueError(f"invalid CVSS source: {source}")
        result = assess(vector)
        self.cvss_vector = result.vector
        self.cvss_score = result.score
        self.cvss_severity = result.severity
        self.cvss_source = source
