import json
from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime

REPORT_SCHEMA_VERSION = 1


@dataclass
class Report:
    target: str
    findings: list
    metadata: dict = field(default_factory=dict)
    generated: str = field(
        default_factory=lambda: datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S")
    )

    def summary(self):
        counts = Counter(f.category for f in self.findings)
        severity_counts = Counter(f.severity.casefold() for f in self.findings)

        return {
            "generated": self.generated,
            "target": self.target,
            "total": len(self.findings),
            "critical": severity_counts["critical"],
            "high": severity_counts["high"],
            "medium": severity_counts["medium"],
            "low": severity_counts["low"],
            "info": severity_counts["info"],
            "categories": dict(counts),
        }

    def to_json(self):
        return json.dumps(
            {
                "schema_version": REPORT_SCHEMA_VERSION,
                "metadata": self.metadata,
                "summary": self.summary(),
                "findings": [vars(f) for f in self.findings],
            },
            indent=2,
        )
