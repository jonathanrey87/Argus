"""Secure one-command assessment orchestration."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from astranyx.core.finding import REVIEW_STATES
from astranyx.importers import mobsf
from astranyx.investigation import integrity

MAX_REVIEW_BYTES = 5 * 1024 * 1024


class AssessmentError(RuntimeError):
    """Raised when an assessment cannot be completed safely."""


def _load_reviews(path: str | Path | None) -> dict[str, dict[str, str]]:
    if path is None:
        return {}
    review_path = Path(path)
    try:
        if review_path.stat().st_size > MAX_REVIEW_BYTES:
            raise AssessmentError("review file exceeds the 5 MiB safety limit")
        payload = json.loads(review_path.read_text(encoding="utf-8"))
    except AssessmentError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise AssessmentError(f"unable to read review file: {exc}") from exc
    if not isinstance(payload, dict):
        raise AssessmentError("invalid review file: root must be an object")
    if payload.get("schema_version") != 1:
        raise AssessmentError("invalid review file: schema_version must be 1")

    reviews = payload.get("reviews")
    if not isinstance(reviews, dict):
        raise AssessmentError("invalid review file: reviews must be an object")
    normalized = {}
    for fingerprint, decision in reviews.items():
        if not isinstance(fingerprint, str) or not fingerprint.startswith("asx-"):
            raise AssessmentError("invalid review fingerprint")
        if not isinstance(decision, dict):
            raise AssessmentError(f"invalid review decision for {fingerprint}")
        state = decision.get("state")
        note = decision.get("note", "")
        if state not in REVIEW_STATES:
            choices = ", ".join(sorted(REVIEW_STATES))
            raise AssessmentError(
                f"invalid review state for {fingerprint}; choose one of: {choices}"
            )
        if not isinstance(note, str):
            raise AssessmentError(f"invalid review note for {fingerprint}")
        normalized[fingerprint] = {"state": state, "note": note[:4_000]}
    return normalized


def _apply_reviews(findings: list[Any], reviews: dict[str, dict[str, str]]) -> None:
    by_fingerprint = {finding.fingerprint: finding for finding in findings}
    unknown = sorted(reviews.keys() - by_fingerprint.keys())
    if unknown:
        raise AssessmentError(f"review references unknown finding: {unknown[0]}")
    for fingerprint, decision in reviews.items():
        finding = by_fingerprint[fingerprint]
        finding.review_state = decision["state"]
        finding.review_note = decision["note"]


def _state_counts(findings: list[Any]) -> dict[str, int]:
    return {
        state: sum(1 for finding in findings if finding.review_state == state)
        for state in sorted(REVIEW_STATES)
    }


def run(
    report: str | Path,
    output: str | Path,
    *,
    client: str = "",
    consultant: str = "",
    assessment_title: str = "",
    review_file: str | Path | None = None,
) -> dict[str, Any]:
    """Import, review, seal, and verify one MobSF assessment."""
    try:
        metadata, findings = mobsf.load(report)
        reviews = _load_reviews(review_file)
        _apply_reviews(findings, reviews)
        result = mobsf.write_report(
            metadata,
            findings,
            output,
            client=client,
            consultant=consultant,
            assessment_title=assessment_title,
        )
        verification = integrity.verify(output)
    except (mobsf.MobSFImportError, integrity.IntegrityError) as exc:
        raise AssessmentError(str(exc)) from exc
    if not verification["valid"]:
        raise AssessmentError(
            "generated assessment bundle failed integrity verification"
        )
    return {
        **result,
        "review_states": _state_counts(findings),
        "integrity_verified": True,
    }
