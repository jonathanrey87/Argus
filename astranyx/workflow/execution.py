"""Durable plan-to-report workflow with explicit separation of duties."""

from __future__ import annotations

import hashlib
import json
import os
import secrets
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from astranyx.evidence import EvidenceError, verify_bundle

MAX_DOCUMENT_BYTES = 10_485_760
TRANSITIONS = {
    "planned": {"approved"},
    "approved": {"executing"},
    "executing": {"verified"},
    "verified": {"reported"},
    "reported": set(),
}


class WorkflowError(RuntimeError):
    """Raised when a workflow transition is invalid or unsafe."""


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _actor(value: str) -> str:
    normalized = value.strip()
    if not 1 <= len(normalized) <= 200 or any(ord(item) < 32 for item in normalized):
        raise WorkflowError("actor identity must be a bounded printable value")
    return normalized


def _moment(value: datetime | None = None) -> datetime:
    result = value or datetime.now(UTC)
    if result.tzinfo is None:
        raise WorkflowError("workflow timestamps must include a timezone")
    return result.astimezone(UTC)


class ValidationWorkflow:
    """Manage atomic workflow state; never executes commands or network requests."""

    schema_version = 1

    def __init__(self, workspace: str | Path):
        self.workspace = Path(workspace).expanduser()
        self.state_path = self.workspace / "workflow.json"
        self.lock_path = self.workspace / ".workflow.lock"

    @contextmanager
    def _lock(self):
        flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(self.lock_path, flags, 0o600)
        os.fchmod(descriptor, 0o600)
        try:
            if os.name == "nt":
                import msvcrt

                if os.fstat(descriptor).st_size == 0:
                    os.write(descriptor, b"\0")
                os.lseek(descriptor, 0, os.SEEK_SET)
                msvcrt.locking(descriptor, msvcrt.LK_LOCK, 1)
            else:
                import fcntl

                fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            if os.name == "nt":
                import msvcrt

                os.lseek(descriptor, 0, os.SEEK_SET)
                msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    def _load(self) -> dict[str, Any]:
        try:
            if self.state_path.is_symlink():
                raise WorkflowError("workflow state must not be a symbolic link")
            if self.state_path.stat().st_size > MAX_DOCUMENT_BYTES:
                raise WorkflowError("workflow state exceeds 10 MiB")
            state = json.loads(self.state_path.read_text(encoding="utf-8"))
        except WorkflowError:
            raise
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise WorkflowError(f"unable to load workflow state: {exc}") from exc
        self._verify_state(state)
        return state

    def _verify_state(self, state: Any) -> None:
        if (
            not isinstance(state, dict)
            or state.get("schema_version") != self.schema_version
        ):
            raise WorkflowError("unsupported or malformed workflow state")
        events = state.get("events")
        if not isinstance(events, list) or not events:
            raise WorkflowError("workflow event chain is missing")
        previous = "0" * 64
        for index, sealed in enumerate(events, start=1):
            if not isinstance(sealed, dict):
                raise WorkflowError("malformed workflow event")
            event = dict(sealed)
            digest = event.pop("hash", None)
            if event.get("index") != index or event.get("previous_hash") != previous:
                raise WorkflowError("workflow event-chain discontinuity")
            calculated = _digest(_canonical(event))
            if digest != calculated:
                raise WorkflowError("workflow event hash mismatch")
            previous = calculated
        if state.get("event_head") != previous or state.get("revision") != len(events):
            raise WorkflowError("workflow state checkpoint mismatch")
        actions = [event.get("action") for event in events]
        expected = ["create", "approve", "begin", "verify", "report"][: len(events)]
        if actions != expected or len(events) > 5:
            raise WorkflowError("invalid workflow transition history")
        status = ["planned", "approved", "executing", "verified", "reported"][
            len(events) - 1
        ]
        create = events[0]
        if (
            state.get("status") != status
            or state.get("creator") != create.get("actor")
            or state.get("plan_id") != create.get("data", {}).get("plan_id")
            or state.get("plan_sha256") != create.get("data", {}).get("plan_sha256")
            or state.get("workflow_id") != create.get("data", {}).get("workflow_id")
        ):
            raise WorkflowError("workflow state does not match its event chain")
        derived = {
            "approver": events[1]["actor"] if len(events) > 1 else None,
            "approval_expires_at": (
                events[1]["data"].get("expires_at") if len(events) > 1 else None
            ),
            "executor": events[2]["actor"] if len(events) > 2 else None,
            "verifier": events[3]["actor"] if len(events) > 3 else None,
            "evidence_manifest_sha256": (
                events[3]["data"].get("evidence_manifest_sha256")
                if len(events) > 3
                else None
            ),
            "evidence_bundle": (
                events[3]["data"].get("evidence_bundle") if len(events) > 3 else None
            ),
            "report_sha256": (
                events[4]["data"].get("report_sha256") if len(events) > 4 else None
            ),
        }
        if any(state.get(key) != value for key, value in derived.items()):
            raise WorkflowError("workflow cached fields do not match the event chain")

    def _write(self, state: dict[str, Any]) -> None:
        payload = json.dumps(state, indent=2, sort_keys=True).encode() + b"\n"
        if len(payload) > MAX_DOCUMENT_BYTES:
            raise WorkflowError("workflow state exceeds 10 MiB")
        temporary = (
            self.workspace / f".workflow.tmp-{os.getpid()}-{secrets.token_hex(8)}"
        )
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(temporary, flags, 0o600)
        try:
            view = memoryview(payload)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise WorkflowError("workflow write made no progress")
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(temporary, self.state_path)

    @staticmethod
    def _load_plan(path: str | Path, plan_id: str | None) -> tuple[dict[str, Any], str]:
        source = Path(path).expanduser()
        try:
            if source.stat().st_size > MAX_DOCUMENT_BYTES:
                raise WorkflowError("validation plan exceeds 10 MiB")
            document = json.loads(source.read_text(encoding="utf-8"))
        except WorkflowError:
            raise
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise WorkflowError(f"unable to load validation plan: {exc}") from exc
        plans = document.get("plans") if isinstance(document, dict) else None
        if (
            not isinstance(document, dict)
            or document.get("schema_version") != 1
            or not isinstance(plans, list)
        ):
            raise WorkflowError("unsupported validation-plan document")
        selected = [
            item
            for item in plans
            if isinstance(item, dict) and (plan_id is None or item.get("id") == plan_id)
        ]
        if len(selected) != 1:
            raise WorkflowError("select exactly one validation plan")
        plan = selected[0]
        if (
            plan.get("execution_allowed") is not False
            or plan.get("status") != "planned"
        ):
            raise WorkflowError("workflow requires a non-executing planned validation")
        return plan, _digest(_canonical(plan))

    @staticmethod
    def _event(
        index: int,
        previous: str,
        action: str,
        actor: str,
        at: datetime,
        data: dict[str, Any],
    ) -> dict[str, Any]:
        event = {
            "index": index,
            "timestamp": at.isoformat(),
            "action": action,
            "actor": actor,
            "data": data,
            "previous_hash": previous,
        }
        return {**event, "hash": _digest(_canonical(event))}

    @classmethod
    def create(
        cls,
        plan_path: str | Path,
        workspace: str | Path,
        *,
        creator: str,
        plan_id: str | None = None,
        now: datetime | None = None,
    ) -> ValidationWorkflow:
        plan, plan_sha256 = cls._load_plan(plan_path, plan_id)
        root = Path(workspace).expanduser()
        try:
            root.mkdir(parents=True, exist_ok=False)
            os.chmod(root, 0o700)
            workflow = cls(root)
            actor = _actor(creator)
            timestamp = _moment(now)
            workflow_id = f"wf-{secrets.token_hex(12)}"
            event = cls._event(
                1,
                "0" * 64,
                "create",
                actor,
                timestamp,
                {
                    "workflow_id": workflow_id,
                    "plan_id": plan["id"],
                    "plan_sha256": plan_sha256,
                },
            )
            state = {
                "schema_version": 1,
                "workflow_id": workflow_id,
                "plan_id": plan["id"],
                "plan_sha256": plan_sha256,
                "status": "planned",
                "creator": actor,
                "approver": None,
                "executor": None,
                "verifier": None,
                "approval_expires_at": None,
                "evidence_bundle": None,
                "evidence_manifest_sha256": None,
                "report_sha256": None,
                "revision": 1,
                "event_head": event["hash"],
                "events": [event],
            }
            workflow._write(state)
            return workflow
        except Exception:
            if root.exists() and not any(root.iterdir()):
                root.rmdir()
            raise

    def _transition(
        self,
        state: dict[str, Any],
        target: str,
        action: str,
        actor: str,
        at: datetime,
        data: dict[str, Any],
    ) -> dict[str, Any]:
        if target not in TRANSITIONS[state["status"]]:
            raise WorkflowError(
                f"invalid workflow transition: {state['status']} -> {target}"
            )
        event = self._event(
            state["revision"] + 1, state["event_head"], action, actor, at, data
        )
        state["events"].append(event)
        state["revision"] += 1
        state["event_head"] = event["hash"]
        state["status"] = target
        return state

    def approve(
        self, *, approver: str, valid_hours: int = 8, now: datetime | None = None
    ) -> dict[str, Any]:
        if not 1 <= valid_hours <= 168:
            raise WorkflowError("approval validity must be between 1 and 168 hours")
        with self._lock():
            state = self._load()
            actor, timestamp = _actor(approver), _moment(now)
            if actor == state["creator"]:
                raise WorkflowError("creator and approver must be different actors")
            expires = timestamp + timedelta(hours=valid_hours)
            state = self._transition(
                state,
                "approved",
                "approve",
                actor,
                timestamp,
                {"expires_at": expires.isoformat()},
            )
            state["approver"] = actor
            state["approval_expires_at"] = expires.isoformat()
            self._write(state)
            return state

    def begin(self, *, executor: str, now: datetime | None = None) -> dict[str, Any]:
        with self._lock():
            state = self._load()
            actor, timestamp = _actor(executor), _moment(now)
            if state["status"] != "approved":
                raise WorkflowError(
                    f"invalid workflow transition: {state['status']} -> executing"
                )
            if actor in {state["creator"], state["approver"]}:
                raise WorkflowError(
                    "executor must be independent from creator and approver"
                )
            expires = datetime.fromisoformat(state["approval_expires_at"])
            if timestamp >= expires:
                raise WorkflowError("workflow approval has expired")
            state = self._transition(
                state,
                "executing",
                "begin",
                actor,
                timestamp,
                {
                    "authority": "bounded validation only; no command execution delegated"
                },
            )
            state["executor"] = actor
            self._write(state)
            return state

    def verify(
        self, evidence_bundle: str | Path, *, verifier: str, now: datetime | None = None
    ) -> dict[str, Any]:
        if self.status()["status"] != "executing":
            raise WorkflowError(
                "workflow must be executing before evidence verification"
            )
        try:
            evidence = verify_bundle(evidence_bundle)
        except EvidenceError as exc:
            raise WorkflowError(str(exc)) from exc
        if not evidence["valid"]:
            raise WorkflowError("evidence bundle failed integrity verification")
        manifest_sha256 = evidence["manifest_sha256"]
        with self._lock():
            state = self._load()
            if state["status"] != "executing":
                raise WorkflowError(
                    "workflow state changed before evidence verification"
                )
            actor, timestamp = _actor(verifier), _moment(now)
            if timestamp >= datetime.fromisoformat(state["approval_expires_at"]):
                raise WorkflowError("workflow approval expired before verification")
            if actor in {state["creator"], state["approver"], state["executor"]}:
                raise WorkflowError(
                    "verifier must be independent from prior workflow actors"
                )
            if evidence["plan_id"] != state["plan_id"]:
                raise WorkflowError("evidence bundle is bound to a different plan")
            if evidence["plan_sha256"] != state["plan_sha256"]:
                raise WorkflowError(
                    "evidence bundle is bound to different plan content"
                )
            state = self._transition(
                state,
                "verified",
                "verify",
                actor,
                timestamp,
                {
                    "evidence_manifest_sha256": manifest_sha256,
                    "evidence_bundle": str(
                        Path(evidence_bundle).expanduser().resolve()
                    ),
                },
            )
            state["verifier"] = actor
            state["evidence_bundle"] = str(Path(evidence_bundle).expanduser().resolve())
            state["evidence_manifest_sha256"] = manifest_sha256
            self._write(state)
            return state

    def report(
        self, output: str | Path, *, reporter: str, now: datetime | None = None
    ) -> dict[str, Any]:
        preliminary = self.status()
        if preliminary["status"] != "verified":
            raise WorkflowError(
                f"invalid workflow transition: {preliminary['status']} -> reported"
            )
        try:
            evidence = verify_bundle(preliminary["evidence_bundle"])
        except EvidenceError as exc:
            raise WorkflowError(str(exc)) from exc
        if (
            not evidence["valid"]
            or evidence["manifest_sha256"] != preliminary["evidence_manifest_sha256"]
        ):
            raise WorkflowError("evidence changed after workflow verification")
        with self._lock():
            state = self._load()
            if (
                state["status"] != "verified"
                or state["event_head"] != preliminary["event_head"]
            ):
                raise WorkflowError("workflow state changed before reporting")
            actor, timestamp = _actor(reporter), _moment(now)
            report = {
                "schema_version": 1,
                "workflow_id": state["workflow_id"],
                "plan_id": state["plan_id"],
                "status": "reported",
                "plan_sha256": state["plan_sha256"],
                "evidence_manifest_sha256": state["evidence_manifest_sha256"],
                "actors": {
                    "creator": state["creator"],
                    "approver": state["approver"],
                    "executor": state["executor"],
                    "verifier": state["verifier"],
                    "reporter": actor,
                },
                "event_head_before_report": state["event_head"],
                "reported_at": timestamp.isoformat(),
            }
            destination = Path(output).expanduser()
            if destination.exists() or destination.is_symlink():
                raise WorkflowError("refusing to overwrite an existing workflow report")
            payload = json.dumps(report, indent=2, sort_keys=True).encode() + b"\n"
            report_sha256 = _digest(payload)
            state = self._transition(
                state,
                "reported",
                "report",
                actor,
                timestamp,
                {"report_sha256": report_sha256},
            )
            flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(destination, flags, 0o600)
            try:
                view = memoryview(payload)
                while view:
                    written = os.write(descriptor, view)
                    if written <= 0:
                        raise WorkflowError("workflow report write made no progress")
                    view = view[written:]
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            state["report_sha256"] = report_sha256
            self._write(state)
            return report

    def status(self) -> dict[str, Any]:
        with self._lock():
            return self._load()
