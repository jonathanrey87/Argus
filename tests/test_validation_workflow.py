import json
import sys
from datetime import UTC, datetime

import pytest

from astranyx.cli import main
from astranyx.evidence import capture_bundle
from astranyx.workflow import ValidationWorkflow, WorkflowError


def write_plan(path, plan_id="vp-1234567890abcdefabcd"):
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "execution_allowed": False,
                "plans": [
                    {"id": plan_id, "status": "planned", "execution_allowed": False}
                ],
            }
        )
    )


def evidence_for(tmp_path, plan):
    source = tmp_path / "evidence.txt"
    source.write_text("controlled result")
    bundle = tmp_path / "bundle"
    capture_bundle(plan, [source], bundle)
    return bundle


def test_complete_separated_workflow(tmp_path):
    plan = tmp_path / "plan.json"
    write_plan(plan)
    workflow = ValidationWorkflow.create(plan, tmp_path / "workflow", creator="planner")
    assert workflow.approve(approver="approver")["status"] == "approved"
    assert workflow.begin(executor="operator")["status"] == "executing"
    assert (
        workflow.verify(evidence_for(tmp_path, plan), verifier="reviewer")["status"]
        == "verified"
    )
    report = workflow.report(tmp_path / "report.json", reporter="reporter")
    state = workflow.status()
    assert report["status"] == "reported"
    assert state["status"] == "reported"
    assert state["revision"] == 5
    assert state["report_sha256"]


def test_rejects_invalid_transition_and_actor_reuse(tmp_path):
    plan = tmp_path / "plan.json"
    write_plan(plan)
    workflow = ValidationWorkflow.create(plan, tmp_path / "workflow", creator="planner")
    with pytest.raises(WorkflowError, match="transition"):
        workflow.begin(executor="operator")
    with pytest.raises(WorkflowError, match="different actors"):
        workflow.approve(approver="planner")
    workflow.approve(approver="approver")
    with pytest.raises(WorkflowError, match="independent"):
        workflow.begin(executor="approver")


def test_expired_approval_cannot_begin(tmp_path):
    plan = tmp_path / "plan.json"
    write_plan(plan)
    workflow = ValidationWorkflow.create(
        plan,
        tmp_path / "workflow",
        creator="planner",
        now=datetime(2026, 1, 1, tzinfo=UTC),
    )
    workflow.approve(
        approver="approver", valid_hours=1, now=datetime(2026, 1, 1, tzinfo=UTC)
    )
    with pytest.raises(WorkflowError, match="expired"):
        workflow.begin(executor="operator", now=datetime(2026, 1, 1, 1, tzinfo=UTC))


def test_execution_cannot_verify_after_approval_expiry(tmp_path):
    plan = tmp_path / "plan.json"
    write_plan(plan)
    workflow = ValidationWorkflow.create(
        plan,
        tmp_path / "workflow",
        creator="planner",
        now=datetime(2026, 1, 1, tzinfo=UTC),
    )
    workflow.approve(
        approver="approver",
        valid_hours=1,
        now=datetime(2026, 1, 1, tzinfo=UTC),
    )
    workflow.begin(executor="operator", now=datetime(2026, 1, 1, tzinfo=UTC))
    with pytest.raises(WorkflowError, match="expired before verification"):
        workflow.verify(
            evidence_for(tmp_path, plan),
            verifier="reviewer",
            now=datetime(2026, 1, 1, 1, tzinfo=UTC),
        )


def test_event_chain_tampering_is_detected(tmp_path):
    plan = tmp_path / "plan.json"
    write_plan(plan)
    workflow = ValidationWorkflow.create(plan, tmp_path / "workflow", creator="planner")
    state = json.loads(workflow.state_path.read_text())
    state["events"][0]["actor"] = "attacker"
    workflow.state_path.write_text(json.dumps(state))
    with pytest.raises(WorkflowError, match="hash mismatch"):
        workflow.status()


def test_cached_state_tampering_is_detected(tmp_path):
    plan = tmp_path / "plan.json"
    write_plan(plan)
    workflow = ValidationWorkflow.create(plan, tmp_path / "workflow", creator="planner")
    state = json.loads(workflow.state_path.read_text())
    state["status"] = "reported"
    workflow.state_path.write_text(json.dumps(state))
    with pytest.raises(WorkflowError, match="event chain"):
        workflow.status()


def test_report_rechecks_evidence_integrity(tmp_path):
    plan = tmp_path / "plan.json"
    write_plan(plan)
    workflow = ValidationWorkflow.create(plan, tmp_path / "workflow", creator="planner")
    workflow.approve(approver="approver")
    workflow.begin(executor="operator")
    bundle = evidence_for(tmp_path, plan)
    workflow.verify(bundle, verifier="reviewer")
    (bundle / "evidence" / "artifact-0001.txt").write_text("tampered")
    with pytest.raises(WorkflowError, match="changed"):
        workflow.report(tmp_path / "report.json", reporter="reporter")


def test_evidence_for_different_plan_is_rejected(tmp_path):
    plan = tmp_path / "plan.json"
    other = tmp_path / "other.json"
    write_plan(plan)
    write_plan(other, "vp-ffffffffffffffffffff")
    workflow = ValidationWorkflow.create(plan, tmp_path / "workflow", creator="planner")
    workflow.approve(approver="approver")
    workflow.begin(executor="operator")
    with pytest.raises(WorkflowError, match="different plan"):
        workflow.verify(evidence_for(tmp_path, other), verifier="reviewer")


def test_cli_create_and_status(tmp_path, monkeypatch, capsys):
    plan = tmp_path / "plan.json"
    workspace = tmp_path / "workflow"
    write_plan(plan)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "astranyx",
            "workflow",
            "create",
            str(plan),
            str(workspace),
            "--actor",
            "planner",
        ],
    )
    main()
    assert json.loads(capsys.readouterr().out)["status"] == "planned"
    monkeypatch.setattr(sys, "argv", ["astranyx", "workflow", "status", str(workspace)])
    main()
    assert json.loads(capsys.readouterr().out)["revision"] == 1
