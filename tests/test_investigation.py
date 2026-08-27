import json

from astranyx import __version__
from astranyx.investigation.manager import InvestigationManager
from astranyx.investigation.run import (
    _unique_workspace_root,
    run,
)

EXPECTED_DIRECTORIES = {
    "analysis",
    "api",
    "evidence",
    "html",
    "js",
    "logs",
    "notes",
    "reports",
    "screenshots",
}


def create_investigation(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    run(None)

    workspaces = list((tmp_path / "investigations").glob("INV-*"))

    assert len(workspaces) == 1
    return workspaces[0]


def test_create_investigation_workspace(
    tmp_path,
    monkeypatch,
):
    workspace = create_investigation(
        tmp_path,
        monkeypatch,
    )

    directories = {path.name for path in workspace.iterdir() if path.is_dir()}

    assert directories == EXPECTED_DIRECTORIES

    metadata_path = workspace / "metadata.json"
    assert metadata_path.is_file()

    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))

    assert metadata["id"] == workspace.name
    assert metadata["status"] == "created"
    assert metadata["target"] is None
    assert metadata["analyst"] == "unspecified"
    assert metadata["astranyx_version"] == __version__
    assert metadata["trace_enabled"] is False
    assert metadata["modules"] == []
    assert metadata["findings"] == {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }


def test_investigation_manager_lifecycle(
    tmp_path,
    monkeypatch,
):
    workspace = create_investigation(
        tmp_path,
        monkeypatch,
    )

    manager = InvestigationManager(workspace)

    manager.set_target("authorized-test-target")
    manager.set_status("active")
    manager.add_module(
        "javascript",
        duration_ms=125,
        details={"files": 3},
    )
    manager.update_findings(
        high=1,
        medium=2,
        info=4,
    )
    manager.finish()

    reloaded = InvestigationManager(workspace)

    assert reloaded.data["target"] == ("authorized-test-target")
    assert reloaded.data["status"] == "completed"
    assert "completed" in reloaded.data

    assert reloaded.data["modules"] == [
        {
            "name": "javascript",
            "status": "completed",
            "completed": reloaded.data["modules"][0]["completed"],
            "duration_ms": 125,
            "files": 3,
        }
    ]

    assert reloaded.data["findings"] == {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 0,
        "info": 4,
    }


def test_unique_workspace_root(tmp_path):
    parent = tmp_path / "investigations"
    parent.mkdir()

    investigation_id = "INV-20260804-120000"

    first = _unique_workspace_root(
        parent,
        investigation_id,
    )
    assert first.name == investigation_id
    first.mkdir()

    second = _unique_workspace_root(
        parent,
        investigation_id,
    )
    assert second.name == (f"{investigation_id}-01")
    second.mkdir()

    third = _unique_workspace_root(
        parent,
        investigation_id,
    )
    assert third.name == (f"{investigation_id}-02")
