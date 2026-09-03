import json
import sys

import pytest

from astranyx.cli import main


def write_policy(tmp_path):
    path = tmp_path / "engagement.json"
    path.write_text(
        json.dumps(
            {
                "engagement_id": "test-engagement",
                "authorization_reference": "written authorization",
                "targets": [
                    {
                        "pattern": "admin.example.test",
                        "schemes": ["https"],
                        "ports": [443],
                    }
                ],
                "mode": "safe_active",
                "allowed_methods": ["GET"],
                "max_requests_per_second": 2,
                "user_agent": "researcher-test",
            }
        ),
        encoding="utf-8",
    )
    return path


def test_cli_authorize_allows_in_scope(tmp_path, monkeypatch, capsys):
    policy = write_policy(tmp_path)
    monkeypatch.setattr(
        sys,
        "argv",
        ["astranyx", "engagement", "authorize", str(policy), "https://admin.example.test/"],
    )
    main()
    result = json.loads(capsys.readouterr().out)
    assert result["allowed"] is True
    assert result["matched_scope"] == "admin.example.test"


def test_cli_authorize_denies_out_of_scope(tmp_path, monkeypatch, capsys):
    policy = write_policy(tmp_path)
    monkeypatch.setattr(
        sys,
        "argv",
        ["astranyx", "engagement", "authorize", str(policy), "https://outside.example/"],
    )
    with pytest.raises(SystemExit) as exc_info:
        main()
    assert exc_info.value.code == 2
    result = json.loads(capsys.readouterr().out)
    assert result["allowed"] is False
