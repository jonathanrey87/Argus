import sys
import tomllib
from pathlib import Path

import pytest

from astranyx import __version__
from astranyx.cli import main


def test_source_and_package_versions_match():
    project = tomllib.loads(
        (Path(__file__).parents[1] / "pyproject.toml").read_text(encoding="utf-8")
    )

    assert project["project"]["version"] == __version__


def test_cli_version(
    monkeypatch,
    capsys,
):
    monkeypatch.delenv(
        "ARIZE_SPACE_ID",
        raising=False,
    )
    monkeypatch.delenv(
        "ARIZE_API_KEY",
        raising=False,
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["astranyx", "--version"],
    )

    with pytest.raises(SystemExit) as exc_info:
        main()

    assert exc_info.value.code == 0
    assert capsys.readouterr().out.strip() == (f"astranyx {__version__}")
