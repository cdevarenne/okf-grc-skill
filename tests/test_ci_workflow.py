"""The CI workflow must never run on its own, and must pin third-party actions."""

import re
from pathlib import Path
from typing import Any

import yaml

WORKFLOW = Path(__file__).parent.parent / ".github" / "workflows" / "ci.yml"


def _workflow() -> dict[Any, Any]:
    return yaml.safe_load(WORKFLOW.read_text())


def test_workflow_is_manual_only() -> None:
    wf = _workflow()
    triggers = wf.get("on", wf.get(True))  # PyYAML reads a bare `on:` key as True
    assert set(triggers) == {"workflow_dispatch"}


def test_actions_are_pinned_to_commits() -> None:
    uses = re.findall(r"uses:\s*(\S+)", WORKFLOW.read_text())
    assert uses and all(re.search(r"@[0-9a-f]{40}$", action) for action in uses)


def test_token_is_read_only() -> None:
    assert _workflow()["permissions"] == {"contents": "read"}


def test_runs_bootstrap_then_tests() -> None:
    steps = [s["run"] for s in _workflow()["jobs"]["test"]["steps"] if "run" in s]
    assert steps == ["make bootstrap", "make test"]
