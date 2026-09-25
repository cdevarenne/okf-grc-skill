"""The grounding gate: findings reach a control only through a declared rule."""

import json
from pathlib import Path

import pytest

from map_findings import map_findings
from okf_lib import load_bundle

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def mapping() -> dict:
    findings = json.loads((FIXTURES / "findings.json").read_text())
    return map_findings(load_bundle(FIXTURES / "bundle"), findings)


def _rules(findings: list[dict]) -> list[str]:
    return [f["rule_id"] for f in findings]


def test_every_bundle_control_is_reported(mapping: dict) -> None:
    assert sorted(mapping["controls"]) == ["cc6.1", "cc7.1", "cc7.2", "cc8.1"]


def test_declared_rules_map_to_their_control(mapping: dict) -> None:
    assert _rules(mapping["controls"]["cc6.1"]["findings"]) == ["require_non_root", "CKV_TEST_1"]


def test_glob_rule_maps_cve(mapping: dict) -> None:
    assert _rules(mapping["controls"]["cc7.1"]["findings"]) == ["CVE-2024-0001"]


def test_undeclared_rule_is_a_gap_not_a_mapping(mapping: dict) -> None:
    gaps = {g["finding"]["rule_id"]: g["reason"] for g in mapping["unmapped"]}
    assert gaps["CKV_TEST_99"] == "no-rule-match"
    assert all("CKV_TEST_99" not in _rules(c["findings"]) for c in mapping["controls"].values())


def test_control_missing_from_bundle_is_a_gap(mapping: dict) -> None:
    gaps = {g["finding"]["rule_id"]: g["reason"] for g in mapping["unmapped"]}
    assert gaps["orphan_rule"] == "control-not-in-bundle"
    assert "cc9.9" not in mapping["controls"]


def test_statuses(mapping: dict) -> None:
    status = {code: c["status"] for code, c in mapping["controls"].items()}
    assert status == {
        "cc6.1": "not-satisfied",
        "cc7.1": "not-satisfied",
        "cc7.2": "not-assessed",
        "cc8.1": "no-violations-detected",
    }


def test_evidence_links(mapping: dict) -> None:
    assert mapping["controls"]["cc7.1"]["evidenced_by"] == ["scanners/trivy"]
    assert mapping["controls"]["cc8.1"]["satisfied_by"] == ["policies/deny-latest-tag"]
