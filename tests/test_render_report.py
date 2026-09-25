import json
from pathlib import Path

from map_findings import map_findings
from okf_lib import load_bundle
from render_report import render_report

FIXTURES = Path(__file__).parent / "fixtures"


def test_report_matches_golden() -> None:
    bundle = load_bundle(FIXTURES / "bundle")
    mapping = map_findings(bundle, json.loads((FIXTURES / "findings.json").read_text()))
    report = render_report(bundle, mapping, "2026-09-25T12:00:00+00:00")
    assert report == (FIXTURES / "report.golden.md").read_text()


def test_remediation_line_is_omitted_without_remediation_text(tmp_path: Path) -> None:
    for rel, fm in {
        "controls/cc6.1.md": "type: SOC 2 Control\ntitle: CC6.1\ntags: [cc6.1]",
        "policies/p.md": 'type: Rego Policy\ntitle: P\ntags: [cc6.1]\nrule_ids: ["conftest:p"]',
    }.items():
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text(f"---\n{fm}\n---\n", encoding="utf-8")
    bundle = load_bundle(tmp_path)
    finding = {"tool": "conftest", "rule_id": "p", "severity": "high", "target": "t", "message": "m", "tags": []}
    report = render_report(bundle, map_findings(bundle, [finding]), "2026-09-25T12:00:00+00:00")
    assert "Open findings" in report and "Remediation" not in report
