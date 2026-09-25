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
