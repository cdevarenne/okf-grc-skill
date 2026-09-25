"""Join normalized findings to in-bundle SOC 2 controls; never invent a mapping."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from okf_lib import GUARDRAIL_TYPES, SCANNER_TYPE, Bundle, load_bundle

Finding = dict[str, Any]


def _controls_for(bundle: Bundle, finding: Finding) -> tuple[list[str], str | None]:
    """Control codes a finding maps to, or ([], reason) when it is a coverage gap."""
    declaring = bundle.by_rule(finding["tool"], finding["rule_id"])
    if not declaring:
        return [], "no-rule-match"
    codes = sorted({t for c in declaring for t in c.control_tags if bundle.control(t)})
    return (codes, None) if codes else ([], "control-not-in-bundle")


def _evidence(bundle: Bundle, code: str) -> tuple[list[str], list[str]]:
    """(evidenced_by, satisfied_by) for a control, derived only from `rule_ids` declarations."""
    declaring = bundle.declaring(code)
    tools = {entry.partition(":")[0] for c in declaring for entry in c.rule_ids}
    scanners = [c.id for c in bundle.of_type(SCANNER_TYPE) if c.code in tools]
    guardrails = [c.id for c in declaring if c.type in GUARDRAIL_TYPES]
    return scanners, guardrails


def map_findings(bundle: Bundle, findings: list[Finding]) -> dict[str, Any]:
    """Build the mapping document (spec §5.4) from a bundle and findings."""
    controls: dict[str, dict[str, Any]] = {}
    for c in bundle.controls():
        evidenced_by, satisfied_by = _evidence(bundle, c.code)
        controls[c.code] = {
            "status": "",
            "findings": [],
            "evidenced_by": evidenced_by,
            "satisfied_by": satisfied_by,
        }
    unmapped: list[dict[str, Any]] = []
    for finding in findings:
        codes, reason = _controls_for(bundle, finding)
        if reason:
            unmapped.append({"finding": finding, "reason": reason})
        for code in codes:
            controls[code]["findings"].append(finding)
    for entry in controls.values():
        if entry["findings"]:
            entry["status"] = "not-satisfied"
        elif entry["evidenced_by"] or entry["satisfied_by"]:
            entry["status"] = "no-violations-detected"
        else:
            entry["status"] = "not-assessed"
    return {"controls": controls, "unmapped": unmapped}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--knowledge", type=Path, default=Path("knowledge"))
    parser.add_argument("--out", type=Path, default=Path("out"))
    args = parser.parse_args()
    findings = json.loads((args.out / "findings.json").read_text(encoding="utf-8"))
    mapping = map_findings(load_bundle(args.knowledge), findings)
    (args.out / "mapping.json").write_text(json.dumps(mapping, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
