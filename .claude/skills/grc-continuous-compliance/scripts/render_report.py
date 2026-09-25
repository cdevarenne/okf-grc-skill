"""Render the control mapping as an auditor-facing markdown report."""

from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from okf_lib import Bundle, load_bundle

Json = dict[str, Any]


def _link(bundle: Bundle, concept_id: str) -> str:
    concept = bundle.concepts[concept_id]
    return f"[{concept.title}](../knowledge/{concept.path})"


def _finding_line(f: Json) -> str:
    return f"- `{f['tool']}` `{f['rule_id']}` ({f['severity']}) — {f['message']} — `{f['target']}`"


def _remediation(bundle: Bundle, code: str, findings: list[Json]) -> str:
    """Join the `# Remediation` sections of concepts that declare these findings' rules for this control."""
    paragraphs: dict[str, None] = {}
    for f in findings:
        for concept in bundle.by_rule(f["tool"], f["rule_id"]):
            text = bundle.section(concept, "Remediation")
            if code in concept.control_tags and text:
                paragraphs[text] = None
    return " ".join(paragraphs)


def _control_section(bundle: Bundle, code: str, entry: Json) -> list[str]:
    control = bundle.control(code)
    evidence = [_link(bundle, cid) for cid in entry["evidenced_by"] + entry["satisfied_by"]]
    lines = [f"### {control.title if control else code}", "", f"**Status:** {entry['status']}", ""]
    lines += [f"**Evidence:** {', '.join(evidence) if evidence else 'none in bundle'}", ""]
    if entry["findings"]:
        lines += ["**Open findings:**", "", *map(_finding_line, entry["findings"]), ""]
        if remediation := _remediation(bundle, code, entry["findings"]):
            lines += [f"**Remediation:** {remediation}", ""]
    return lines


def render_report(bundle: Bundle, mapping: Json, now: str) -> str:
    """Markdown report: summary, per-control detail, coverage gaps, not-assessed controls."""
    controls = sorted(mapping["controls"].items())
    lines = [
        "# Compliance Scan Report",
        "",
        f"Generated {now}. Every status below is derived from scanner findings joined to",
        "controls declared in the OKF knowledge bundle; nothing is mapped without a declaration.",
        "`no-violations-detected` means automated checks found nothing for that control;",
        "it is evidence, not a control attestation.",
        "",
        "## Summary",
        "",
        "| Control | Status | Open findings |",
        "|---|---|---|",
    ]
    for code, entry in controls:
        lines.append(f"| {code} | {entry['status']} | {len(entry['findings'])} |")
    lines += ["", "## Controls", ""]
    for code, entry in controls:
        if entry["status"] != "not-assessed":
            lines += _control_section(bundle, code, entry)
    lines += ["## Coverage gaps", ""]
    if mapping["unmapped"]:
        lines += ["Findings with no in-bundle control. These are gaps to close, not mappings to invent.", ""]
        lines += [f"{_finding_line(u['finding'])} — reason: `{u['reason']}`" for u in mapping["unmapped"]]
    else:
        lines.append("None.")
    lines += ["", "## Not assessed", ""]
    not_assessed = [code for code, entry in controls if entry["status"] == "not-assessed"]
    for code in not_assessed:
        control = bundle.control(code)
        lines.append(f"- {control.title if control else code}: no in-bundle scanner or policy evidences this control.")
    if not not_assessed:
        lines.append("None.")
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--knowledge", type=Path, default=Path("knowledge"))
    parser.add_argument("--out", type=Path, default=Path("out"))
    parser.add_argument("--now", default=datetime.now(UTC).isoformat(timespec="seconds"))
    args = parser.parse_args()
    mapping = json.loads((args.out / "mapping.json").read_text(encoding="utf-8"))
    report = render_report(load_bundle(args.knowledge), mapping, args.now)
    (args.out / "report.md").write_text(report, encoding="utf-8")


if __name__ == "__main__":
    main()
