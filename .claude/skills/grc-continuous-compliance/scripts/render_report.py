"""Render the control mapping as an auditor-facing markdown report."""

from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from okf_lib import Bundle, load_bundle

Json = dict[str, Any]

SEVERITIES = ("critical", "high", "medium", "low")  # known severities, ordered high-to-low
UNCLASSIFIED = "unclassified"  # a finding the scanner did not severity-rank


def _bucket(severity: str) -> str:
    """Map a scanner severity to a known bucket, or 'unclassified'."""
    s = (severity or "").strip().lower()
    return s if s in SEVERITIES else UNCLASSIFIED


def _counts(findings: list[Json]) -> dict[str, int]:
    """Count findings per severity bucket."""
    counts = dict.fromkeys((*SEVERITIES, UNCLASSIFIED), 0)
    for f in findings:
        counts[_bucket(f["severity"])] += 1
    return counts


def _breakdown(counts: dict[str, int]) -> str:
    """One-line severity breakdown, e.g. '3 critical, 16 high'. Empty buckets are omitted."""
    parts = [f"{counts[s]} {s}" for s in (*SEVERITIES, UNCLASSIFIED) if counts[s]]
    return ", ".join(parts) if parts else "no findings"


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
    if entry["findings"]:
        lines += [f"**Findings:** {_breakdown(_counts(entry['findings']))}", ""]
    lines += [f"**Evidence:** {', '.join(evidence) if evidence else 'none in bundle'}", ""]
    if entry["findings"]:
        lines += ["**Open findings:**", "", *map(_finding_line, entry["findings"]), ""]
        if remediation := _remediation(bundle, code, entry["findings"]):
            lines += [f"**Remediation:** {remediation}", ""]
    return lines


def _risk_posture(controls: list[tuple[str, Json]], unmapped: list[Json]) -> list[str]:
    """A one-glance summary: open findings by severity, control status counts, and coverage gaps."""
    total = dict.fromkeys((*SEVERITIES, UNCLASSIFIED), 0)
    open_findings = not_satisfied = not_assessed = clean = 0
    for _code, entry in controls:
        status = entry["status"]
        if status == "not-assessed":
            not_assessed += 1
        elif status == "not-satisfied":
            not_satisfied += 1
        else:
            clean += 1
        for f in entry["findings"]:
            total[_bucket(f["severity"])] += 1
            open_findings += 1
    findings_word = "finding" if open_findings == 1 else "findings"
    controls_word = "control" if len(controls) == 1 else "controls"
    clean_clause = "control shows" if clean == 1 else "controls show"
    gaps_word = "coverage gap" if len(unmapped) == 1 else "coverage gaps"
    return [
        "## Risk posture",
        "",
        f"{open_findings} open {findings_word} across {not_satisfied} of {len(controls)} {controls_word}: "
        f"{_breakdown(total)}.",
        f"{clean} {clean_clause} no violations. {not_assessed} not assessed. "
        f"{len(unmapped)} {gaps_word} to triage.",
        "",
    ]


def render_report(bundle: Bundle, mapping: Json, now: str) -> str:
    """Markdown report: risk posture, summary, per-control detail, coverage gaps, not-assessed controls."""
    controls = sorted(mapping["controls"].items())
    lines = [
        "# Compliance Scan Report",
        "",
        f"Generated {now}. Every status below is derived from scanner findings joined to",
        "controls declared in the OKF knowledge bundle; nothing is mapped without a declaration.",
        "`no-violations-detected` means automated checks found nothing for that control;",
        "it is evidence, not a control attestation.",
        "",
        *_risk_posture(controls, mapping["unmapped"]),
        "## Summary",
        "",
        "| Control | Status | Critical | High | Medium | Low | Uncl. | Total |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for code, entry in controls:
        c = _counts(entry["findings"])
        lines.append(
            f"| {code} | {entry['status']} | {c['critical']} | {c['high']} | "
            f"{c['medium']} | {c['low']} | {c['unclassified']} | {len(entry['findings'])} |"
        )
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
