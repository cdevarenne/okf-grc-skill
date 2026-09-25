"""Render a control mapping as OSCAL 1.2.3 component-definition + assessment-results (documented subset)."""

from __future__ import annotations

import argparse
import json
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from okf_lib import COMPONENT_TYPE, Bundle, load_bundle

OSCAL_VERSION = "1.2.3"
DOC_VERSION = "0.1.0"
NAMESPACE = uuid.UUID("6f1c3a52-2d0e-5b8e-9c61-0b8f4a7d2e10")
TSC_RESOURCE = "tsc-2017"
NO_AP_HREF = "#assessment-plan-not-modeled"

Json = dict[str, Any]


def _uuid(*parts: str) -> str:
    """Deterministic UUIDv5 so re-runs on the same input produce the same ids."""
    return str(uuid.uuid5(NAMESPACE, "/".join(parts)))


def _metadata(title: str, now: str) -> Json:
    return {"title": title, "last-modified": now, "version": DOC_VERSION, "oscal-version": OSCAL_VERSION}


def _finding_key(f: Json) -> str:
    return f"{f['tool']}:{f['rule_id']}:{f['target']}:{f['message']}"


def component_definition(bundle: Bundle, now: str) -> Json:
    """Stack components × the in-bundle controls each one links to that some concept declares rules for."""
    tsc_uuid = _uuid("resource", TSC_RESOURCE)
    grounded = [c for c in bundle.controls() if bundle.declaring(c.code)]
    components = []
    for comp in bundle.of_type(COMPONENT_TYPE):
        controls = [c for cid in comp.links if (c := bundle.concepts.get(cid)) and c in grounded]
        entry: Json = {
            "uuid": _uuid("component", comp.id),
            "type": "software",
            "title": comp.title,
            "description": comp.description or comp.title,
        }
        if controls:
            entry["control-implementations"] = [
                {
                    "uuid": _uuid("control-implementation", comp.id),
                    "source": f"#{tsc_uuid}",
                    "description": f"SOC 2 criteria that apply to {comp.title}.",
                    "implemented-requirements": [
                        {"uuid": _uuid("req", comp.id, c.code), "control-id": c.code, "description": c.title}
                        for c in controls
                    ],
                }
            ]
        components.append(entry)
    return {
        "component-definition": {
            "uuid": _uuid("component-definition"),
            "metadata": _metadata("okf-grc-skill sample app components", now),
            "components": components,
            "back-matter": {
                "resources": [{"uuid": tsc_uuid, "title": "AICPA Trust Services Criteria (SOC 2)"}]
            },
        }
    }


def _observation(f: Json, now: str) -> Json:
    return {
        "uuid": _uuid("observation", _finding_key(f)),
        "title": f"{f['tool']} {f['rule_id']}",
        "description": f"{f['message']} ({f['target']}, severity {f['severity']})",
        "methods": ["TEST"],
        "collected": now,
    }


def _remarks(mapping: Json) -> str:
    """Controls without an OSCAL finding, stated so their absence is not read as a pass."""
    by_status = {
        status: sorted(code for code, c in mapping["controls"].items() if c["status"] == status)
        for status in ("no-violations-detected", "not-assessed")
    }
    parts = []
    if by_status["no-violations-detected"]:
        parts.append(
            "No violations detected by automated checks (not a control attestation): "
            + ", ".join(by_status["no-violations-detected"])
        )
    if by_status["not-assessed"]:
        parts.append("Not assessed (no in-bundle scanner or policy): " + ", ".join(by_status["not-assessed"]))
    return ". ".join(parts)


def assessment_results(bundle: Bundle, mapping: Json, now: str) -> Json:
    """Findings only for controls with violations; unmapped findings become open risks, never findings.

    A clean automated scan never produces a `satisfied` finding: automation evidences a
    control but does not attest it.
    """
    all_findings = [f for c in mapping["controls"].values() for f in c["findings"]]
    all_findings += [u["finding"] for u in mapping["unmapped"]]
    observations = {_finding_key(f): _observation(f, now) for f in all_findings}
    assessed = sorted(code for code, c in mapping["controls"].items() if c["status"] != "not-assessed")
    findings = []
    for code in assessed:
        entry = mapping["controls"][code]
        if entry["status"] != "not-satisfied":
            continue
        control = bundle.control(code)
        findings.append(
            {
                "uuid": _uuid("finding", code),
                "title": control.title if control else code,
                "description": f"{len(entry['findings'])} open finding(s).",
                "target": {"type": "objective-id", "target-id": code, "status": {"state": "not-satisfied"}},
                "related-observations": [
                    {"observation-uuid": observations[_finding_key(f)]["uuid"]} for f in entry["findings"]
                ],
            }
        )
    risks = [
        {
            "uuid": _uuid("risk", _finding_key(u["finding"])),
            "title": f"Coverage gap: {u['finding']['tool']} {u['finding']['rule_id']}",
            "description": f"No in-bundle control covers this finding ({u['reason']}).",
            "statement": u["finding"]["message"],
            "status": "open",
            "related-observations": [{"observation-uuid": observations[_finding_key(u["finding"])]["uuid"]}],
        }
        for u in mapping["unmapped"]
    ]
    result: Json = {
        "uuid": _uuid("result"),
        "title": "Automated compliance scan",
        "description": "Scanner findings mapped to SOC 2 criteria through the OKF knowledge bundle.",
        "start": now,
        "reviewed-controls": {
            "control-selections": [{"include-controls": [{"control-id": code} for code in assessed]}]
        },
    }
    if observations:
        result["observations"] = list(observations.values())
    if risks:
        result["risks"] = risks
    if findings:
        result["findings"] = findings
    if remarks := _remarks(mapping):
        result["remarks"] = remarks
    return {
        "assessment-results": {
            "uuid": _uuid("assessment-results"),
            "metadata": _metadata("okf-grc-skill automated assessment", now),
            "import-ap": {"href": NO_AP_HREF, "remarks": "Assessment plan not modeled in v1; see docs/oscal-subset.md."},
            "results": [result],
        }
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--knowledge", type=Path, default=Path("knowledge"))
    parser.add_argument("--out", type=Path, default=Path("out"))
    parser.add_argument("--now", default=datetime.now(UTC).isoformat(timespec="seconds"))
    args = parser.parse_args()
    bundle = load_bundle(args.knowledge)
    mapping = json.loads((args.out / "mapping.json").read_text(encoding="utf-8"))
    oscal_dir = args.out / "oscal"
    oscal_dir.mkdir(parents=True, exist_ok=True)
    for name, doc in (
        ("component-definition.json", component_definition(bundle, args.now)),
        ("assessment-results.json", assessment_results(bundle, mapping, args.now)),
    ):
        (oscal_dir / name).write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
