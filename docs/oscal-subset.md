# OSCAL subset emitted in v1

`to_oscal.py` emits OSCAL **1.2.3** JSON. Both documents validate against the
NIST JSON schemas vendored in `tests/fixtures/oscal/`. This is a documented
subset, not a complete OSCAL implementation.

## component-definition.json

| Field | Source |
|---|---|
| `metadata` | title, `last-modified` (scan time), `version` 0.1.0, `oscal-version` 1.2.3 |
| `components[]` | one per `Stack Component` concept; `type: software` |
| `control-implementations[].implemented-requirements[]` | one per SOC 2 control the component's concept links to; `control-id` is the criterion code (`cc6.1`) |
| `control-implementations[].source` | `#<uuid>` of a back-matter resource titled "AICPA Trust Services Criteria (SOC 2)" |

## assessment-results.json

| Field | Source |
|---|---|
| `import-ap.href` | **placeholder** `#assessment-plan-not-modeled`: v1 has no assessment plan |
| `results[0].reviewed-controls` | every control with status other than `not-assessed` |
| `results[0].observations[]` | one per scanner finding; `methods: [TEST]` |
| `results[0].findings[]` | one per control with open violations; `target.status.state` is always `not-satisfied` |
| `results[0].risks[]` | one per unmapped finding, titled "Coverage gap: …", `status: open` |
| `results[0].remarks` | lists controls with no violations detected, and controls not assessed |

## Deliberately not modeled

- Assessment plan, SSP, POA&M, and profiles.
- A machine-readable SOC 2 catalog: the Trust Services Criteria are not
  published as an OSCAL catalog, so `control-id` values are the criterion codes.
- Parties, roles, and responsible-parties.
- A `satisfied` finding: a clean automated scan evidences a control but does not
  attest it, so controls with no violations are listed in `remarks` instead.
- Coverage gaps as `findings`: an OSCAL finding must target a control, and
  targeting one would invent the mapping the grounding rule forbids.
