# okf-grc-skill v1 — Design Spec

- **Date:** 2026-09-25
- **Status:** approved design, pending written-spec review
- **Scope:** Phases 0–6 (§9). A Postgres/pgvector projection of the bundle (a queryable compliance data layer) is out of scope and gets its own spec → plan cycle after Phase 6 is verified.

---

## 1. Goal and definition of done

A portable OKF knowledge bundle grounds an agent skill that scans a clean-room sample app, maps each finding to a SOC 2 / NIST 800-53 control, emits OSCAL, and writes an auditor-facing report.

**Done when:**

1. `make scan` against `app/` produces `out/findings.json`, `out/mapping.json`, `out/oscal/component-definition.json`, `out/oscal/assessment-results.json`, and `out/report.md`, end to end.
2. Every seeded issue in `app/SEEDED.yaml` appears with its expected control — and the seeded coverage-gap issue appears as an **unmapped coverage gap**, not an invented control mapping.
3. Both OSCAL files validate against the pinned NIST OSCAL JSON schema.
4. `make render` produces the OKF visualizer HTML for `knowledge/`.
5. Screenshots of the graph and the report are in `docs/screenshots/`.

**Out of scope:** agent eval harness, automated remediation, the database projection of the bundle, cross-agent shims (Gemini CLI / Copilot / Cursor), running the sample app.

## 2. Guardrails

- **Original work only.** The sample app, Rego, Semgrep rules, control text, and OSCAL mappings are written from scratch for this repo against public frameworks (SOC 2 TSC, NIST 800-53, OSCAL).
- **OSCAL is a documented subset.** `docs/oscal-subset.md` states exactly what is emitted and which required fields carry placeholders.
- **Grounding is enforced in code, not trusted to a prompt.** A finding reaches a control only through an explicit rule declaration in the bundle (§5). No fallback mapping.
- **Deterministic core.** `make scan` invokes no LLM. The `SKILL.md` layer may enrich prose in `report.md` when run in Claude Code, but never changes a status, mapping, or finding.
- **Intentionally vulnerable scan target.** `app/` contains deliberate misconfigurations and an outdated dependency. The README and `app/SEEDED.yaml` say so ("do not deploy"); Dependabot is disabled for this repo so it never "fixes" a seeded issue.
- **Small, composable scripts.** Each script has one purpose and a file-based interface; intelligence lives in the bundle and the skill prompt.

## 3. Pinned external versions

| Dependency | Pin | Notes |
|---|---|---|
| Python | `>=3.14` | uv-managed project |
| OKF spec | v0.2, `GoogleCloudPlatform/open-knowledge-format` @ `ad30107c31c0` | No tags/releases exist; pin by commit. The `knowledge-catalog/okf` copy is frozen and must not be used. |
| OKF visualizer | `reference-agent` package from the same commit | Run isolated: `uvx --python 3.14 --from "reference-agent @ git+…@<OKF_COMMIT>" reference-agent visualize --bundle knowledge --out out/knowledge-viz.html` |
| OSCAL | 1.2.3 (latest release) | JSON schemas vendored into `tests/fixtures/oscal/` |
| Semgrep, Checkov | 1.178.0, 3.3.19; `uv tool install` into repo-local `.tools/` | Checkov runs on Python 3.12, its highest supported version |
| Trivy, Conftest | 0.74.0, 0.70.1; checksum-verified release binaries into `.tools/bin/` | Homebrew cannot pin versions, so it is not used |

All pins live in `tools.lock`. `make bootstrap` installs them repo-locally and fails on any version mismatch.

OKF v0.2 changes relative to the v0.1-era source docs, adopted here:

- `index.md` files carry **no frontmatter**, except the bundle-root `index.md`, which declares `okf_version: "0.2"`.
- `timestamp` is replaced by `generated: {by, at}` (ISO 8601 with offset).
- `verified: [{by: "human:cdevarenne", at}]` records human review.
- OKF recommends bundle-absolute links (`/controls/cc7.1.md`), but the pinned visualizer draws no edge for them. This bundle therefore uses **relative links**, which both the spec and the visualizer accept.

## 4. Repository layout

```
okf-grc-skill/
├── README.md                  # thesis, one-command loop, pins, guardrails
├── LICENSE                    # MIT
├── Makefile                   # bootstrap / scan / render / test / clean
├── pyproject.toml             # runtime: pyyaml; dev: pytest, jsonschema
├── tools.lock                 # all pinned external versions
├── scripts/bootstrap.sh       # installs pinned scanners into .tools/ (git-ignored)
├── app/                       # clean-room scan target (never executed in v1)
│   ├── SEEDED.yaml            # machine-readable seeded-issue ledger
│   ├── manage.py
│   ├── requirements.txt       # includes one deliberately outdated, CVE-bearing pin
│   ├── widgets/{models,views,serializers,urls}.py
│   ├── Dockerfile
│   ├── k8s/{deployment,service}.yaml
│   └── infra/main.tf
├── knowledge/                 # OKF v0.2 bundle (§5)
├── policies/
│   ├── rego/{deny_latest_tag,require_non_root,no_public_bucket}.rego (+ *_test.rego)
│   └── semgrep/               # small vendored ruleset (deterministic, offline)
├── .claude/skills/grc-continuous-compliance/
│   ├── SKILL.md
│   └── scripts/{okf_lib,run_scan,map_findings,to_oscal,render_report}.py
├── tests/
│   ├── fixtures/              # mini-bundles, hand-written findings, captured scanner JSON, OSCAL schemas, golden report
│   └── test_*.py
├── docs/
│   ├── oscal-subset.md
│   ├── screenshots/
│   └── superpowers/{specs,plans}/
└── out/                       # generated, git-ignored
```

## 5. Data contracts

These are fixed before Phase 4 and are the interface for any parallel agent work.

### 5.1 Bundle conventions (OKF v0.2)

| `type` value | Files |
|---|---|
| `SOC 2 Control` | `controls/cc6.1.md`, `cc6.6.md`, `cc7.1.md`, `cc7.2.md`, `cc8.1.md` |
| `Stack Component` | `stack/django-api.md`, `container.md`, `k8s.md`, `terraform.md` |
| `Rego Policy` | `policies/deny-latest-tag.md`, `require-non-root.md`, `no-public-bucket.md` |
| `Semgrep Rule` | `policies/drf-authenticated-writes.md` |
| `Scanner` | `scanners/semgrep.md`, `trivy.md`, `checkov.md`, `conftest.md` |
| `Reference` | `oscal/component-definition.md` |

Plus `index.md` per directory (no frontmatter except root) and root `log.md`.

Every concept carries `type`, `title`, `description`, `tags`, and `generated` (`by: claude-code/claude-opus-5-5` for agent-drafted files). After human review it also carries `verified: [{by: "human:cdevarenne", at}]`.

- **Control tags:** the control's own id (`cc7.1`) plus NIST tags (`nist-ra-5`, `nist-si-2`).
- **Extension key `rule_ids`:** a list of `"<tool>:<rule_id>"` strings, the scanner rules this concept declares coverage for.
  - **A concept that declares `rule_ids` carries exactly one control tag.** Otherwise every rule on it would map to every control it names.
  - Detector rules live on the **guardrail** they detect (`Rego Policy`, `Semgrep Rule`). For example, `require-non-root` lists the Conftest, Checkov, and Trivy rules that all detect a root container.
  - `Scanner` concepts declare only rule families that belong to one control (Trivy `CVE-*`/`GHSA-*` → CC7.1).
  - The rule part may be a shell-style glob (`fnmatch`) for open-ended id families, e.g. `trivy:CVE-*` and `trivy:GHSA-*` on `scanners/trivy.md`, because vulnerability ids cannot be enumerated.
  - A bare `<tool>:*` is forbidden (it would map every finding from a tool and defeat the grounding rule); the bundle conformance test enforces this.
- **`# Remediation` body section:** on every concept that declares `rule_ids`; the report templates remediation text from it.
- **Links:** relative form (§3); headings `# Evidenced by`, `# Satisfies`, `# Applies to` carry the relationship in prose.

### 5.2 `okf_lib`

```python
@dataclass(frozen=True)
class Concept:
    id: str                 # path relative to bundle, without ".md": "controls/cc7.1"
    path: str               # "controls/cc7.1.md"
    type: str
    title: str
    description: str
    tags: tuple[str, ...]
    rule_ids: tuple[str, ...]
    frontmatter: Mapping[str, Any]   # full, unknown keys preserved
    body: str
    links: tuple[str, ...]           # resolved bundle-relative targets, broken links included

@dataclass(frozen=True)
class Bundle:
    concepts: Mapping[str, Concept]
    def controls(self) -> list[Concept]: ...
    def by_rule(self, tool: str, rule_id: str) -> list[Concept]: ...
    def section(self, concept: Concept, heading: str) -> str | None: ...

def load_bundle(root: Path) -> Bundle: ...
```

Tolerates unknown types, unknown keys, broken links, and missing `index.md` (OKF §11). Raises `BundleError` naming the file for a non-reserved `.md` with unparseable frontmatter or a missing/empty `type`. Skips `index.md` and `log.md`.

### 5.3 Finding (`out/findings.json`)

```json
[{"tool": "checkov", "rule_id": "CKV_K8S_...", "severity": "high",
  "target": "app/k8s/deployment.yaml", "message": "...", "tags": []}]
```

- `tool` ∈ `semgrep | trivy | checkov | conftest`.
- `severity` ∈ `critical | high | medium | low | info | unknown` (normalized per tool). Checkov reports no severity without a vendor API key, so its findings are `unknown` rather than an invented level. Conftest deny rules are blocking, so they are `high`.
- `target` is repo-relative.
- `tags` holds tool-native tags only; the join key is `(tool, rule_id)`.
- Only fully identical findings are collapsed (key `(tool, rule_id, target, message)`): one rule can fire on several resources in one file, and those are distinct findings. Cross-tool duplicates are kept as corroborating evidence.

### 5.4 Mapping (`out/mapping.json`)

```json
{
  "controls": {
    "cc7.1": {
      "status": "not-satisfied",
      "findings": [ {...finding...} ],
      "evidenced_by": ["scanners/trivy"],
      "satisfied_by": []
    }
  },
  "unmapped": [
    {"finding": {...}, "reason": "no-rule-match"}
  ]
}
```

Join algorithm for each finding:

1. `bundle.by_rule(tool, rule_id)` → concepts declaring that rule. None → unmapped, `reason: "no-rule-match"`.
2. Collect those concepts' `ccN.N` tags.
3. Keep only tags that name an existing `SOC 2 Control` concept. None survive → unmapped, `reason: "control-not-in-bundle"`.
4. Attach the finding to each surviving control.

Control status:

- `not-satisfied` — at least one finding attached.
- `no-violations-detected` — no findings, and at least one `Scanner`, `Rego Policy`, or `Semgrep Rule` concept carries the control's tag. This is evidence, not attestation: automated scans never report a control as `satisfied`.
- `not-assessed` — no in-bundle scanner or policy carries the control's tag (CC7.2 in v1; runtime monitoring is v2).

## 6. Pipeline

`make scan` = `run_scan.py` → `map_findings.py` → `to_oscal.py` → `render_report.py`. Each is a CLI with `--knowledge`, `--target`, `--out` defaults of `knowledge/`, `app/`, `out/`.

- **`run_scan.py`** runs:
  - Semgrep with `policies/semgrep/`, `--metrics=off`;
  - `trivy config` and `trivy fs` on `app/`;
  - Checkov on Terraform, K8s, and the Dockerfile;
  - Conftest with `policies/rego/` and `--all-namespaces` on `k8s/**/*.{yaml,yml}` and `infra/**/*.tf` under the target. Conftest parses HCL2 directly; each block parses to a list.

  One normalizer function per tool. Observed tool behavior the normalizers rely on:
  - Semgrep prefixes rule ids with the config path (`policies.semgrep.drf-allowany`); the normalizer keeps the last segment.
  - Trivy 0.74 rule ids are dashed (`DS-0002`, `KSV-0013`); targets are relative to the scanned directory.
  - Checkov runs with `cwd` = the target: its Kubernetes framework reports paths relative to the working directory, not `-d`.
  - Conftest's rule id is the Rego package name (`namespace` in its JSON). A scanner exiting non-zero because it found issues is success. A missing binary or a crash fails the run with the scanner named.
- **`map_findings.py`** — pure join per §5.4; file I/O only at the CLI edge.
- **`to_oscal.py`** writes `component-definition.json` (components × control implementations) and `assessment-results.json` (findings as observations; per-control findings).
  - UUIDs are `uuid5` over stable content ids.
  - Timestamps come from an injectable `--now` for reproducible tests.
  - Only controls with violations get an OSCAL `finding` (state `not-satisfied`). Controls with no violations detected, and controls not assessed, are listed in the result `remarks`, never as `satisfied`.
  - Unmapped findings become observations plus an open **risk** titled "Coverage gap: …". They are never OSCAL `findings`, because an OSCAL finding must target a control and targeting one would invent a mapping.
  - Placeholder values for required fields (e.g. `import-ap`) are listed in `docs/oscal-subset.md`.
- **`render_report.py`** writes `out/report.md`:
  - per control: status, evidence (linked concepts), open findings, remediation paragraph from `# Remediation` sections;
  - a **Coverage gaps** section with each unmapped finding and its reason;
  - a **Not assessed** section.
- **`SKILL.md`** — the scope doc's skeleton, tightened. It instructs the agent to read the bundle, run `make scan`, then optionally enrich `report.md` prose without altering statuses, mappings, or findings, and to report unmapped findings as gaps.

Makefile targets:

| Target | Does |
|---|---|
| `bootstrap` | `uv sync`; install and version-check pinned scanners |
| `scan` | the pipeline above |
| `render` | OKF visualizer → `out/knowledge-viz.html` |
| `test` | unit tests (no scanners required) |
| `test-integration` | `pytest -m integration` (scanners required) |
| `clean` | remove `out/` |

## 7. Seeded issues

Recorded in `app/SEEDED.yaml`, with the rule ids observed detecting each issue in a prototype run of the pinned scanners (2026-09-25). The full scan also surfaces about 40 other misconfigurations the bundle does not declare. They are reported as coverage gaps too, which is the grounding rule working as intended.

| Id | Where | Issue | Expected outcome |
|---|---|---|---|
| S1 | `Dockerfile` | runs as root (no `USER`) | CC6.1 |
| S2 | `Dockerfile` | no `HEALTHCHECK` | **coverage gap** (availability, SOC 2 A1, not in bundle) |
| S3 | `k8s/deployment.yaml` | image `:latest` | CC8.1 |
| S4 | `k8s/deployment.yaml` | runs as root / no `runAsNonRoot` | CC6.1 |
| S5 | `infra/main.tf` | bucket publicly readable (`allUsers`) | CC6.6 |
| S6 | `widgets/views.py` | `AllowAny` on a write endpoint (vendored Semgrep rule) | CC6.1 |
| S7 | `requirements.txt` | outdated package with a known CVE | CC7.1 |

The bundle must deliberately not declare S2's rule ids, so the gap is produced by the real join, not staged.

## 8. Testing and verification

- **TDD per script.** Unit tests never need scanners installed.
  - `okf_lib`: fixture mini-bundles — missing `type` rejected; unknown type/key tolerated; broken link tolerated and recorded; `index.md`/`log.md` skipped.
  - `map_findings`: the grounding gate. Hand-written findings: three mapped (one via a `CVE-*` glob), one `no-rule-match`, one `control-not-in-bundle` (fixture policy tagged `cc9.9`); status derivation for all three states. These fixtures stay in the repo permanently.
  - `run_scan`: normalizers tested against captured real scanner JSON in `tests/fixtures/scanner_output/`, captured during Phase 4.
  - `to_oscal`: schema validation against the vendored OSCAL schemas (the schemas' `\p{L}`/`\p{N}` regex classes are rewritten to Python equivalents at load time, since Python's `re` rejects them); determinism (same input + `--now` → identical output); coverage gaps never carry a related control.
  - `render_report`: golden-file test from a fixture mapping.
- **Bundle conformance test** on the real `knowledge/`:
  - OKF v0.2 §11;
  - every `rule_ids` entry is `tool:rule` with a known tool, and none is a bare `tool:*`;
  - every `ccN.N` tag on a policy/scanner resolves to a control concept;
  - every concept has `verified`.

  The last check fails until human review, making the Phase 2 human-review gate executable.
- **Rego:** `conftest verify` with a `_test.rego` per policy. Kubernetes policies cover every pod-running workload kind (Pod, Deployment, StatefulSet, DaemonSet, ReplicaSet, Job, CronJob) and init containers, via a shared `lib.k8s` helper.
- **Semgrep:** `semgrep --test` against an annotated test file covering the list, tuple, and decorator forms of `AllowAny`.
- **Integration (`make test-integration`):** runs `make scan`, asserts every `SEEDED.yaml` entry appears with its expected control or as the expected coverage gap, all outputs exist, and OSCAL validates. Assertions are superset (⊇), since `trivy fs` CVE results change as the vulnerability database is updated.
- **Manual (Phase 6):** screenshots of the visualizer graph and the rendered report into `docs/screenshots/`.

## 9. Phases

| Phase | Deliverable | Verified by |
|---|---|---|
| 0 | Repo scaffold, `tools.lock`, `scripts/bootstrap.sh`, README, Makefile, `pyproject.toml`, `.gitignore`, LICENSE | `make bootstrap` passes version checks; pin-format test green |
| 1 | Sample app, manifests, Terraform, `SEEDED.yaml` with real rule ids | each seeded issue observed in a manual scanner run; ids recorded |
| 2 | OKF bundle (~20 concepts + indexes + log) | bundle conformance test green after author review adds `verified` |
| 3 | Three Rego policies + tests; Semgrep ruleset | `conftest verify`; each policy fires on its seeded file |
| 4 | `okf_lib` → `map_findings` (sequential, fixture-proven) → `run_scan`, `to_oscal`, `render_report` (parallelizable against §5) → `SKILL.md` | unit tests per script |
| 5 | Wired `make scan` | integration test green |
| 6 | `make render`, screenshots | HTML opens; screenshots committed |

## 10. Tracking

Work is tracked as GitHub issues on `cdevarenne/okf-grc-skill` (public), one per plan task. Trunk-based: commits go to `main`, no feature branches or PRs.
