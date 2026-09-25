# okf-grc-skill v1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `make scan` turns a clean-room sample app into normalized findings, a grounded control mapping, OSCAL 1.2.3 JSON, and an auditor report, with every seeded issue landing on its expected control or, for one, as an honest coverage gap.

**Architecture:** An OKF v0.2 markdown bundle (`knowledge/`) declares which scanner rules evidence which SOC 2 controls. Five small Python scripts form a file-based pipeline (`run_scan` → `map_findings` → `to_oscal` → `render_report`, all built on `okf_lib`). A finding reaches a control only through a `rule_ids` declaration; anything else is a coverage gap. A `SKILL.md` wraps the pipeline for Claude Code.

**Tech Stack:** Python 3.14 (uv), PyYAML, pytest, jsonschema; Semgrep 1.178.0, Trivy 0.74.0, Checkov 3.3.19, Conftest 0.70.1 (OPA/Rego v1); OKF v0.2 reference visualizer; OSCAL 1.2.3.

**Spec:** `docs/superpowers/specs/2026-09-25-okf-grc-skill-v1-design.md`

**Provenance:** every file in this plan was run in a prototype on 2026-09-25 against the pinned tools. At that point there were 78 unit tests, 9 integration tests, and 13 Rego tests, all green; `make scan` ran end to end; and both OSCAL outputs validated. Expected outputs quoted below come from that run.

## Global Constraints

- Python `>=3.14`; runtime dependency PyYAML only; dev dependencies pytest and jsonschema.
- All external versions come from `tools.lock`; tools install repo-locally into `.tools/` (git-ignored), never globally.
- OKF v0.2 at commit `ad30107c31c06aec8a7d5636e0d1058118604e6f`; OSCAL 1.2.3.
- Grounding rule: a finding maps to a control only via a `rule_ids` declaration; a concept declaring `rule_ids` carries exactly one control tag; a bare `<tool>:*` is forbidden.
- Bundle links are relative (the pinned visualizer ignores `/`-absolute links); `index.md` files carry no frontmatter except the root's `okf_version: "0.2"`.
- Type hints on all functions, tests included; docstrings on public functions.
- Public repo: all content is original and self-contained; cite only public frameworks, specs, and tools.
- Commits: trunk-based on `main`; authored by the repo-local identity (`cdevarenne`, no-reply email). **Never add a `Co-Authored-By` trailer.** Short subject, `Closes #N` body line.
- Every commit ships tests. Docs-only commits say so.
- `app/` is intentionally vulnerable; Dependabot is disabled for the repo. Do not "fix" seeded issues.

## Task order and parallelism

Task order follows dependencies, so it differs from the spec's phase numbers: guardrail policies (Phase 3) come before the bundle, and `okf_lib` comes before the bundle its conformance test loads. **Tasks 8, 9, and 10 are independent** once Task 7 is merged, so they can run as parallel subagents against the contracts in spec §5. **Task 6 is a human gate:** an executing agent must stop there and hand off to the repo owner.

## Task 0: Tracking issues (no commit)

- [ ] **Step 1: Create one GitHub issue per task.** The repo has no issues yet, so Task N becomes issue #N.

```bash
gh issue create --title "T1: Scaffold and pinned toolchain" --body "Phase 0. See docs/superpowers/plans/2026-09-25-okf-grc-skill-v1.md, Task 1."
gh issue create --title "T2: Sample app and seeded-issue ledger" --body "Phase 1. See docs/superpowers/plans/2026-09-25-okf-grc-skill-v1.md, Task 2."
gh issue create --title "T3: Guardrail policies: Rego and Semgrep" --body "Phase 3. See docs/superpowers/plans/2026-09-25-okf-grc-skill-v1.md, Task 3."
gh issue create --title "T4: okf_lib: parse the bundle" --body "Phase 4.1. See docs/superpowers/plans/2026-09-25-okf-grc-skill-v1.md, Task 4."
gh issue create --title "T5: OKF knowledge bundle" --body "Phase 2. See docs/superpowers/plans/2026-09-25-okf-grc-skill-v1.md, Task 5."
gh issue create --title "T6: Human review of the bundle" --body "Phase 2 gate. See docs/superpowers/plans/2026-09-25-okf-grc-skill-v1.md, Task 6."
gh issue create --title "T7: map_findings: the grounding gate" --body "Phase 4.2. See docs/superpowers/plans/2026-09-25-okf-grc-skill-v1.md, Task 7."
gh issue create --title "T8: run_scan: scanners and normalizers" --body "Phase 4.3. See docs/superpowers/plans/2026-09-25-okf-grc-skill-v1.md, Task 8."
gh issue create --title "T9: to_oscal: OSCAL output" --body "Phase 4.4. See docs/superpowers/plans/2026-09-25-okf-grc-skill-v1.md, Task 9."
gh issue create --title "T10: render_report: auditor report" --body "Phase 4.5. See docs/superpowers/plans/2026-09-25-okf-grc-skill-v1.md, Task 10."
gh issue create --title "T11: SKILL.md and OSCAL subset doc" --body "Phase 4.6. See docs/superpowers/plans/2026-09-25-okf-grc-skill-v1.md, Task 11."
gh issue create --title "T12: End-to-end integration" --body "Phase 5. See docs/superpowers/plans/2026-09-25-okf-grc-skill-v1.md, Task 12."
gh issue create --title "T13: Visualize, screenshots, README" --body "Phase 6. See docs/superpowers/plans/2026-09-25-okf-grc-skill-v1.md, Task 13."
```

- [ ] **Step 2: Verify.** Run `gh issue list --limit 20`. Expected: 13 open issues, #1–#13.

---

## Task 1: Scaffold and pinned toolchain

**Files:**
- Create: `pyproject.toml`, `.gitignore`, `LICENSE`, `README.md`, `tools.lock`, `scripts/bootstrap.sh`, `Makefile`
- Test: `tests/test_tools_lock.py`

**Interfaces:**
- Produces: `make bootstrap|scan|render|test|test-integration|clean`; `.tools/bin/{semgrep,checkov,trivy,conftest}`; `tools.lock` keys `SEMGREP_VERSION CHECKOV_VERSION CHECKOV_PYTHON TRIVY_VERSION CONFTEST_VERSION OKF_COMMIT OSCAL_VERSION`; pytest `pythonpath` includes `.claude/skills/grc-continuous-compliance/scripts` so tests import scripts by module name.

- [ ] **Step 1: Create the Python project and sync.**

`pyproject.toml`:

```toml
[project]
name = "okf-grc-skill"
version = "0.1.0"
requires-python = ">=3.14"
dependencies = ["pyyaml>=6.0.2"]

[dependency-groups]
dev = ["pytest>=8.4", "jsonschema>=4.25"]

[tool.pytest.ini_options]
testpaths = ["tests"]
pythonpath = [".claude/skills/grc-continuous-compliance/scripts"]
markers = ["integration: requires scanners installed (make test-integration)"]
addopts = "-m 'not integration'"
```

`.gitignore`:

```
out/
.tools/
.venv/
__pycache__/
.pytest_cache/
```

Run: `uv sync --python 3.14`
Expected: creates `.venv/` and `uv.lock`.

- [ ] **Step 2: Write the failing test.**

`tests/test_tools_lock.py`:

```python
import re
from pathlib import Path

LOCK = Path(__file__).parent.parent / "tools.lock"
REQUIRED = {
    "SEMGREP_VERSION", "CHECKOV_VERSION", "CHECKOV_PYTHON", "TRIVY_VERSION",
    "CONFTEST_VERSION", "OKF_COMMIT", "OSCAL_VERSION",
}


def _pins() -> dict[str, str]:
    lines = [ln for ln in LOCK.read_text().splitlines() if ln and not ln.startswith("#")]
    return dict(ln.split("=", 1) for ln in lines)


def test_all_pins_present() -> None:
    assert set(_pins()) == REQUIRED


def test_pins_are_exact() -> None:
    pins = _pins()
    assert re.fullmatch(r"[0-9a-f]{40}", pins["OKF_COMMIT"])
    for key in REQUIRED - {"OKF_COMMIT"}:
        assert re.fullmatch(r"\d+\.\d+(\.\d+)?", pins[key]), key
```

- [ ] **Step 3: Run it to confirm it fails.**

Run: `uv run pytest tests/test_tools_lock.py -q`
Expected: FAIL, `FileNotFoundError: ... tools.lock`.

- [ ] **Step 4: Add the pins.**

`tools.lock`:

```bash
# Pinned external versions. Read by scripts/bootstrap.sh and the Makefile.
SEMGREP_VERSION=1.178.0
CHECKOV_VERSION=3.3.19
CHECKOV_PYTHON=3.12
TRIVY_VERSION=0.74.0
CONFTEST_VERSION=0.70.1
OKF_COMMIT=ad30107c31c06aec8a7d5636e0d1058118604e6f
OSCAL_VERSION=1.2.3
```

- [ ] **Step 5: Run the test to confirm it passes.**

Run: `uv run pytest tests/test_tools_lock.py -q`
Expected: `2 passed`.

- [ ] **Step 6: Add bootstrap, Makefile, LICENSE, README.**

`scripts/bootstrap.sh`:

```bash
#!/usr/bin/env bash
# Install the pinned scanners into ./.tools (repo-local, git-ignored) and verify their versions.
set -euo pipefail
cd "$(dirname "$0")/.."
source tools.lock
TOOLS="$PWD/.tools"
BIN="$TOOLS/bin"
mkdir -p "$BIN"

case "$(uname -s)-$(uname -m)" in
  Darwin-arm64) TRIVY_OS=macOS-ARM64; CONFTEST_OS=Darwin_arm64 ;;
  Linux-x86_64) TRIVY_OS=Linux-64bit; CONFTEST_OS=Linux_x86_64 ;;
  *) echo "unsupported platform: $(uname -s)-$(uname -m)" >&2; exit 1 ;;
esac

# fetch_release <repo> <tag> <asset> <checksums-file> <binary>
fetch_release() {
  local repo=$1 tag=$2 asset=$3 sums=$4 binary=$5 tmp
  tmp=$(mktemp -d)
  curl -fsSL -o "$tmp/$asset" "https://github.com/$repo/releases/download/$tag/$asset"
  curl -fsSL -o "$tmp/$sums" "https://github.com/$repo/releases/download/$tag/$sums"
  (cd "$tmp" && grep " $asset\$" "$sums" | shasum -a 256 -c -)
  tar -xzf "$tmp/$asset" -C "$tmp" "$binary"
  mv "$tmp/$binary" "$BIN/$binary"
  rm -rf "$tmp"
}

fetch_release aquasecurity/trivy "v$TRIVY_VERSION" "trivy_${TRIVY_VERSION}_${TRIVY_OS}.tar.gz" "trivy_${TRIVY_VERSION}_checksums.txt" trivy
fetch_release open-policy-agent/conftest "v$CONFTEST_VERSION" "conftest_${CONFTEST_VERSION}_${CONFTEST_OS}.tar.gz" checksums.txt conftest

export UV_TOOL_DIR="$TOOLS/uv" UV_TOOL_BIN_DIR="$BIN"
uv tool install --force --quiet "semgrep==$SEMGREP_VERSION"
uv tool install --force --quiet --python "$CHECKOV_PYTHON" "checkov==$CHECKOV_VERSION"

# check <binary> <expected-version> <version-args...>
check() {
  local binary=$1 expected=$2; shift 2
  if ! "$BIN/$binary" "$@" 2>&1 | grep -q "$expected"; then
    echo "version mismatch: $binary is not $expected" >&2; exit 1
  fi
  echo "ok  $binary $expected"
}
check trivy "$TRIVY_VERSION" --version
check conftest "$CONFTEST_VERSION" --version
check semgrep "$SEMGREP_VERSION" --version
check checkov "$CHECKOV_VERSION" --version
```

`Makefile`:

```make
include tools.lock

SCRIPTS := .claude/skills/grc-continuous-compliance/scripts
PY := uv run python
TOOLBIN := $(CURDIR)/.tools/bin
export PATH := $(TOOLBIN):$(PATH)
export TRIVY_CACHE_DIR := $(CURDIR)/.tools/trivy-cache
OKF := reference-agent @ git+https://github.com/GoogleCloudPlatform/open-knowledge-format@$(OKF_COMMIT)

.PHONY: bootstrap scan render test test-integration clean

bootstrap:
	uv sync
	./scripts/bootstrap.sh

scan:
	$(PY) $(SCRIPTS)/run_scan.py --target app --out out
	$(PY) $(SCRIPTS)/map_findings.py --knowledge knowledge --out out
	$(PY) $(SCRIPTS)/to_oscal.py --knowledge knowledge --out out
	$(PY) $(SCRIPTS)/render_report.py --knowledge knowledge --out out

render:
	mkdir -p out
	uvx --python 3.14 --from "$(OKF)" reference-agent visualize --bundle knowledge --out out/knowledge-viz.html

test:
	uv run pytest
	$(TOOLBIN)/conftest verify -p policies/rego --no-color

test-integration:
	uv run pytest -m integration

clean:
	rm -rf out
```

`TOOLBIN` is referenced explicitly in the `test` recipe because macOS's GNU Make 3.81 does not use an exported `PATH` to look up a recipe's own first command. Child processes (the scanners run by `run_scan.py`) do inherit it.

`LICENSE`:

```text
MIT License

Copyright (c) 2026 Claude Devarenne

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

`README.md`:

````markdown
# okf-grc-skill

A portable [Open Knowledge Format](https://github.com/GoogleCloudPlatform/open-knowledge-format)
(OKF) knowledge bundle grounds an agent skill that scans a sample app, maps each
finding to a SOC 2 / NIST SP 800-53 control, emits OSCAL, and writes an
auditor-facing report.

*Organize knowledge → derive intelligence → take action.*

> **`app/` is intentionally vulnerable.** It exists only as a scan target, with
> seeded issues listed in [`app/SEEDED.yaml`](app/SEEDED.yaml). Do not deploy it.

## The one-command loop

```
make bootstrap         # uv sync + install pinned scanners into .tools/
make scan              # out/findings.json, out/mapping.json, out/oscal/*.json, out/report.md
make render            # out/knowledge-viz.html — the OKF graph
make test              # unit tests + Rego tests
make test-integration  # full scan; asserts every seeded issue lands where expected
make clean             # remove out/
```

## How grounding works

A finding reaches a control only through a `rule_ids` declaration in the bundle.
A finding with no declaration is reported as a **coverage gap**, never mapped by
guesswork. The scan surfaces dozens of such gaps; each one is a rule the bundle
has not yet claimed for any control.

## Pins

All external versions are pinned in [`tools.lock`](tools.lock): Semgrep, Checkov,
Trivy, Conftest, the OKF spec (v0.2, by commit), and OSCAL 1.2.3. The OSCAL
output is a documented subset: see [`docs/oscal-subset.md`](docs/oscal-subset.md).

## Layout

| Path | What |
|---|---|
| `app/` | clean-room Django/DRF sample app, Dockerfile, Kubernetes, Terraform |
| `knowledge/` | the OKF bundle: controls, stack, guardrail policies, scanners |
| `policies/` | Rego guardrails (+ tests) and a vendored Semgrep rule |
| `.claude/skills/grc-continuous-compliance/` | the skill (`SKILL.md`) and its scripts |
| `docs/` | design spec, implementation plan, OSCAL subset |

## License

MIT
````

- [ ] **Step 7: Bootstrap.**

Run: `chmod +x scripts/bootstrap.sh && make bootstrap`
Expected, after both `...tar.gz: OK` checksum lines (first run is about 80 seconds):

```
ok  trivy 0.74.0
ok  conftest 0.70.1
ok  semgrep 1.178.0
ok  checkov 3.3.19
```

- [ ] **Step 8: Commit.**

```bash
git add pyproject.toml uv.lock .gitignore LICENSE README.md tools.lock scripts/bootstrap.sh Makefile tests/test_tools_lock.py
git commit -m "Add scaffold and pinned toolchain" -m "Closes #1"
```

---

## Task 2: Sample app and seeded-issue ledger

**Files:**
- Create: `app/manage.py`, `app/requirements.txt`, `app/Dockerfile`, `app/widgets/{__init__,models,serializers,urls,views}.py`, `app/k8s/{deployment,service}.yaml`, `app/infra/main.tf`, `app/SEEDED.yaml`
- Test: `tests/test_seeded_ledger.py`

**Interfaces:**
- Produces: `app/SEEDED.yaml`, a list of `{id, file, issue, detected_by: ["tool:rule_id"], expect: {control: ccN.N} | {gap: reason}}`, consumed by Task 12.

- [ ] **Step 1: Write the failing test.**

`tests/test_seeded_ledger.py`:

```python
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).parent.parent
SEEDED = yaml.safe_load((ROOT / "app" / "SEEDED.yaml").read_text())
TOOLS = {"semgrep", "trivy", "checkov", "conftest"}


def test_ids_are_unique() -> None:
    assert len({s["id"] for s in SEEDED}) == len(SEEDED)


def test_has_a_coverage_gap_seed() -> None:
    assert any("gap" in s["expect"] for s in SEEDED)


@pytest.mark.parametrize("seed", SEEDED, ids=lambda s: s["id"])
def test_entry_is_well_formed(seed: dict) -> None:
    assert (ROOT / seed["file"]).is_file()
    assert seed["detected_by"]
    for detector in seed["detected_by"]:
        tool, _, rule = detector.partition(":")
        assert tool in TOOLS and rule
    assert len(seed["expect"]) == 1 and set(seed["expect"]) <= {"control", "gap"}
```

- [ ] **Step 2: Run it to confirm it fails.**

Run: `uv run pytest tests/test_seeded_ledger.py -q`
Expected: FAIL at collection, `FileNotFoundError: ... app/SEEDED.yaml`.

- [ ] **Step 3: Write the app.** Create an empty `app/widgets/__init__.py` (`touch` it). `requirements.txt` pins Django 4.2.0 on purpose (S7). The app is a scan target and is never run in v1.

`app/manage.py`:

```python
#!/usr/bin/env python
"""Django management entry point for the sample widgets API."""

import os
import sys

if __name__ == "__main__":
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
    from django.core.management import execute_from_command_line

    execute_from_command_line(sys.argv)
```

`app/requirements.txt`:

```
Django==4.2.0
djangorestframework==3.15.2
gunicorn==23.0.0
```

`app/Dockerfile`:

```dockerfile
FROM python:3.14-slim
WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 8000
CMD ["gunicorn", "config.wsgi", "--bind", "0.0.0.0:8000"]
```

`app/widgets/models.py`:

```python
from django.db import models


class Widget(models.Model):
    name = models.CharField(max_length=100)
    description = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self) -> str:
        return self.name
```

`app/widgets/serializers.py`:

```python
from rest_framework import serializers

from .models import Widget


class WidgetSerializer(serializers.ModelSerializer):
    class Meta:
        model = Widget
        fields = ["id", "name", "description", "created_at"]
        read_only_fields = ["id", "created_at"]
```

`app/widgets/urls.py`:

```python
from rest_framework.routers import DefaultRouter

from .views import WidgetViewSet

router = DefaultRouter()
router.register("widgets", WidgetViewSet)

urlpatterns = router.urls
```

`app/widgets/views.py`:

```python
from rest_framework import viewsets
from rest_framework.permissions import AllowAny

from .models import Widget
from .serializers import WidgetSerializer


class WidgetViewSet(viewsets.ModelViewSet):
    queryset = Widget.objects.all()
    serializer_class = WidgetSerializer
    permission_classes = [AllowAny]
```

`app/k8s/deployment.yaml`:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: widgets-api
  labels:
    app: widgets-api
spec:
  replicas: 2
  selector:
    matchLabels:
      app: widgets-api
  template:
    metadata:
      labels:
        app: widgets-api
    spec:
      containers:
        - name: api
          image: ghcr.io/example/widgets-api:latest
          ports:
            - containerPort: 8000
          securityContext:
            runAsUser: 0
            runAsNonRoot: false
```

`app/k8s/service.yaml`:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: widgets-api
spec:
  selector:
    app: widgets-api
  ports:
    - port: 80
      targetPort: 8000
```

`app/infra/main.tf`:

```hcl
resource "google_service_account" "widgets" {
  account_id   = "widgets-api"
  display_name = "Widgets API"
}

resource "google_storage_bucket" "widgets_assets" {
  name                        = "widgets-assets-example"
  location                    = "EU"
  uniform_bucket_level_access = true
}

resource "google_storage_bucket_iam_member" "public_read" {
  bucket = google_storage_bucket.widgets_assets.name
  role   = "roles/storage.objectViewer"
  member = "allUsers"
}
```

- [ ] **Step 4: Write the ledger.** The rule ids are the ones the pinned scanners reported in the prototype run.

`app/SEEDED.yaml`:

```yaml
# INTENTIONALLY VULNERABLE SCAN TARGET — DO NOT DEPLOY.
# Each seeded issue, the scanner rules observed to detect it, and the expected outcome.
# Asserted by tests/test_integration.py (make test-integration).
- id: S1
  file: app/Dockerfile
  issue: image runs as root (no USER instruction)
  detected_by: ["trivy:DS-0002", "checkov:CKV_DOCKER_3"]
  expect: {control: cc6.1}
- id: S2
  file: app/Dockerfile
  issue: no HEALTHCHECK (availability, SOC 2 A1 — not in the bundle)
  detected_by: ["trivy:DS-0026", "checkov:CKV_DOCKER_2"]
  expect: {gap: no-rule-match}
- id: S3
  file: app/k8s/deployment.yaml
  issue: image uses the :latest tag
  detected_by: ["conftest:deny_latest_tag", "checkov:CKV_K8S_14", "trivy:KSV-0013"]
  expect: {control: cc8.1}
- id: S4
  file: app/k8s/deployment.yaml
  issue: container runs as root (runAsUser 0, runAsNonRoot false)
  detected_by: ["conftest:require_non_root", "checkov:CKV_K8S_23", "trivy:KSV-0012", "trivy:KSV-0105"]
  expect: {control: cc6.1}
- id: S5
  file: app/infra/main.tf
  issue: bucket readable by allUsers
  detected_by: ["conftest:no_public_bucket", "checkov:CKV_GCP_28", "trivy:GCP-0001"]
  expect: {control: cc6.6}
- id: S6
  file: app/widgets/views.py
  issue: DRF viewset uses AllowAny
  detected_by: ["semgrep:drf-allowany"]
  expect: {control: cc6.1}
- id: S7
  file: app/requirements.txt
  issue: Django 4.2.0 has known CVEs
  detected_by: ["trivy:CVE-2023-31047"]
  expect: {control: cc7.1}
```

- [ ] **Step 5: Run the test to confirm it passes.**

Run: `uv run pytest tests/test_seeded_ledger.py -q`
Expected: `9 passed`.

- [ ] **Step 6: Confirm the Trivy and Checkov detections (Semgrep and Conftest are confirmed in Task 3).**

```bash
export TRIVY_CACHE_DIR=.tools/trivy-cache
.tools/bin/trivy config --quiet --format json app | python3 -c 'import json,sys; print(sorted({m["ID"] for r in json.load(sys.stdin)["Results"] for m in r.get("Misconfigurations") or []}))'
.tools/bin/trivy fs --quiet --scanners vuln --format json app | grep -c '"CVE-2023-31047"'
(cd app && ../.tools/bin/checkov -d . --framework terraform kubernetes dockerfile -o json --quiet --compact) | python3 -c 'import json,sys; print(sorted({c["check_id"] for f in json.load(sys.stdin) for c in f["results"]["failed_checks"]}))'
```

Expected: the Trivy list includes `DS-0002`, `DS-0026`, `GCP-0001`, `KSV-0012`, `KSV-0013`, `KSV-0105`; the CVE count is ≥ 1; the Checkov list includes `CKV_DOCKER_2`, `CKV_DOCKER_3`, `CKV_GCP_28`, `CKV_K8S_14`, `CKV_K8S_23`. If an id differs, the scanner changed: update `SEEDED.yaml` and re-check `tools.lock`.

- [ ] **Step 7: Commit.**

```bash
git add app tests/test_seeded_ledger.py
git commit -m "Add sample app with seeded issues" -m "Closes #2"
```

---

## Task 3: Guardrail policies: Rego and Semgrep

**Files:**
- Create: `policies/rego/{deny_latest_tag,require_non_root,no_public_bucket}.rego`, `policies/semgrep/drf-allowany.yaml`
- Test: `policies/rego/*_test.rego`

**Interfaces:**
- Produces: Conftest rule ids = Rego package names `deny_latest_tag`, `require_non_root`, `no_public_bucket`; Semgrep rule id `drf-allowany`. Task 5 declares these in `rule_ids`.

- [ ] **Step 1: Write the failing Rego tests.**

`policies/rego/deny_latest_tag_test.rego`:

```rego
package deny_latest_tag

import rego.v1

deployment(image) := {"kind": "Deployment", "spec": {"template": {"spec": {"containers": [{"name": "api", "image": image}]}}}}

test_latest_denied if count(deny) == 1 with input as deployment("ghcr.io/example/api:latest")

test_untagged_denied if count(deny) == 1 with input as deployment("ghcr.io/example/api")

test_registry_port_is_not_a_tag if count(deny) == 1 with input as deployment("registry:5000/api")

test_version_tag_allowed if count(deny) == 0 with input as deployment("ghcr.io/example/api:1.4.2")

test_digest_allowed if count(deny) == 0 with input as deployment("ghcr.io/example/api@sha256:0123abcd")
```

`policies/rego/require_non_root_test.rego`:

```rego
package require_non_root

import rego.v1

deployment(ctx) := {"kind": "Deployment", "spec": {"template": {"spec": {"containers": [object.union({"name": "api"}, ctx)]}}}}

test_missing_context_denied if count(deny) == 1 with input as deployment({})

test_explicit_root_denied if count(deny) == 1 with input as deployment({"securityContext": {"runAsNonRoot": false}})

test_non_root_allowed if count(deny) == 0 with input as deployment({"securityContext": {"runAsNonRoot": true}})

test_other_kinds_ignored if count(deny) == 0 with input as {"kind": "Service"}
```

`policies/rego/no_public_bucket_test.rego`:

```rego
package no_public_bucket

import rego.v1

binding(member) := {"resource": {"google_storage_bucket_iam_member": {"b": [{"member": member}]}}}

test_all_users_denied if count(deny) == 1 with input as binding("allUsers")

test_all_authenticated_users_denied if count(deny) == 1 with input as binding("allAuthenticatedUsers")

test_service_account_allowed if count(deny) == 0 with input as binding("serviceAccount:api@example.iam.gserviceaccount.com")

test_no_buckets_allowed if count(deny) == 0 with input as {"resource": {}}
```

- [ ] **Step 2: Run them to confirm they fail.**

Run: `.tools/bin/conftest verify -p policies/rego --no-color`
Expected: errors, because `deny` is undefined in each package.

- [ ] **Step 3: Write the policies.** Conftest parses each HCL block into a list, so `no_public_bucket` iterates `blocks`.

`policies/rego/deny_latest_tag.rego`:

```rego
package deny_latest_tag

import rego.v1

deny contains msg if {
	input.kind == "Deployment"
	some container in input.spec.template.spec.containers
	not pinned(container.image)
	msg := sprintf("container %q uses unpinned image %q", [container.name, container.image])
}

pinned(image) if contains(image, "@sha256:")

pinned(image) if {
	parts := split(image, "/")
	name := parts[count(parts) - 1]
	contains(name, ":")
	not endswith(name, ":latest")
}
```

`policies/rego/require_non_root.rego`:

```rego
package require_non_root

import rego.v1

deny contains msg if {
	input.kind == "Deployment"
	some container in input.spec.template.spec.containers
	not container.securityContext.runAsNonRoot == true
	msg := sprintf("container %q does not set runAsNonRoot: true", [container.name])
}
```

`policies/rego/no_public_bucket.rego`:

```rego
package no_public_bucket

import rego.v1

public_members := {"allUsers", "allAuthenticatedUsers"}

deny contains msg if {
	some name, blocks in input.resource.google_storage_bucket_iam_member
	some binding in blocks
	binding.member in public_members
	msg := sprintf("bucket IAM binding %q grants access to %s", [name, binding.member])
}
```

- [ ] **Step 4: Run the tests to confirm they pass.**

Run: `make test`
Expected: pytest passes and Conftest reports `13 tests, 13 passed`.

- [ ] **Step 5: Write the vendored Semgrep rule.**

`policies/semgrep/drf-allowany.yaml`:

```yaml
rules:
  - id: drf-allowany
    languages: [python]
    severity: ERROR
    message: DRF view allows unauthenticated access (AllowAny); require an authenticated permission class.
    pattern: permission_classes = [..., AllowAny, ...]
```

- [ ] **Step 6: Confirm each guardrail fires on its seeded file.**

```bash
.tools/bin/conftest test app/k8s/deployment.yaml app/infra/main.tf -p policies/rego --all-namespaces --no-color
.tools/bin/semgrep scan --config policies/semgrep --metrics=off --json --quiet app | python3 -c 'import json,sys; print([r["check_id"] for r in json.load(sys.stdin)["results"]])'
```

Expected: Conftest shows three `FAIL` lines (`require_non_root` and `deny_latest_tag` on `deployment.yaml`, `no_public_bucket` on `main.tf`) and exits 1. Semgrep prints `['policies.semgrep.drf-allowany']`.

- [ ] **Step 7: Commit.**

```bash
git add policies
git commit -m "Add Rego guardrails and Semgrep rule" -m "Closes #3"
```

---

## Task 4: okf_lib: parse the bundle

**Files:**
- Create: `.claude/skills/grc-continuous-compliance/scripts/okf_lib.py`, `tests/fixtures/bundle/**`
- Test: `tests/test_okf_lib.py`

**Interfaces:**
- Produces (used by every later script):
  - `load_bundle(root: Path) -> Bundle`; `BundleError(ValueError)`
  - `Concept(id, path, type, title, description, tags, rule_ids, frontmatter, body, links)` with properties `.code -> str` (`"cc7.1"`) and `.control_tags -> tuple[str, ...]`
  - `Bundle.concepts: Mapping[str, Concept]`, `.of_type(*types) -> list[Concept]`, `.controls()`, `.control(code) -> Concept | None`, `.by_rule(tool, rule_id) -> list[Concept]` (fnmatch globs), `.section(concept, heading) -> str | None`
  - constants `CONTROL_TYPE`, `SCANNER_TYPE`, `COMPONENT_TYPE`, `GUARDRAIL_TYPES = ("Rego Policy", "Semgrep Rule")`

- [ ] **Step 1: Write the fixture bundle.** It is shared by Tasks 4, 7, 9, and 10. It has:
  - four controls (`cc7.2` is evidenced by nothing, so it is not assessed);
  - a Trivy scanner with a `CVE-*` glob;
  - two policies;
  - an orphan policy tagged with a control that is not in the bundle (`cc9.9`);
  - a component with absolute, relative, broken, and external links.

`tests/fixtures/bundle/controls/cc6.1.md`:

```markdown
---
type: SOC 2 Control
title: CC6.1 — Logical Access
description: Fixture control cc6.1.
tags: [soc2, cc6.1, nist-ac-3]
---
# Intent
Logical access.
```

`tests/fixtures/bundle/controls/cc7.1.md`:

```markdown
---
type: SOC 2 Control
title: CC7.1 — Vulnerability Detection
description: Fixture control cc7.1.
tags: [soc2, cc7.1, nist-ra-5]
---
# Intent
Vulnerability detection.
```

`tests/fixtures/bundle/controls/cc7.2.md`:

```markdown
---
type: SOC 2 Control
title: CC7.2 — Monitoring
description: Fixture control cc7.2.
tags: [soc2, cc7.2, nist-si-4]
---
# Intent
Monitoring.
```

`tests/fixtures/bundle/controls/cc8.1.md`:

```markdown
---
type: SOC 2 Control
title: CC8.1 — Change Management
description: Fixture control cc8.1.
tags: [soc2, cc8.1, nist-cm-2]
---
# Intent
Change management.
```

`tests/fixtures/bundle/index.md`:

```markdown
---
okf_version: "0.2"
---
# Fixture bundle

* [Controls](controls/) - three controls
```

`tests/fixtures/bundle/log.md`:

```markdown
# Directory Update Log

## 2026-09-25
* **Initialization**: Test fixture bundle.
```

`tests/fixtures/bundle/policies/deny-latest-tag.md`:

```markdown
---
type: Rego Policy
title: Deny latest tag
description: Fixture policy with no findings in the fixture set.
tags: [opa, cc8.1]
rule_ids: ["conftest:deny_latest_tag"]
---
# Satisfies
- [CC8.1](/controls/cc8.1.md)

# Remediation
Pin an immutable image tag.
```

`tests/fixtures/bundle/policies/orphan.md`:

```markdown
---
type: Rego Policy
title: Orphan policy
description: Fixture policy tagged with a control that is not in the bundle.
tags: [opa, cc9.9]
rule_ids: ["conftest:orphan_rule"]
---
# Remediation
Not applicable.
```

`tests/fixtures/bundle/policies/require-non-root.md`:

```markdown
---
type: Rego Policy
title: Require non-root
description: Fixture policy.
tags: [opa, cc6.1]
rule_ids: ["conftest:require_non_root", "checkov:CKV_TEST_1"]
---
# Satisfies
- [CC6.1](../controls/cc6.1.md)

# Remediation
Run the container as a non-root user.
```

`tests/fixtures/bundle/scanners/trivy.md`:

```markdown
---
type: Scanner
title: Trivy
description: Fixture scanner.
tags: [sca, cc7.1]
rule_ids: ["trivy:CVE-*"]
---
# Evidences
- [CC7.1](/controls/cc7.1.md)

# Remediation
Upgrade the affected dependency to a fixed version.
```

`tests/fixtures/bundle/stack/app.md`:

```markdown
---
type: Stack Component
title: Fixture app
description: Fixture component.
tags: [python]
---
# Controls that apply
- [CC6.1](/controls/cc6.1.md)
- [CC7.1](../controls/cc7.1.md)
- [Not yet written](/controls/missing.md)
- [External](https://example.com/doc.md)
```

- [ ] **Step 2: Write the failing tests.**

`tests/test_okf_lib.py`:

```python
from pathlib import Path

import pytest

from okf_lib import BundleError, load_bundle

FIXTURE = Path(__file__).parent / "fixtures" / "bundle"


def _write(root: Path, rel: str, text: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_loads_concepts_and_skips_reserved_files() -> None:
    bundle = load_bundle(FIXTURE)
    assert "controls/cc6.1" in bundle.concepts
    assert not any(cid.endswith(("index", "log")) for cid in bundle.concepts)


def test_concept_fields() -> None:
    trivy = load_bundle(FIXTURE).concepts["scanners/trivy"]
    assert trivy.type == "Scanner"
    assert trivy.path == "scanners/trivy.md"
    assert trivy.rule_ids == ("trivy:CVE-*",)
    assert trivy.control_tags == ("cc7.1",)
    assert trivy.links == ("controls/cc7.1",)


def test_links_resolve_absolute_and_relative_and_keep_broken() -> None:
    app = load_bundle(FIXTURE).concepts["stack/app"]
    assert app.links == ("controls/cc6.1", "controls/cc7.1", "controls/missing")


def test_controls_and_lookup_by_code() -> None:
    bundle = load_bundle(FIXTURE)
    assert [c.code for c in bundle.controls()] == ["cc6.1", "cc7.1", "cc7.2", "cc8.1"]
    assert bundle.control("cc7.1").title.startswith("CC7.1")
    assert bundle.control("cc9.9") is None


def test_by_rule_exact_and_glob() -> None:
    bundle = load_bundle(FIXTURE)
    assert [c.id for c in bundle.by_rule("checkov", "CKV_TEST_1")] == ["policies/require-non-root"]
    assert [c.id for c in bundle.by_rule("trivy", "CVE-2024-0001")] == ["scanners/trivy"]
    assert bundle.by_rule("trivy", "DS026") == []
    assert bundle.by_rule("checkov", "CVE-2024-0001") == []


def test_section() -> None:
    bundle = load_bundle(FIXTURE)
    trivy = bundle.concepts["scanners/trivy"]
    assert bundle.section(trivy, "Remediation") == "Upgrade the affected dependency to a fixed version."
    assert bundle.section(trivy, "Nope") is None


def test_missing_type_is_rejected(tmp_path: Path) -> None:
    _write(tmp_path, "a.md", "---\ntitle: no type\n---\nbody\n")
    with pytest.raises(BundleError, match="a.md"):
        load_bundle(tmp_path)


def test_missing_frontmatter_is_rejected(tmp_path: Path) -> None:
    _write(tmp_path, "sub/b.md", "just markdown\n")
    with pytest.raises(BundleError, match="sub/b.md"):
        load_bundle(tmp_path)


def test_unknown_type_and_keys_are_tolerated(tmp_path: Path) -> None:
    _write(tmp_path, "c.md", "---\ntype: Mystery\nwhatever: 1\n---\n")
    concept = load_bundle(tmp_path).concepts["c"]
    assert concept.type == "Mystery"
    assert concept.frontmatter["whatever"] == 1
    assert concept.title == "c"
```

- [ ] **Step 3: Run them to confirm they fail.**

Run: `uv run pytest tests/test_okf_lib.py -q`
Expected: FAIL, `ModuleNotFoundError: No module named 'okf_lib'`.

- [ ] **Step 4: Implement.**

`.claude/skills/grc-continuous-compliance/scripts/okf_lib.py`:

```python
"""Load an OKF v0.2 bundle into an in-memory concept graph."""

from __future__ import annotations

import posixpath
import re
from collections.abc import Mapping
from dataclasses import dataclass
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any

import yaml

RESERVED = frozenset({"index.md", "log.md"})
CONTROL_TYPE = "SOC 2 Control"
SCANNER_TYPE = "Scanner"
GUARDRAIL_TYPES = ("Rego Policy", "Semgrep Rule")
COMPONENT_TYPE = "Stack Component"
_CONTROL_TAG = re.compile(r"^cc\d+\.\d+$")
_FRONTMATTER = re.compile(r"\A---\n(.*?)\n---\n?(.*)\Z", re.S)
_LINK = re.compile(r"\[[^\]]*\]\(([^)\s]+)\)")
_H1 = re.compile(r"^# (.+?)\s*$", re.M)


class BundleError(ValueError):
    """A bundle file violates OKF v0.2 conformance (§11)."""


@dataclass(frozen=True)
class Concept:
    """One OKF concept document."""

    id: str
    path: str
    type: str
    title: str
    description: str
    tags: tuple[str, ...]
    rule_ids: tuple[str, ...]
    frontmatter: Mapping[str, Any]
    body: str
    links: tuple[str, ...]

    @property
    def code(self) -> str:
        """Last path segment of the id, e.g. 'cc7.1' for 'controls/cc7.1'."""
        return self.id.rsplit("/", 1)[-1]

    @property
    def control_tags(self) -> tuple[str, ...]:
        """Tags naming a SOC 2 criterion, e.g. ('cc7.1',)."""
        return tuple(t for t in self.tags if _CONTROL_TAG.match(t))


@dataclass(frozen=True)
class Bundle:
    """All concepts in a bundle, keyed by concept id."""

    concepts: Mapping[str, Concept]

    def of_type(self, *types: str) -> list[Concept]:
        """Concepts of the given type(s), sorted by id."""
        return sorted((c for c in self.concepts.values() if c.type in types), key=lambda c: c.id)

    def controls(self) -> list[Concept]:
        """SOC 2 control concepts, sorted by id."""
        return self.of_type(CONTROL_TYPE)

    def control(self, code: str) -> Concept | None:
        """The control concept whose code is `code`, if the bundle has one."""
        return next((c for c in self.controls() if c.code == code), None)

    def by_rule(self, tool: str, rule_id: str) -> list[Concept]:
        """Concepts whose `rule_ids` declare coverage of this scanner rule (globs allowed)."""
        return [
            c
            for c in sorted(self.concepts.values(), key=lambda c: c.id)
            if any(_rule_matches(entry, tool, rule_id) for entry in c.rule_ids)
        ]

    def section(self, concept: Concept, heading: str) -> str | None:
        """Body text under `# heading`, up to the next level-1 heading."""
        matches = list(_H1.finditer(concept.body))
        for i, m in enumerate(matches):
            if m.group(1) == heading:
                end = matches[i + 1].start() if i + 1 < len(matches) else len(concept.body)
                return concept.body[m.end() : end].strip()
        return None


def _rule_matches(entry: str, tool: str, rule_id: str) -> bool:
    entry_tool, _, pattern = entry.partition(":")
    return entry_tool == tool and fnmatchcase(rule_id, pattern)


def _resolve_link(target: str, concept_path: str) -> str | None:
    """Bundle-relative concept id for a markdown link, or None if it is not a concept link."""
    target = target.split("#", 1)[0]
    if "://" in target or target.startswith("mailto:") or not target.endswith(".md"):
        return None
    if target.startswith("/"):
        resolved = posixpath.normpath(target.lstrip("/"))
    else:
        resolved = posixpath.normpath(posixpath.join(posixpath.dirname(concept_path), target))
    if resolved.startswith("..") or posixpath.basename(resolved) in RESERVED:
        return None
    return resolved.removesuffix(".md")


def _parse(rel_path: str, text: str) -> Concept:
    m = _FRONTMATTER.match(text)
    if not m:
        raise BundleError(f"{rel_path}: missing YAML frontmatter")
    try:
        fm = yaml.safe_load(m.group(1)) or {}
    except yaml.YAMLError as e:
        raise BundleError(f"{rel_path}: unparseable frontmatter: {e}") from e
    if not isinstance(fm, dict) or not str(fm.get("type") or "").strip():
        raise BundleError(f"{rel_path}: frontmatter has no non-empty 'type'")
    body = m.group(2)
    stem = rel_path.removesuffix(".md")
    return Concept(
        id=stem,
        path=rel_path,
        type=str(fm["type"]).strip(),
        title=str(fm.get("title") or posixpath.basename(stem)),
        description=str(fm.get("description") or ""),
        tags=tuple(str(t) for t in fm.get("tags") or ()),
        rule_ids=tuple(str(r) for r in fm.get("rule_ids") or ()),
        frontmatter=fm,
        body=body,
        links=tuple(
            dict.fromkeys(
                link for t in _LINK.findall(body) if (link := _resolve_link(t, rel_path)) is not None
            )
        ),
    )


def load_bundle(root: Path) -> Bundle:
    """Parse every non-reserved .md under `root` into a Bundle."""
    concepts: dict[str, Concept] = {}
    for path in sorted(root.rglob("*.md")):
        if path.name in RESERVED:
            continue
        rel = path.relative_to(root).as_posix()
        concept = _parse(rel, path.read_text(encoding="utf-8"))
        concepts[concept.id] = concept
    return Bundle(concepts=concepts)
```

- [ ] **Step 5: Run the tests to confirm they pass.**

Run: `uv run pytest tests/test_okf_lib.py -q`
Expected: `9 passed`.

- [ ] **Step 6: Commit.**

```bash
git add .claude/skills/grc-continuous-compliance/scripts/okf_lib.py tests/fixtures/bundle tests/test_okf_lib.py
git commit -m "Add OKF bundle parser" -m "Closes #4"
```

---

## Task 5: OKF knowledge bundle

**Files:**
- Create: `knowledge/**` (18 concepts, 5 `index.md`, 1 `log.md`)
- Test: `tests/test_bundle_conformance.py`

**Interfaces:**
- Consumes: `okf_lib` (Task 4); rule ids from Tasks 2–3.
- Produces: control codes `cc6.1 cc6.6 cc7.1 cc7.2 cc8.1`; guardrail concepts carrying `rule_ids` and `# Remediation`.

The NIST mappings and remediation text are drafted judgments. Task 6 is where they get reviewed. If you author a file by hand rather than taking the draft, set its `generated.by` to `human:cdevarenne`.

- [ ] **Step 1: Write the failing conformance test.**

`tests/test_bundle_conformance.py`:

```python
"""The real knowledge/ bundle: OKF v0.2 conformance plus this repo's grounding conventions."""

import re
from pathlib import Path

import pytest
import yaml

from okf_lib import load_bundle

KNOWLEDGE = Path(__file__).parent.parent / "knowledge"
TOOLS = {"semgrep", "trivy", "checkov", "conftest"}
TYPES = {"SOC 2 Control", "Stack Component", "Rego Policy", "Semgrep Rule", "Scanner", "Reference"}
BUNDLE = load_bundle(KNOWLEDGE)  # raises BundleError on a missing or empty `type` (OKF §11)


def test_bundle_has_the_five_controls() -> None:
    assert [c.code for c in BUNDLE.controls()] == ["cc6.1", "cc6.6", "cc7.1", "cc7.2", "cc8.1"]


def test_types_are_the_documented_set() -> None:
    assert {c.type for c in BUNDLE.concepts.values()} <= TYPES


@pytest.mark.parametrize("concept", BUNDLE.concepts.values(), ids=lambda c: c.id)
def test_required_metadata(concept) -> None:
    fm = concept.frontmatter
    assert fm.get("title") and fm.get("description") and fm.get("tags"), concept.path
    assert fm.get("generated", {}).get("by") and fm["generated"].get("at"), concept.path


@pytest.mark.parametrize("concept", [c for c in BUNDLE.concepts.values() if c.rule_ids], ids=lambda c: c.id)
def test_rule_declarations_are_grounded(concept) -> None:
    for entry in concept.rule_ids:
        tool, _, rule = entry.partition(":")
        assert tool in TOOLS and rule, f"{concept.path}: malformed rule id {entry!r}"
        assert rule != "*", f"{concept.path}: bare wildcard {entry!r} would map every {tool} finding"
    assert len(concept.control_tags) == 1, f"{concept.path}: rule_ids need exactly one control tag"


def test_every_control_tag_names_a_control() -> None:
    for concept in BUNDLE.concepts.values():
        for tag in concept.control_tags:
            assert BUNDLE.control(tag), f"{concept.path}: tag {tag} has no control concept"


def test_controls_carry_their_own_code_as_tag() -> None:
    for control in BUNDLE.controls():
        assert control.code in control.tags, control.path


def test_no_broken_links() -> None:
    for concept in BUNDLE.concepts.values():
        for link in concept.links:
            assert link in BUNDLE.concepts, f"{concept.path}: broken link to {link}"


def test_index_files_have_no_frontmatter_except_root_version() -> None:
    for index in KNOWLEDGE.rglob("index.md"):
        text = index.read_text(encoding="utf-8")
        if index.parent == KNOWLEDGE:
            fm = yaml.safe_load(text.split("---\n")[1])
            assert fm == {"okf_version": "0.2"}
        else:
            assert not text.startswith("---"), index


def test_log_dates_are_iso() -> None:
    for log in KNOWLEDGE.rglob("log.md"):
        for heading in re.findall(r"^## (.+)$", log.read_text(encoding="utf-8"), re.M):
            assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", heading), f"{log}: {heading}"


def test_links_are_relative() -> None:
    """The pinned OKF visualizer ignores bundle-absolute links, so the bundle uses relative ones."""
    for concept in BUNDLE.concepts.values():
        assert "](/" not in concept.body, f"{concept.path}: use a relative link"
```

- [ ] **Step 2: Run it to confirm it fails.**

Run: `uv run pytest tests/test_bundle_conformance.py -q`
Expected: `test_bundle_has_the_five_controls` FAILS (`assert [] == [...]`). With no `knowledge/` the other checks have nothing to inspect, which is why this test exists.

- [ ] **Step 3: Write the bundle.**

`knowledge/controls/cc6.1.md`:

```markdown
---
type: SOC 2 Control
title: CC6.1 — Logical Access
description: Access to systems and data is restricted to authorized, least-privileged identities.
tags: [soc2, cc6.1, nist-ac-2, nist-ac-3, nist-ac-6]
generated:
  by: claude-code/claude-opus-5-5
  at: "2026-09-25T00:00:00+00:00"
---
# Intent

Only authenticated, authorized identities reach protected functions and data,
and workloads run with the least privilege they need.

# NIST SP 800-53 mapping

- **AC-2** — Account Management
- **AC-3** — Access Enforcement
- **AC-6** — Least Privilege

# Satisfied by

- [Require non-root containers](../policies/require-non-root.md)
- [DRF writes require authentication](../policies/drf-authenticated-writes.md)

# Evidenced by

- [Semgrep](../scanners/semgrep.md) — authorization rules in application code

# Applies to

- [Sample Django / DRF API](../stack/django-api.md)
- [Container image](../stack/container.md)
- [Kubernetes manifests](../stack/k8s.md)
```

`knowledge/controls/cc6.6.md`:

```markdown
---
type: SOC 2 Control
title: CC6.6 — System Boundary Protection
description: Resources are protected from access originating outside the system boundary.
tags: [soc2, cc6.6, nist-sc-7, nist-sc-8]
generated:
  by: claude-code/claude-opus-5-5
  at: "2026-09-25T00:00:00+00:00"
---
# Intent

Nothing inside the system boundary is reachable anonymously from outside it,
and data crossing the boundary is protected in transit.

# NIST SP 800-53 mapping

- **SC-7** — Boundary Protection
- **SC-8** — Transmission Confidentiality and Integrity

# Satisfied by

- [No public buckets](../policies/no-public-bucket.md)

# Evidenced by

- [Checkov](../scanners/checkov.md) — IaC boundary checks

# Applies to

- [Terraform module](../stack/terraform.md)
```

`knowledge/controls/cc7.1.md`:

```markdown
---
type: SOC 2 Control
title: CC7.1 — Vulnerability Detection
description: Vulnerabilities in code, dependencies, images, and configuration are detected.
tags: [soc2, cc7.1, nist-ra-5, nist-si-2]
generated:
  by: claude-code/claude-opus-5-5
  at: "2026-09-25T00:00:00+00:00"
---
# Intent

Known vulnerabilities across the software supply chain are detected before
they can be exploited: source, third-party dependencies, and container images.

# NIST SP 800-53 mapping

- **RA-5** — Vulnerability Monitoring and Scanning
- **SI-2** — Flaw Remediation

# Evidenced by

- [Trivy](../scanners/trivy.md) — dependency and image CVEs
- [Semgrep](../scanners/semgrep.md) — static analysis

# Applies to

- [Sample Django / DRF API](../stack/django-api.md)
- [Container image](../stack/container.md)
```

`knowledge/controls/cc7.2.md`:

```markdown
---
type: SOC 2 Control
title: CC7.2 — Security Monitoring
description: System components are monitored for anomalous and malicious activity.
tags: [soc2, cc7.2, nist-si-4, nist-au-6]
generated:
  by: claude-code/claude-opus-5-5
  at: "2026-09-25T00:00:00+00:00"
---
# Intent

Running workloads are monitored so anomalies and attacks are detected and
acted on.

# NIST SP 800-53 mapping

- **SI-4** — System Monitoring
- **AU-6** — Audit Record Review, Analysis, and Reporting

# Evidenced by

No scanner in this bundle evidences runtime monitoring. A runtime detection
tool is planned for a later version, so this control is reported as
not assessed rather than satisfied.

# Applies to

- [Kubernetes manifests](../stack/k8s.md)
```

`knowledge/controls/cc8.1.md`:

```markdown
---
type: SOC 2 Control
title: CC8.1 — Change Management
description: Changes to infrastructure and software are controlled, reproducible, and reviewed.
tags: [soc2, cc8.1, nist-cm-2, nist-cm-3]
generated:
  by: claude-code/claude-opus-5-5
  at: "2026-09-25T00:00:00+00:00"
---
# Intent

What is deployed is exactly what was reviewed: artifacts are pinned and
changes pass automated policy gates before release.

# NIST SP 800-53 mapping

- **CM-2** — Baseline Configuration
- **CM-3** — Configuration Change Control

# Satisfied by

- [Deny :latest image tag](../policies/deny-latest-tag.md)

# Evidenced by

- [Conftest](../scanners/conftest.md) — policy gate on manifests
- [Checkov](../scanners/checkov.md) — IaC policy scan

# Applies to

- [Kubernetes manifests](../stack/k8s.md)
```

`knowledge/controls/index.md`:

```markdown
# Controls

* [CC6.1 — Logical Access](cc6.1.md) - Access to systems and data is restricted to authorized, least-privileged identities.
* [CC6.6 — System Boundary Protection](cc6.6.md) - Resources are protected from access originating outside the system boundary.
* [CC7.1 — Vulnerability Detection](cc7.1.md) - Vulnerabilities in code, dependencies, images, and configuration are detected.
* [CC7.2 — Security Monitoring](cc7.2.md) - System components are monitored for anomalous and malicious activity.
* [CC8.1 — Change Management](cc8.1.md) - Changes to infrastructure and software are controlled, reproducible, and reviewed.
```

`knowledge/index.md`:

```markdown
---
okf_version: "0.2"
---
# OKF-GRC Knowledge Bundle

Knowledge graph that grounds the `grc-continuous-compliance` skill. Every
finding the skill reports must trace to a control concept here. A finding
with no mapped control is a coverage gap to report, never a license to
invent a mapping.

# Map

* [Controls](controls/) - SOC 2 Trust Services Criteria in scope, mapped to NIST SP 800-53
* [Stack](stack/) - the sample app and its infrastructure
* [Policies](policies/) - guardrails (Rego, Semgrep) and the scanner rules that detect each
* [Scanners](scanners/) - DevSecOps tools and the controls they evidence
* [OSCAL output](oscal/component-definition.md) - the machine-readable output target
```

`knowledge/log.md`:

```markdown
# Directory Update Log

## 2026-09-25
* **Initialization**: Created the bundle: 5 controls, 4 stack components, 4 guardrail policies, 4 scanners, and the OSCAL reference.
```

`knowledge/oscal/component-definition.md`:

```markdown
---
type: Reference
title: OSCAL output
description: The OSCAL 1.2.3 component-definition and assessment-results the skill emits.
resource: https://pages.nist.gov/OSCAL/
tags: [oscal, nist]
generated:
  by: claude-code/claude-opus-5-5
  at: "2026-09-25T00:00:00+00:00"
---
# Output

- `out/oscal/component-definition.json` — each [stack component](../stack/index.md)
  with the controls that apply to it as implemented requirements.
- `out/oscal/assessment-results.json` — one result: findings per assessed
  control, observations per scanner finding, and coverage gaps as open risks.

# Subset

v1 emits a documented subset of OSCAL, not full conformance. The fields used,
and the placeholders for required fields the demo does not model, are listed in
`docs/oscal-subset.md`.
```

`knowledge/policies/deny-latest-tag.md`:

```markdown
---
type: Rego Policy
title: Deny :latest image tag
description: Deployments must pin an immutable image tag or digest.
resource: ../../policies/rego/deny_latest_tag.rego
tags: [opa, conftest, kubernetes, cc8.1]
rule_ids:
  - conftest:deny_latest_tag
  - checkov:CKV_K8S_14
  - trivy:KSV-0013
generated:
  by: claude-code/claude-opus-5-5
  at: "2026-09-25T00:00:00+00:00"
---
# Rule

`:latest` (or no tag) means the running image can change without a change
record, which breaks reproducibility and change control.

# Satisfies

- [CC8.1 — Change Management](../controls/cc8.1.md)

# Enforced at

- Deploy gate: Conftest in CI, blocking
- Also detected by Checkov and Trivy (listed in `rule_ids`)

# Remediation

Pin every container image to a released version tag or an `@sha256:` digest,
and update it only through a reviewed change.
```

`knowledge/policies/drf-authenticated-writes.md`:

```markdown
---
type: Semgrep Rule
title: DRF writes require authentication
description: API views must not use AllowAny.
resource: ../../policies/semgrep/drf-allowany.yaml
tags: [semgrep, django, cc6.1]
rule_ids:
  - semgrep:drf-allowany
generated:
  by: claude-code/claude-opus-5-5
  at: "2026-09-25T00:00:00+00:00"
---
# Rule

`AllowAny` on a DRF view lets unauthenticated callers use every action the
view exposes, including create, update, and delete.

# Satisfies

- [CC6.1 — Logical Access](../controls/cc6.1.md)

# Enforced at

- Semgrep in CI, using the vendored ruleset in `policies/semgrep/`

# Remediation

Replace `AllowAny` with an authenticated permission class (for example
`IsAuthenticated`, or `IsAuthenticatedOrReadOnly` for public reads).
```

`knowledge/policies/index.md`:

```markdown
# Policies

Each guardrail declares, in `rule_ids`, every scanner rule that detects a
violation of it. A concept that declares `rule_ids` carries exactly one
control tag.

* [Require non-root containers](require-non-root.md) - Containers and images must not run as root.
* [Deny :latest image tag](deny-latest-tag.md) - Deployments must pin an immutable image tag or digest.
* [No public buckets](no-public-bucket.md) - Storage buckets must not grant access to allUsers or allAuthenticatedUsers.
* [DRF writes require authentication](drf-authenticated-writes.md) - API views must not use AllowAny.
```

`knowledge/policies/no-public-bucket.md`:

```markdown
---
type: Rego Policy
title: No public buckets
description: Storage buckets must not grant access to allUsers or allAuthenticatedUsers.
resource: ../../policies/rego/no_public_bucket.rego
tags: [opa, conftest, terraform, cc6.6]
rule_ids:
  - conftest:no_public_bucket
  - checkov:CKV_GCP_28
  - checkov:CKV_GCP_114
  - trivy:GCP-0001
generated:
  by: claude-code/claude-opus-5-5
  at: "2026-09-25T00:00:00+00:00"
---
# Rule

An IAM binding to `allUsers` or `allAuthenticatedUsers` exposes bucket
contents to anyone on the internet, outside the system boundary.

# Satisfies

- [CC6.6 — System Boundary Protection](../controls/cc6.6.md)

# Enforced at

- Deploy gate: Conftest on Terraform, blocking
- Also detected by Checkov and Trivy (listed in `rule_ids`)

# Remediation

Remove public IAM members from the bucket, grant access to named service
accounts only, and enforce public access prevention on the bucket.
```

`knowledge/policies/require-non-root.md`:

```markdown
---
type: Rego Policy
title: Require non-root containers
description: Containers and images must not run as root.
resource: ../../policies/rego/require_non_root.rego
tags: [opa, conftest, kubernetes, cc6.1]
rule_ids:
  - conftest:require_non_root
  - checkov:CKV_K8S_23
  - checkov:CKV_DOCKER_3
  - trivy:KSV-0012
  - trivy:KSV-0105
  - trivy:DS-0002
generated:
  by: claude-code/claude-opus-5-5
  at: "2026-09-25T00:00:00+00:00"
---
# Rule

A process running as root inside a container turns any code-execution bug into
root on the container and widens the path to the node. Workloads must set
`runAsNonRoot: true` and images must switch to a non-root `USER`.

# Satisfies

- [CC6.1 — Logical Access](../controls/cc6.1.md)

# Enforced at

- Deploy gate: Conftest in CI, blocking
- Also detected by Checkov and Trivy (listed in `rule_ids`)

# Remediation

Add a non-root `USER` to the Dockerfile and set `securityContext.runAsNonRoot: true`
(with a non-zero `runAsUser`) on every container in the Deployment.
```

`knowledge/scanners/checkov.md`:

```markdown
---
type: Scanner
title: Checkov
description: Infrastructure-as-code policy scan.
resource: https://github.com/bridgecrewio/checkov
tags: [iac, cc6.6, cc8.1]
generated:
  by: claude-code/claude-opus-5-5
  at: "2026-09-25T00:00:00+00:00"
---
# Covers

Terraform, Kubernetes, and Dockerfile misconfigurations.

# Evidences

- [CC6.6 — System Boundary Protection](../controls/cc6.6.md)
- [CC8.1 — Change Management](../controls/cc8.1.md)

# Rules

Rule-to-control declarations live on guardrail concepts, for example
[No public buckets](../policies/no-public-bucket.md).
```

`knowledge/scanners/conftest.md`:

```markdown
---
type: Scanner
title: Conftest
description: Runs the Rego guardrails as a deploy gate.
resource: https://github.com/open-policy-agent/conftest
tags: [opa, policy, cc8.1]
generated:
  by: claude-code/claude-opus-5-5
  at: "2026-09-25T00:00:00+00:00"
---
# Covers

Evaluates `policies/rego/` against the Kubernetes manifests and Terraform.
Each Rego package name is the rule id.

# Evidences

- [CC8.1 — Change Management](../controls/cc8.1.md)

# Rules

- [Require non-root containers](../policies/require-non-root.md)
- [Deny :latest image tag](../policies/deny-latest-tag.md)
- [No public buckets](../policies/no-public-bucket.md)
```

`knowledge/scanners/index.md`:

```markdown
# Scanners

* [Semgrep](semgrep.md) - Static analysis of application code.
* [Trivy](trivy.md) - Dependency and image CVEs, and configuration checks.
* [Checkov](checkov.md) - Infrastructure-as-code policy scan.
* [Conftest](conftest.md) - Runs the Rego guardrails as a deploy gate.
```

`knowledge/scanners/semgrep.md`:

```markdown
---
type: Scanner
title: Semgrep
description: Static analysis of application code.
resource: https://github.com/semgrep/semgrep
tags: [sast, cc6.1, cc7.1]
generated:
  by: claude-code/claude-opus-5-5
  at: "2026-09-25T00:00:00+00:00"
---
# Covers

Pattern-based static analysis of the Python source, using the vendored ruleset
in `policies/semgrep/` so results are offline and reproducible.

# Evidences

- [CC6.1 — Logical Access](../controls/cc6.1.md)
- [CC7.1 — Vulnerability Detection](../controls/cc7.1.md)

# Rules

Rule-to-control declarations live on guardrail concepts, for example
[DRF writes require authentication](../policies/drf-authenticated-writes.md).
```

`knowledge/scanners/trivy.md`:

```markdown
---
type: Scanner
title: Trivy
description: Dependency and image CVEs, and configuration checks.
resource: https://github.com/aquasecurity/trivy
tags: [sca, container, iac, cc7.1]
rule_ids:
  - "trivy:CVE-*"
  - "trivy:GHSA-*"
generated:
  by: claude-code/claude-opus-5-5
  at: "2026-09-25T00:00:00+00:00"
---
# Covers

Known vulnerabilities in dependencies (`trivy fs`) and misconfigurations in the
Dockerfile, Kubernetes manifests, and Terraform (`trivy config`).

# Evidences

- [CC7.1 — Vulnerability Detection](../controls/cc7.1.md)

# Rules

Every vulnerability id (`CVE-*`, `GHSA-*`) evidences CC7.1. Configuration
rules are declared on the guardrail they detect, for example
[Require non-root containers](../policies/require-non-root.md).

# Remediation

Upgrade each vulnerable dependency to a version that fixes the listed
advisories, then re-scan.
```

`knowledge/stack/container.md`:

```markdown
---
type: Stack Component
title: Container image
description: The API's Dockerfile.
resource: ../../app/Dockerfile
tags: [docker, image]
generated:
  by: claude-code/claude-opus-5-5
  at: "2026-09-25T00:00:00+00:00"
---
# What it is

The image definition for the API.

# Controls that apply

- [CC6.1 — Logical Access](../controls/cc6.1.md)
- [CC7.1 — Vulnerability Detection](../controls/cc7.1.md)

# Scanned by

- [Trivy](../scanners/trivy.md)
- [Checkov](../scanners/checkov.md)
```

`knowledge/stack/django-api.md`:

```markdown
---
type: Stack Component
title: Sample Django / DRF API
description: Minimal widgets REST API; the application code under scan.
resource: ../../app/widgets/
tags: [django, drf, python]
generated:
  by: claude-code/claude-opus-5-5
  at: "2026-09-25T00:00:00+00:00"
---
# What it is

A deliberately small Django REST Framework API with seeded, fixable issues so
the scan loop has something real to find. Not a production system.

# Controls that apply

- [CC6.1 — Logical Access](../controls/cc6.1.md)
- [CC7.1 — Vulnerability Detection](../controls/cc7.1.md)

# Scanned by

- [Semgrep](../scanners/semgrep.md)
- [Trivy](../scanners/trivy.md)
```

`knowledge/stack/index.md`:

```markdown
# Stack

* [Sample Django / DRF API](django-api.md) - Minimal widgets REST API; the application code under scan.
* [Container image](container.md) - The API's Dockerfile.
* [Kubernetes manifests](k8s.md) - Deployment and Service for the API.
* [Terraform module](terraform.md) - Storage bucket and service account for the API.
```

`knowledge/stack/k8s.md`:

```markdown
---
type: Stack Component
title: Kubernetes manifests
description: Deployment and Service for the API.
resource: ../../app/k8s/
tags: [kubernetes]
generated:
  by: claude-code/claude-opus-5-5
  at: "2026-09-25T00:00:00+00:00"
---
# What it is

The Deployment and Service that run the API. This is the policy enforcement
point for the Rego guardrails.

# Controls that apply

- [CC6.1 — Logical Access](../controls/cc6.1.md)
- [CC7.2 — Security Monitoring](../controls/cc7.2.md)
- [CC8.1 — Change Management](../controls/cc8.1.md)

# Scanned by

- [Conftest](../scanners/conftest.md)
- [Checkov](../scanners/checkov.md)
- [Trivy](../scanners/trivy.md)
```

`knowledge/stack/terraform.md`:

```markdown
---
type: Stack Component
title: Terraform module
description: Storage bucket and service account for the API.
resource: ../../app/infra/main.tf
tags: [terraform, iac, gcp]
generated:
  by: claude-code/claude-opus-5-5
  at: "2026-09-25T00:00:00+00:00"
---
# What it is

A generic storage bucket, an IAM binding on it, and a service account.

# Controls that apply

- [CC6.6 — System Boundary Protection](../controls/cc6.6.md)

# Scanned by

- [Checkov](../scanners/checkov.md)
- [Trivy](../scanners/trivy.md)
- [Conftest](../scanners/conftest.md)
```

- [ ] **Step 4: Run the tests to confirm they pass.**

Run: `uv run pytest tests/test_bundle_conformance.py -q`
Expected: all pass (about 40 parametrized cases).

- [ ] **Step 5: Confirm the check can fail.** Temporarily change `"trivy:GHSA-*"` to `"trivy:*"` in `knowledge/scanners/trivy.md` and re-run.
Expected: FAIL, `bare wildcard 'trivy:*' would map every trivy finding`. Revert with `git checkout knowledge/scanners/trivy.md`.

- [ ] **Step 6: Commit.**

```bash
git add knowledge tests/test_bundle_conformance.py
git commit -m "Add OKF knowledge bundle" -m "Closes #5"
```

---

## Task 6: Human review of the bundle — HUMAN GATE

**An executing agent stops here and hands off to the repo owner.** This is the review a GRC reader will scrutinize.

**Files:**
- Modify: every concept under `knowledge/` (add `verified`)
- Modify: `tests/test_bundle_conformance.py` (append one test)

- [ ] **Step 1: Append the failing test.**

```python

@pytest.mark.parametrize("concept", BUNDLE.concepts.values(), ids=lambda c: c.id)
def test_every_concept_is_human_verified(concept) -> None:
    verified = concept.frontmatter.get("verified")
    entries = verified if isinstance(verified, list) else [verified] if verified else []
    assert any(str(e.get("by", "")).startswith("human:") for e in entries), f"{concept.path}: not human-verified"
```

- [ ] **Step 2: Run it to confirm it fails.**

Run: `uv run pytest tests/test_bundle_conformance.py -q -k human_verified`
Expected: 18 failures, `not human-verified`.

- [ ] **Step 3: Review each concept.** Check:
  - control intent paraphrases, and the NIST SP 800-53 mappings (AC-2/3/6, SC-7/8, RA-5, SI-2, SI-4, AU-6, CM-2/3);
  - that every `rule_ids` entry really detects the guardrail it is declared on;
  - that the remediation text is correct.

  Edit where you disagree, then add this to each concept's frontmatter, using the review time:

```yaml
verified:
  - by: "human:cdevarenne"
    at: "2026-10-01T10:00:00+01:00"
```

- [ ] **Step 4: Run the tests to confirm they pass.**

Run: `uv run pytest -q`
Expected: all pass.

- [ ] **Step 5: Log and commit.** Add a dated entry to `knowledge/log.md`, e.g. `* **Update**: Human review of all concepts; verified recorded.`, then:

```bash
git add knowledge tests/test_bundle_conformance.py
git commit -m "Record human review of the bundle" -m "Closes #6"
```

---

## Task 7: map_findings: the grounding gate

**Files:**
- Create: `.claude/skills/grc-continuous-compliance/scripts/map_findings.py`, `tests/fixtures/findings.json`
- Test: `tests/test_map_findings.py`

**Interfaces:**
- Consumes: `load_bundle`, `Bundle.by_rule`, `.control`, `.controls`, `.of_type`, `GUARDRAIL_TYPES`, `SCANNER_TYPE`.
- Produces: `map_findings(bundle: Bundle, findings: list[dict]) -> dict` returning `{"controls": {code: {status, findings, evidenced_by, satisfied_by}}, "unmapped": [{finding, reason}]}`. `status` ∈ `not-satisfied|satisfied|not-assessed`; `reason` ∈ `no-rule-match|control-not-in-bundle`. The CLI reads `out/findings.json` and writes `out/mapping.json`.

- [ ] **Step 1: Write the hand-written findings.** Three mapped (one through the `CVE-*` glob), one `no-rule-match`, one `control-not-in-bundle`. These fixtures are permanent.

`tests/fixtures/findings.json`:

```json
[
  {"tool": "conftest", "rule_id": "require_non_root", "severity": "high", "target": "app/k8s/deployment.yaml", "message": "container runs as root", "tags": []},
  {"tool": "checkov", "rule_id": "CKV_TEST_1", "severity": "medium", "target": "app/k8s/deployment.yaml", "message": "runAsNonRoot not set", "tags": []},
  {"tool": "trivy", "rule_id": "CVE-2024-0001", "severity": "critical", "target": "app/requirements.txt", "message": "example-pkg 1.0 vulnerable", "tags": []},
  {"tool": "checkov", "rule_id": "CKV_TEST_99", "severity": "low", "target": "app/Dockerfile", "message": "no HEALTHCHECK", "tags": []},
  {"tool": "conftest", "rule_id": "orphan_rule", "severity": "medium", "target": "app/infra/main.tf", "message": "orphan", "tags": []}
]
```

- [ ] **Step 2: Write the failing tests.**

`tests/test_map_findings.py`:

```python
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
        "cc8.1": "satisfied",
    }


def test_evidence_links(mapping: dict) -> None:
    assert mapping["controls"]["cc7.1"]["evidenced_by"] == ["scanners/trivy"]
    assert mapping["controls"]["cc8.1"]["satisfied_by"] == ["policies/deny-latest-tag"]
```

- [ ] **Step 3: Run them to confirm they fail.**

Run: `uv run pytest tests/test_map_findings.py -q`
Expected: FAIL, `ModuleNotFoundError: No module named 'map_findings'`.

- [ ] **Step 4: Implement.**

`.claude/skills/grc-continuous-compliance/scripts/map_findings.py`:

```python
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


def _carriers(bundle: Bundle, types: tuple[str, ...], code: str) -> list[str]:
    return [c.id for c in bundle.of_type(*types) if code in c.control_tags]


def map_findings(bundle: Bundle, findings: list[Finding]) -> dict[str, Any]:
    """Build the mapping document (spec §5.4) from a bundle and findings."""
    controls: dict[str, dict[str, Any]] = {
        c.code: {
            "status": "",
            "findings": [],
            "evidenced_by": _carriers(bundle, (SCANNER_TYPE,), c.code),
            "satisfied_by": _carriers(bundle, GUARDRAIL_TYPES, c.code),
        }
        for c in bundle.controls()
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
            entry["status"] = "satisfied"
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
```

- [ ] **Step 5: Run the tests to confirm they pass.**

Run: `uv run pytest tests/test_map_findings.py -q`
Expected: `7 passed`.

- [ ] **Step 6: Commit.**

```bash
git add .claude/skills/grc-continuous-compliance/scripts/map_findings.py tests/fixtures/findings.json tests/test_map_findings.py
git commit -m "Add grounded finding-to-control mapping" -m "Closes #7"
```

---

## Task 8: run_scan: scanners and normalizers (parallelizable)

**Files:**
- Create: `.claude/skills/grc-continuous-compliance/scripts/run_scan.py`, `tests/fixtures/scanner_output/{semgrep,trivy-config,trivy-fs,checkov,conftest}.json`
- Test: `tests/test_run_scan.py`

**Interfaces:**
- Produces: `scan(repo: Path, target_dir: str) -> list[dict]` producing findings `{tool, rule_id, severity, target, message, tags}`; `normalize_{semgrep,trivy,checkov,conftest}(doc, target_dir) -> list[dict]`; `dedupe(findings)`; `run_tool(tool, argv, cwd) -> Any`; `ScanError`. The CLI (`--target app --out out`, run from the repo root) writes `out/findings.json`.

- [ ] **Step 1: Write the scanner-output fixtures.** They are trimmed from real pinned-scanner output on the sample app, with the fields kept as the tools emit them.

`tests/fixtures/scanner_output/semgrep.json`:

```json
{
  "results": [
    {
      "check_id": "policies.semgrep.drf-allowany",
      "path": "app/widgets/views.py",
      "start": {
        "line": 11
      },
      "extra": {
        "message": "DRF view allows unauthenticated access (AllowAny); require an authenticated permission class.",
        "severity": "ERROR"
      }
    }
  ],
  "errors": []
}
```

`tests/fixtures/scanner_output/trivy-config.json`:

```json
{
  "Results": [
    {
      "Target": "Dockerfile",
      "Class": "config",
      "Misconfigurations": [
        {
          "ID": "DS-0002",
          "Title": "Image user should not be 'root'",
          "Message": "Specify at least 1 USER command in Dockerfile with non-root user as argument",
          "Severity": "HIGH",
          "Status": "FAIL"
        },
        {
          "ID": "DS-0026",
          "Title": "No HEALTHCHECK defined",
          "Message": "Add HEALTHCHECK instruction in your Dockerfile",
          "Severity": "LOW",
          "Status": "FAIL"
        }
      ]
    },
    {
      "Target": "k8s/deployment.yaml",
      "Class": "config",
      "Misconfigurations": [
        {
          "ID": "KSV-0013",
          "Title": "Image tag \":latest\" used",
          "Message": "Container 'api' of Deployment 'widgets-api' should specify an image tag",
          "Severity": "MEDIUM",
          "Status": "FAIL"
        }
      ]
    }
  ]
}
```

`tests/fixtures/scanner_output/trivy-fs.json`:

```json
{
  "Results": [
    {
      "Target": "requirements.txt",
      "Class": "lang-pkgs",
      "Vulnerabilities": [
        {
          "VulnerabilityID": "CVE-2023-31047",
          "PkgName": "Django",
          "InstalledVersion": "4.2.0",
          "Severity": "CRITICAL",
          "Title": "python-django: Potential bypass of validation when uploading multiple files using one form field"
        }
      ]
    }
  ]
}
```

`tests/fixtures/scanner_output/checkov.json`:

```json
[
  {
    "check_type": "terraform",
    "results": {
      "failed_checks": [
        {
          "check_id": "CKV_GCP_28",
          "check_name": "Ensure that Cloud Storage bucket is not anonymously or publicly accessible",
          "file_path": "/infra/main.tf",
          "resource": "google_storage_bucket_iam_member.public_read",
          "severity": null
        }
      ]
    }
  },
  {
    "check_type": "kubernetes",
    "results": {
      "failed_checks": [
        {
          "check_id": "CKV_K8S_14",
          "check_name": "Image Tag should be fixed - not latest or blank",
          "file_path": "/k8s/deployment.yaml",
          "resource": "Deployment.default.widgets-api",
          "severity": null
        }
      ]
    }
  },
  {
    "check_type": "dockerfile",
    "results": {
      "failed_checks": [
        {
          "check_id": "CKV_DOCKER_2",
          "check_name": "Ensure that HEALTHCHECK instructions have been added to container images",
          "file_path": "/Dockerfile",
          "resource": "/Dockerfile.",
          "severity": null
        }
      ]
    }
  }
]
```

`tests/fixtures/scanner_output/conftest.json`:

```json
[
  {"filename": "app/k8s/deployment.yaml", "namespace": "no_public_bucket", "successes": 1},
  {"filename": "app/k8s/deployment.yaml", "namespace": "deny_latest_tag", "successes": 0,
   "failures": [{"msg": "container \"api\" uses unpinned image \"ghcr.io/example/widgets-api:latest\"",
                 "metadata": {"query": "data.deny_latest_tag.deny"}}]}
]
```

- [ ] **Step 2: Write the failing tests.**

`tests/test_run_scan.py`:

```python
import json
import sys
from pathlib import Path
from typing import Any

import pytest

from run_scan import (
    ScanError,
    dedupe,
    normalize_checkov,
    normalize_conftest,
    normalize_semgrep,
    normalize_trivy,
    run_tool,
)

OUTPUT = Path(__file__).parent / "fixtures" / "scanner_output"


def _load(name: str) -> Any:
    return json.loads((OUTPUT / name).read_text())


def _keys(findings: list[dict]) -> list[tuple[str, str, str, str]]:
    return [(f["tool"], f["rule_id"], f["severity"], f["target"]) for f in findings]


def test_semgrep_strips_config_prefix_and_maps_severity() -> None:
    assert _keys(normalize_semgrep(_load("semgrep.json"), "app")) == [
        ("semgrep", "drf-allowany", "high", "app/widgets/views.py")
    ]


def test_trivy_config_misconfigurations() -> None:
    assert _keys(normalize_trivy(_load("trivy-config.json"), "app")) == [
        ("trivy", "DS-0002", "high", "app/Dockerfile"),
        ("trivy", "DS-0026", "low", "app/Dockerfile"),
        ("trivy", "KSV-0013", "medium", "app/k8s/deployment.yaml"),
    ]


def test_trivy_fs_vulnerabilities() -> None:
    (finding,) = normalize_trivy(_load("trivy-fs.json"), "app")
    assert (finding["rule_id"], finding["severity"], finding["target"]) == (
        "CVE-2023-31047",
        "critical",
        "app/requirements.txt",
    )
    assert finding["message"].startswith("Django 4.2.0: ")


def test_checkov_prefixes_target_and_marks_missing_severity_unknown() -> None:
    assert _keys(normalize_checkov(_load("checkov.json"), "app")) == [
        ("checkov", "CKV_GCP_28", "unknown", "app/infra/main.tf"),
        ("checkov", "CKV_K8S_14", "unknown", "app/k8s/deployment.yaml"),
        ("checkov", "CKV_DOCKER_2", "unknown", "app/Dockerfile"),
    ]


def test_checkov_accepts_single_framework_object() -> None:
    single = _load("checkov.json")[0]
    assert len(normalize_checkov(single, "app")) == 1


def test_conftest_uses_namespace_as_rule_id_and_skips_successes() -> None:
    assert _keys(normalize_conftest(_load("conftest.json"), "app")) == [
        ("conftest", "deny_latest_tag", "high", "app/k8s/deployment.yaml")
    ]


def test_dedupe_collapses_exact_duplicates_only() -> None:
    a = {"tool": "trivy", "rule_id": "X", "target": "t", "severity": "low", "message": "1", "tags": []}
    b = {**a, "message": "2"}
    c = {**a, "tool": "checkov"}
    assert dedupe([a, b, c]) == [a, c]


def test_run_tool_missing_binary(tmp_path: Path) -> None:
    with pytest.raises(ScanError, match="not found"):
        run_tool("nope", ["definitely-not-a-scanner-binary"], tmp_path)


def test_run_tool_accepts_exit_1_with_json(tmp_path: Path) -> None:
    argv = [sys.executable, "-c", "import sys; print('[]'); sys.exit(1)"]
    assert run_tool("fake", argv, tmp_path) == []


def test_run_tool_rejects_crash(tmp_path: Path) -> None:
    argv = [sys.executable, "-c", "import sys; sys.stderr.write('boom'); sys.exit(2)"]
    with pytest.raises(ScanError, match="exit 2: boom"):
        run_tool("fake", argv, tmp_path)
```

- [ ] **Step 3: Run them to confirm they fail.**

Run: `uv run pytest tests/test_run_scan.py -q`
Expected: FAIL, `ModuleNotFoundError: No module named 'run_scan'`.

- [ ] **Step 4: Implement.** Exit codes: Checkov and Conftest exit 1 when they find issues; Semgrep and Trivy exit 0. Both are success.

`.claude/skills/grc-continuous-compliance/scripts/run_scan.py`:

```python
"""Run Semgrep, Trivy, Checkov and Conftest against a target and write normalized findings."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any

Finding = dict[str, Any]
SEVERITIES = ("critical", "high", "medium", "low", "info", "unknown")
_SEMGREP_SEVERITY = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}


class ScanError(RuntimeError):
    """A scanner is missing, crashed, or produced unreadable output."""


def _finding(tool: str, rule_id: str, severity: str, target: str, message: str) -> Finding:
    level = severity.lower() if severity.lower() in SEVERITIES else "unknown"
    return {"tool": tool, "rule_id": rule_id, "severity": level, "target": target, "message": message, "tags": []}


def normalize_semgrep(doc: dict[str, Any], target_dir: str) -> list[Finding]:
    """Semgrep --json; paths are already repo-relative. Rule ids drop the config-path prefix."""
    return [
        _finding(
            "semgrep",
            r["check_id"].rsplit(".", 1)[-1],
            _SEMGREP_SEVERITY.get(r["extra"]["severity"], r["extra"]["severity"]),
            r["path"],
            r["extra"]["message"],
        )
        for r in doc["results"]
    ]


def normalize_trivy(doc: dict[str, Any], target_dir: str) -> list[Finding]:
    """Trivy config/fs --format json; targets are relative to the scanned directory."""
    findings = []
    for result in doc.get("Results", []):
        target = f"{target_dir}/{result['Target']}"
        for m in result.get("Misconfigurations") or []:
            if m["Status"] == "FAIL":
                findings.append(_finding("trivy", m["ID"], m["Severity"], target, f"{m['Title']}: {m['Message']}"))
        for v in result.get("Vulnerabilities") or []:
            message = f"{v['PkgName']} {v['InstalledVersion']}: {v['Title']}"
            findings.append(_finding("trivy", v["VulnerabilityID"], v["Severity"], target, message))
    return findings


def normalize_checkov(doc: dict[str, Any] | list[dict[str, Any]], target_dir: str) -> list[Finding]:
    """Checkov -o json (one object per framework); run with cwd=target so paths are target-relative."""
    reports = doc if isinstance(doc, list) else [doc]
    return [
        _finding(
            "checkov",
            c["check_id"],
            c["severity"] or "unknown",
            f"{target_dir}/{c['file_path'].lstrip('/')}",
            f"{c['check_name']} ({c['resource']})",
        )
        for report in reports
        for c in report["results"]["failed_checks"]
    ]


def normalize_conftest(doc: list[dict[str, Any]], target_dir: str) -> list[Finding]:
    """Conftest -o json; the policy package (namespace) is the rule id. Deny rules block, so severity is high."""
    return [
        _finding("conftest", r["namespace"], "high", r["filename"], f["msg"])
        for r in doc
        for f in r.get("failures") or []
    ]


def dedupe(findings: list[Finding]) -> list[Finding]:
    """Collapse exact (tool, rule_id, target) duplicates, keeping first occurrence order."""
    seen: dict[tuple[str, str, str], Finding] = {}
    for f in findings:
        seen.setdefault((f["tool"], f["rule_id"], f["target"]), f)
    return list(seen.values())


def run_tool(tool: str, argv: list[str], cwd: Path) -> Any:
    """Run a scanner and parse its JSON stdout. Exit 0/1 means clean/issues found; anything else fails."""
    if shutil.which(argv[0]) is None:
        raise ScanError(f"{tool}: '{argv[0]}' not found on PATH; run `make bootstrap`")
    proc = subprocess.run(argv, cwd=cwd, capture_output=True, text=True, check=False)
    if proc.returncode not in (0, 1):
        raise ScanError(f"{tool}: exit {proc.returncode}: {proc.stderr.strip()[-500:]}")
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as e:
        raise ScanError(f"{tool}: unreadable JSON output: {e}") from e


def scan(repo: Path, target_dir: str) -> list[Finding]:
    """Run all four scanners over `repo/target_dir` and return deduplicated findings."""
    target = repo / target_dir
    conftest_inputs = sorted(p.relative_to(repo).as_posix() for p in [*target.glob("k8s/*.yaml"), *target.glob("infra/*.tf")])
    runs: list[tuple[str, list[str], Path, Callable[[Any, str], list[Finding]]]] = [
        ("semgrep", ["semgrep", "scan", "--config", "policies/semgrep", "--metrics=off", "--json", "--quiet", target_dir], repo, normalize_semgrep),
        ("trivy", ["trivy", "config", "--quiet", "--format", "json", target_dir], repo, normalize_trivy),
        ("trivy", ["trivy", "fs", "--quiet", "--scanners", "vuln", "--format", "json", target_dir], repo, normalize_trivy),
        ("checkov", ["checkov", "-d", ".", "--framework", "terraform", "kubernetes", "dockerfile", "-o", "json", "--quiet", "--compact"], target, normalize_checkov),
        ("conftest", ["conftest", "test", "--all-namespaces", "--no-color", "-o", "json", "-p", "policies/rego", *conftest_inputs], repo, normalize_conftest),
    ]
    findings: list[Finding] = []
    for tool, argv, cwd, normalize in runs:
        findings += normalize(run_tool(tool, argv, cwd), target_dir)
    return dedupe(findings)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", default="app", help="scan target, relative to the repo root")
    parser.add_argument("--out", type=Path, default=Path("out"))
    args = parser.parse_args()
    findings = scan(Path.cwd(), args.target)
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "findings.json").write_text(json.dumps(findings, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
```

- [ ] **Step 5: Run the tests to confirm they pass.**

Run: `uv run pytest tests/test_run_scan.py -q`
Expected: `10 passed`.

- [ ] **Step 6: Smoke-test against real scanners.**

Run: `PATH=$PWD/.tools/bin:$PATH TRIVY_CACHE_DIR=.tools/trivy-cache uv run python .claude/skills/grc-continuous-compliance/scripts/run_scan.py && python3 -c 'import json; f=json.load(open("out/findings.json")); print(len(f), sorted({x["tool"] for x in f}))'`
Expected: more than 100 findings from all four tools (the count moves as the Trivy database updates).

- [ ] **Step 7: Commit.**

```bash
git add .claude/skills/grc-continuous-compliance/scripts/run_scan.py tests/fixtures/scanner_output tests/test_run_scan.py
git commit -m "Add scanner runner and normalizers" -m "Closes #8"
```

---

## Task 9: to_oscal: OSCAL output (parallelizable)

**Files:**
- Create: `.claude/skills/grc-continuous-compliance/scripts/to_oscal.py`, `tests/oscal_schema.py`, `tests/fixtures/oscal/oscal_{component,assessment-results}_schema.json`
- Test: `tests/test_to_oscal.py`

**Interfaces:**
- Consumes: `map_findings` output shape (Task 7); `Bundle`.
- Produces: `component_definition(bundle, now: str) -> dict`; `assessment_results(bundle, mapping, now: str) -> dict`; test helper `validate(document, schema_file)`. The CLI (`--now` injectable) writes `out/oscal/{component-definition,assessment-results}.json`.

- [ ] **Step 1: Vendor the NIST schemas.**

```bash
mkdir -p tests/fixtures/oscal
gh release download v1.2.3 -R usnistgov/OSCAL -D tests/fixtures/oscal \
  -p oscal_component_schema.json -p oscal_assessment-results_schema.json
```

Expected: two files; their `$id` values contain `/1.2.3/`.

- [ ] **Step 2: Add the validation helper.** Python's `re` cannot compile the schemas' `\p{L}`/`\p{N}` classes, so the helper rewrites them at load time.

`tests/oscal_schema.py`:

```python
"""Validate documents against the vendored NIST OSCAL JSON schemas."""

import json
from pathlib import Path

from jsonschema import Draft7Validator

SCHEMAS = Path(__file__).parent / "fixtures" / "oscal"

# OSCAL patterns use Unicode property classes that Python's `re` cannot compile.
_PY_EQUIVALENTS = {r"\p{L}": r"[^\W\d_]", r"\p{N}": r"\d"}


def validate(document: dict, schema_file: str) -> None:
    """Raise jsonschema.ValidationError if `document` does not conform."""
    text = (SCHEMAS / schema_file).read_text(encoding="utf-8")
    for unicode_class, python_class in _PY_EQUIVALENTS.items():
        text = text.replace(unicode_class.replace("\\", "\\\\"), python_class.replace("\\", "\\\\"))
    Draft7Validator(json.loads(text)).validate(document)
```

- [ ] **Step 3: Write the failing tests.** They include two negative tests proving the validator really rejects invalid documents.

`tests/test_to_oscal.py`:

```python
import json
from pathlib import Path

import pytest

from map_findings import map_findings
from okf_lib import Bundle, load_bundle
from oscal_schema import validate
from to_oscal import assessment_results, component_definition

FIXTURES = Path(__file__).parent / "fixtures"
NOW = "2026-09-25T12:00:00+00:00"


@pytest.fixture
def bundle() -> Bundle:
    return load_bundle(FIXTURES / "bundle")


@pytest.fixture
def mapping(bundle: Bundle) -> dict:
    return map_findings(bundle, json.loads((FIXTURES / "findings.json").read_text()))


def test_component_definition_is_schema_valid(bundle: Bundle) -> None:
    validate(component_definition(bundle, NOW), "oscal_component_schema.json")


def test_component_lists_only_in_bundle_controls(bundle: Bundle) -> None:
    (comp,) = component_definition(bundle, NOW)["component-definition"]["components"]
    reqs = comp["control-implementations"][0]["implemented-requirements"]
    assert [r["control-id"] for r in reqs] == ["cc6.1", "cc7.1"]


def test_assessment_results_is_schema_valid(bundle: Bundle, mapping: dict) -> None:
    validate(assessment_results(bundle, mapping, NOW), "oscal_assessment-results_schema.json")


def test_findings_target_assessed_controls_only(bundle: Bundle, mapping: dict) -> None:
    (result,) = assessment_results(bundle, mapping, NOW)["assessment-results"]["results"]
    states = {f["target"]["target-id"]: f["target"]["status"]["state"] for f in result["findings"]}
    assert states == {"cc6.1": "not-satisfied", "cc7.1": "not-satisfied", "cc8.1": "satisfied"}
    assert "cc7.2" in result["remarks"]


def test_coverage_gaps_are_risks_not_findings(bundle: Bundle, mapping: dict) -> None:
    (result,) = assessment_results(bundle, mapping, NOW)["assessment-results"]["results"]
    assert sorted(r["title"] for r in result["risks"]) == [
        "Coverage gap: checkov CKV_TEST_99",
        "Coverage gap: conftest orphan_rule",
    ]
    gap_obs = {o["observation-uuid"] for r in result["risks"] for o in r["related-observations"]}
    finding_obs = {o["observation-uuid"] for f in result["findings"] for o in f.get("related-observations", [])}
    assert gap_obs and not gap_obs & finding_obs


def test_output_is_deterministic(bundle: Bundle, mapping: dict) -> None:
    assert assessment_results(bundle, mapping, NOW) == assessment_results(bundle, mapping, NOW)
    assert component_definition(bundle, NOW) == component_definition(bundle, NOW)


def test_validator_rejects_missing_required_field(bundle: Bundle, mapping: dict) -> None:
    from jsonschema import ValidationError

    doc = assessment_results(bundle, mapping, NOW)
    del doc["assessment-results"]["import-ap"]
    with pytest.raises(ValidationError, match="import-ap"):
        validate(doc, "oscal_assessment-results_schema.json")


def test_validator_rejects_bad_token(bundle: Bundle) -> None:
    from jsonschema import ValidationError

    doc = component_definition(bundle, NOW)
    reqs = doc["component-definition"]["components"][0]["control-implementations"][0]["implemented-requirements"]
    reqs[0]["control-id"] = "9 not a token"
    with pytest.raises(ValidationError):
        validate(doc, "oscal_component_schema.json")
```

- [ ] **Step 4: Run them to confirm they fail.**

Run: `uv run pytest tests/test_to_oscal.py -q`
Expected: FAIL, `ModuleNotFoundError: No module named 'to_oscal'`.

- [ ] **Step 5: Implement.** Coverage gaps become open `risks`, never `findings`.

`.claude/skills/grc-continuous-compliance/scripts/to_oscal.py`:

```python
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
    return f"{f['tool']}:{f['rule_id']}:{f['target']}"


def component_definition(bundle: Bundle, now: str) -> Json:
    """Stack components × the in-bundle controls each one links to."""
    tsc_uuid = _uuid("resource", TSC_RESOURCE)
    components = []
    for comp in bundle.of_type(COMPONENT_TYPE):
        controls = [c for cid in comp.links if (c := bundle.concepts.get(cid)) and c in bundle.controls()]
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


def assessment_results(bundle: Bundle, mapping: Json, now: str) -> Json:
    """Findings per assessed control; unmapped findings become open risks, never control findings."""
    all_findings = [f for c in mapping["controls"].values() for f in c["findings"]]
    all_findings += [u["finding"] for u in mapping["unmapped"]]
    observations = {_finding_key(f): _observation(f, now) for f in all_findings}
    assessed = {code: c for code, c in mapping["controls"].items() if c["status"] != "not-assessed"}
    not_assessed = sorted(set(mapping["controls"]) - set(assessed))
    findings = []
    for code, entry in sorted(assessed.items()):
        control = bundle.control(code)
        finding: Json = {
            "uuid": _uuid("finding", code),
            "title": control.title if control else code,
            "description": f"{len(entry['findings'])} open finding(s).",
            "target": {"type": "objective-id", "target-id": code, "status": {"state": entry["status"]}},
        }
        if entry["findings"]:
            finding["related-observations"] = [
                {"observation-uuid": observations[_finding_key(f)]["uuid"]} for f in entry["findings"]
            ]
        findings.append(finding)
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
            "control-selections": [{"include-controls": [{"control-id": code} for code in sorted(assessed)]}]
        },
    }
    if observations:
        result["observations"] = list(observations.values())
    if risks:
        result["risks"] = risks
    if findings:
        result["findings"] = findings
    if not_assessed:
        result["remarks"] = "Not assessed (no in-bundle scanner or policy): " + ", ".join(not_assessed)
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
```

- [ ] **Step 6: Run the tests to confirm they pass.**

Run: `uv run pytest tests/test_to_oscal.py -q`
Expected: `8 passed`.

- [ ] **Step 7: Commit.**

```bash
git add .claude/skills/grc-continuous-compliance/scripts/to_oscal.py tests/oscal_schema.py tests/fixtures/oscal tests/test_to_oscal.py
git commit -m "Add OSCAL 1.2.3 output" -m "Closes #9"
```

---

## Task 10: render_report: auditor report (parallelizable)

**Files:**
- Create: `.claude/skills/grc-continuous-compliance/scripts/render_report.py`, `tests/fixtures/report.golden.md`
- Test: `tests/test_render_report.py`

**Interfaces:**
- Consumes: mapping shape (Task 7); `Bundle.section(concept, "Remediation")`, `Bundle.by_rule`.
- Produces: `render_report(bundle, mapping, now: str) -> str`. The CLI writes `out/report.md`.

- [ ] **Step 1: Write the golden report.** It is the expected output for the fixture bundle and findings. The `**Remediation:**` paragraph comes only from `# Remediation` sections of concepts that declare the finding's rule for that control.

`tests/fixtures/report.golden.md`:

```markdown
# Compliance Scan Report

Generated 2026-09-25T12:00:00+00:00. Every status below is derived from scanner findings joined to
controls declared in the OKF knowledge bundle; nothing is mapped without a declaration.

## Summary

| Control | Status | Open findings |
|---|---|---|
| cc6.1 | not-satisfied | 2 |
| cc7.1 | not-satisfied | 1 |
| cc7.2 | not-assessed | 0 |
| cc8.1 | satisfied | 0 |

## Controls

### CC6.1 — Logical Access

**Status:** not-satisfied

**Evidence:** [Require non-root](../knowledge/policies/require-non-root.md)

**Open findings:**

- `conftest` `require_non_root` (high) — container runs as root — `app/k8s/deployment.yaml`
- `checkov` `CKV_TEST_1` (medium) — runAsNonRoot not set — `app/k8s/deployment.yaml`

**Remediation:** Run the container as a non-root user.

### CC7.1 — Vulnerability Detection

**Status:** not-satisfied

**Evidence:** [Trivy](../knowledge/scanners/trivy.md)

**Open findings:**

- `trivy` `CVE-2024-0001` (critical) — example-pkg 1.0 vulnerable — `app/requirements.txt`

**Remediation:** Upgrade the affected dependency to a fixed version.

### CC8.1 — Change Management

**Status:** satisfied

**Evidence:** [Deny latest tag](../knowledge/policies/deny-latest-tag.md)

## Coverage gaps

Findings with no in-bundle control. These are gaps to close, not mappings to invent.

- `checkov` `CKV_TEST_99` (low) — no HEALTHCHECK — `app/Dockerfile` — reason: `no-rule-match`
- `conftest` `orphan_rule` (medium) — orphan — `app/infra/main.tf` — reason: `control-not-in-bundle`

## Not assessed

- CC7.2 — Monitoring: no in-bundle scanner or policy evidences this control.
```

- [ ] **Step 2: Write the failing test.**

`tests/test_render_report.py`:

```python
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
```

- [ ] **Step 3: Run it to confirm it fails.**

Run: `uv run pytest tests/test_render_report.py -q`
Expected: FAIL, `ModuleNotFoundError: No module named 'render_report'`.

- [ ] **Step 4: Implement.**

`.claude/skills/grc-continuous-compliance/scripts/render_report.py`:

```python
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
        lines += [f"**Remediation:** {_remediation(bundle, code, entry['findings'])}", ""]
    return lines


def render_report(bundle: Bundle, mapping: Json, now: str) -> str:
    """Markdown report: summary, per-control detail, coverage gaps, not-assessed controls."""
    controls = sorted(mapping["controls"].items())
    lines = [
        "# Compliance Scan Report",
        "",
        f"Generated {now}. Every status below is derived from scanner findings joined to",
        "controls declared in the OKF knowledge bundle; nothing is mapped without a declaration.",
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
```

- [ ] **Step 5: Run the test to confirm it passes.**

Run: `uv run pytest tests/test_render_report.py -q`
Expected: `1 passed`.

- [ ] **Step 6: Commit.**

```bash
git add .claude/skills/grc-continuous-compliance/scripts/render_report.py tests/fixtures/report.golden.md tests/test_render_report.py
git commit -m "Add auditor report renderer" -m "Closes #10"
```

---

## Task 11: SKILL.md and OSCAL subset doc

**Files:**
- Create: `.claude/skills/grc-continuous-compliance/SKILL.md`, `docs/oscal-subset.md`
- Test: `tests/test_skill_md.py`

- [ ] **Step 1: Write the failing test.**

`tests/test_skill_md.py`:

```python
from pathlib import Path

import yaml

SKILL = Path(__file__).parent.parent / ".claude" / "skills" / "grc-continuous-compliance" / "SKILL.md"


def test_frontmatter_names_the_skill() -> None:
    fm = yaml.safe_load(SKILL.read_text().split("---\n")[1])
    assert fm["name"] == SKILL.parent.name
    assert len(fm["description"]) > 100


def test_states_the_grounding_rule() -> None:
    text = SKILL.read_text()
    assert "coverage gap" in text and "Never invent" in text
```

- [ ] **Step 2: Run it to confirm it fails.**

Run: `uv run pytest tests/test_skill_md.py -q`
Expected: FAIL, `FileNotFoundError: ... SKILL.md`.

- [ ] **Step 3: Write the skill and the subset doc.**

`.claude/skills/grc-continuous-compliance/SKILL.md`:

```markdown
---
name: grc-continuous-compliance
description: >
  Runs a layered DevSecOps scan (Semgrep, Trivy, Checkov, Conftest) against a
  target app, maps each finding to a SOC 2 / NIST 800-53 control using the local
  OKF knowledge bundle, emits OSCAL, and writes an auditor-facing report. Use
  when the user asks to review security or compliance posture, produce an audit
  evidence pass, or check a deploy against policy, in a repo that ships a
  knowledge/ OKF bundle.
---

# GRC Continuous-Compliance Skill

## Grounding rule (non-negotiable)

1. Read `knowledge/index.md`, then the concepts under `controls/`, `policies/`,
   and `scanners/`, before doing anything else.
2. A finding maps to a control only through a `rule_ids` declaration in the
   bundle. The scripts enforce this; do not override them.
3. A finding with no mapped control is a **coverage gap**. Report it as one.
   Never invent a control, a mapping, or a status.

## Workflow

1. **Check tools.** If `.tools/bin/` is missing, run `make bootstrap`.
2. **Scan and map.** Run `make scan`. It writes:
   - `out/findings.json`: normalized findings `{tool, rule_id, severity, target, message, tags}`
   - `out/mapping.json`: per-control status plus unmapped findings with a reason
   - `out/oscal/component-definition.json`, `out/oscal/assessment-results.json`
   - `out/report.md`: the deterministic report
3. **Review.** Read `out/report.md` and `out/mapping.json`. Summarize for the
   user: controls not satisfied, the highest-severity findings, coverage gaps,
   and controls not assessed.
4. **Enrich (optional, on request).** You may rewrite prose in `out/report.md`
   to be clearer for an auditor. You must not change any status, add or remove
   a finding, or move a finding between a control and the coverage-gap list.
5. **Propose, don't patch the bundle.** If a coverage gap looks like it belongs
   to an existing control, propose a `rule_ids` addition to the relevant
   guardrail concept for human review. Do not edit `knowledge/` unasked.

## Scope

Operates only on this repository's `app/` and `knowledge/`. Reads no external
systems, credentials, or production infrastructure. `app/` is intentionally
vulnerable; never deploy it.
```

`docs/oscal-subset.md`:

```markdown
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
| `results[0].findings[]` | one per assessed control; `target.status.state` is `satisfied` or `not-satisfied` |
| `results[0].risks[]` | one per unmapped finding, titled "Coverage gap: …", `status: open` |
| `results[0].remarks` | lists controls not assessed |

## Deliberately not modeled

- Assessment plan, SSP, POA&M, and profiles.
- A machine-readable SOC 2 catalog: the Trust Services Criteria are not
  published as an OSCAL catalog, so `control-id` values are the criterion codes.
- Parties, roles, and responsible-parties.
- Coverage gaps as `findings`: an OSCAL finding must target a control, and
  targeting one would invent the mapping the grounding rule forbids.
```

- [ ] **Step 4: Run the test to confirm it passes.**

Run: `uv run pytest tests/test_skill_md.py -q`
Expected: `2 passed`.

- [ ] **Step 5: Commit.**

```bash
git add .claude/skills/grc-continuous-compliance/SKILL.md docs/oscal-subset.md tests/test_skill_md.py
git commit -m "Add skill definition and OSCAL subset doc" -m "Closes #11"
```

---

## Task 12: End-to-end integration

**Files:**
- Test: `tests/test_integration.py`

**Interfaces:**
- Consumes: `make scan` (Task 1 Makefile), `app/SEEDED.yaml` (Task 2), `validate` (Task 9).

- [ ] **Step 1: Write the integration test.** It is marked `integration` and excluded from `make test` by `addopts`.

`tests/test_integration.py`:

```python
"""End-to-end: `make scan` finds every seeded issue and maps it exactly as SEEDED.yaml expects."""

import json
import subprocess
from pathlib import Path

import pytest
import yaml

from oscal_schema import validate

ROOT = Path(__file__).parent.parent
OUT = ROOT / "out"
pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def mapping() -> dict:
    subprocess.run(["make", "scan"], cwd=ROOT, check=True)
    return json.loads((OUT / "mapping.json").read_text())


def _located(mapping: dict, tool: str, rule_id: str, file: str) -> set[str]:
    """Where a finding landed: control codes, or 'gap:<reason>'."""
    hits = {
        code
        for code, entry in mapping["controls"].items()
        for f in entry["findings"]
        if (f["tool"], f["rule_id"], f["target"]) == (tool, rule_id, file)
    }
    hits |= {
        f"gap:{u['reason']}"
        for u in mapping["unmapped"]
        if (u["finding"]["tool"], u["finding"]["rule_id"], u["finding"]["target"]) == (tool, rule_id, file)
    }
    return hits


SEEDED = yaml.safe_load((ROOT / "app" / "SEEDED.yaml").read_text())


@pytest.mark.parametrize("seed", SEEDED, ids=lambda s: s["id"])
def test_seeded_issue_lands_where_expected(mapping: dict, seed: dict) -> None:
    expected = seed["expect"].get("control") or f"gap:{seed['expect']['gap']}"
    for detector in seed["detected_by"]:
        tool, rule_id = detector.split(":", 1)
        assert _located(mapping, tool, rule_id, seed["file"]) == {expected}, f"{seed['id']} {detector}"


def test_outputs_exist_and_oscal_validates(mapping: dict) -> None:
    assert (OUT / "report.md").read_text().startswith("# Compliance Scan Report")
    validate(json.loads((OUT / "oscal" / "component-definition.json").read_text()), "oscal_component_schema.json")
    validate(json.loads((OUT / "oscal" / "assessment-results.json").read_text()), "oscal_assessment-results_schema.json")


def test_monitoring_control_is_not_assessed(mapping: dict) -> None:
    assert mapping["controls"]["cc7.2"]["status"] == "not-assessed"
```

- [ ] **Step 2: Run it.**

Run: `make clean && make test-integration`
Expected: `9 passed`. If a seed fails, debug with superpowers:systematic-debugging. Never fix it by editing `SEEDED.yaml` expectations to match output you have not traced.

- [ ] **Step 3: Confirm the test can fail.** Temporarily delete the `trivy:KSV-0105` line from `knowledge/policies/require-non-root.md` and re-run.
Expected: `AssertionError: S4 trivy:KSV-0105`. Revert with `git checkout knowledge/policies/require-non-root.md`.

- [ ] **Step 4: Inspect the outputs.**

Run: `python3 -c 'import json; m=json.load(open("out/mapping.json")); print({k: (v["status"], len(v["findings"])) for k, v in m["controls"].items()}, len(m["unmapped"]))'`
Expected (prototype run): `cc6.1` not-satisfied 7, `cc6.6` not-satisfied 4, `cc7.1` not-satisfied ≈51 (CVE count), `cc7.2` not-assessed 0, `cc8.1` not-satisfied 3, and about 41 unmapped. Open `out/report.md` and check that it reads correctly.

- [ ] **Step 5: Run the full suite.**

Run: `make test`
Expected: all unit tests pass, and Conftest reports `13 tests, 13 passed`.

- [ ] **Step 6: Commit.**

```bash
git add tests/test_integration.py
git commit -m "Add end-to-end seeded-issue integration test" -m "Closes #12"
```

---

## Task 13: Visualize, screenshots, README

**Files:**
- Create: `docs/screenshots/knowledge-graph.png`, `docs/screenshots/report.png`
- Modify: `README.md` (add a Screenshots section)

This task is docs only, with no new tests. It verifies manually, as below.

- [ ] **Step 1: Render the graph.**

Run: `make render`
Expected: `Wrote 19 concept(s), 52 edge(s) ... → out/knowledge-viz.html` (the visualizer counts `log.md` too). Zero edges means a link was written in `/`-absolute form.

- [ ] **Step 2: Capture screenshots.** Open `out/knowledge-viz.html` in a browser and capture the full graph with a control selected, saving it as `docs/screenshots/knowledge-graph.png`. Then view `out/report.md` rendered (e.g. in a markdown preview) and capture the Summary and Coverage gaps sections as `docs/screenshots/report.png`.

- [ ] **Step 3: Add to the README**, after "How grounding works":

```markdown
## Screenshots

![OKF knowledge graph](docs/screenshots/knowledge-graph.png)

![Compliance scan report](docs/screenshots/report.png)
```

- [ ] **Step 4: Check the definition of done** against spec §1:
  - `make clean && make scan` produces all five outputs;
  - `make test-integration` is green;
  - `make render` works;
  - screenshots are committed;
  - a final read of `README.md` and `docs/` confirms everything cited is a public framework, spec, or tool.

- [ ] **Step 5: Commit** (docs only, no tests).

```bash
git add README.md docs/screenshots
git commit -m "Add knowledge graph and report screenshots" -m "Closes #13"
```
