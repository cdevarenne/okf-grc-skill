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
