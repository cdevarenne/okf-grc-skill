# Compliance Scan Report

Generated 2026-09-25T12:00:00+00:00. Every status below is derived from scanner findings joined to
controls declared in the OKF knowledge bundle; nothing is mapped without a declaration.
`no-violations-detected` means automated checks found nothing for that control;
it is evidence, not a control attestation.

## Summary

| Control | Status | Open findings |
|---|---|---|
| cc6.1 | not-satisfied | 2 |
| cc7.1 | not-satisfied | 1 |
| cc7.2 | not-assessed | 0 |
| cc8.1 | no-violations-detected | 0 |

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

**Status:** no-violations-detected

**Evidence:** [Deny latest tag](../knowledge/policies/deny-latest-tag.md)

## Coverage gaps

Findings with no in-bundle control. These are gaps to close, not mappings to invent.

- `checkov` `CKV_TEST_99` (low) — no HEALTHCHECK — `app/Dockerfile` — reason: `no-rule-match`
- `conftest` `orphan_rule` (medium) — orphan — `app/infra/main.tf` — reason: `control-not-in-bundle`

## Not assessed

- CC7.2 — Monitoring: no in-bundle scanner or policy evidences this control.
