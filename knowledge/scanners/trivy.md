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
