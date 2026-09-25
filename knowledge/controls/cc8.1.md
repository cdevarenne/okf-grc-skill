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
