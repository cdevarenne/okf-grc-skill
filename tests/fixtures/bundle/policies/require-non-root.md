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
