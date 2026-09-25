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
