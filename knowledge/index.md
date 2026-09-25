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
