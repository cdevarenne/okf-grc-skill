# Policies

Each guardrail declares, in `rule_ids`, every scanner rule that detects a
violation of it. A concept that declares `rule_ids` carries exactly one
control tag.

* [Require non-root containers](require-non-root.md) - Containers and images must not run as root.
* [Deny :latest image tag](deny-latest-tag.md) - Deployments must pin an immutable image tag or digest.
* [No public buckets](no-public-bucket.md) - Storage buckets must not grant access to allUsers or allAuthenticatedUsers.
* [DRF writes require authentication](drf-authenticated-writes.md) - API views must not use AllowAny.
