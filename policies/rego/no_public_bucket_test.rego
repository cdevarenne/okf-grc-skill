package no_public_bucket

import rego.v1

binding(member) := {"resource": {"google_storage_bucket_iam_member": {"b": [{"member": member}]}}}

test_all_users_denied if count(deny) == 1 with input as binding("allUsers")

test_all_authenticated_users_denied if count(deny) == 1 with input as binding("allAuthenticatedUsers")

test_service_account_allowed if count(deny) == 0 with input as binding("serviceAccount:api@example.iam.gserviceaccount.com")

test_no_buckets_allowed if count(deny) == 0 with input as {"resource": {}}
