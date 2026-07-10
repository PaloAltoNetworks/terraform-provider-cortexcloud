# Look up an existing CloudSec policy by ID
data "cortexcloud_cloudsec_policy" "example" {
  id = "12345678-1234-1234-1234-123456789012"
}

# Use the policy data in outputs
output "policy_name" {
  description = "Name of the CloudSec policy"
  value       = data.cortexcloud_cloudsec_policy.example.name
}

output "policy_description" {
  description = "Description of the policy"
  value       = data.cortexcloud_cloudsec_policy.example.description
}

output "policy_enabled" {
  description = "Whether the policy is currently enabled"
  value       = data.cortexcloud_cloudsec_policy.example.enabled
}

output "policy_rule_matching_type" {
  description = "Type of rule matching used by the policy"
  value       = data.cortexcloud_cloudsec_policy.example.rule_matching.type
}

output "policy_asset_matching_type" {
  description = "Type of asset matching used by the policy"
  value       = data.cortexcloud_cloudsec_policy.example.asset_matching.type
}

output "policy_labels" {
  description = "Custom labels assigned to the policy"
  value       = data.cortexcloud_cloudsec_policy.example.labels
}

# Example: Reference policy's rule IDs in another resource
output "policy_rule_ids" {
  description = "Rule IDs used by the policy (if type is RULES)"
  value       = data.cortexcloud_cloudsec_policy.example.rule_matching.rules
}

# Example: Check if policy applies to specific asset groups
output "policy_asset_group_ids" {
  description = "Asset group IDs targeted by the policy (if type is ASSET_GROUPS)"
  value       = data.cortexcloud_cloudsec_policy.example.asset_matching.asset_group_ids
}

# Example: Use policy data to create a similar policy
resource "cortexcloud_cloudsec_policy" "similar_policy" {
  name        = "Copy of ${data.cortexcloud_cloudsec_policy.example.name}"
  description = "Similar to: ${data.cortexcloud_cloudsec_policy.example.description}"

  # Reuse the same rule matching configuration
  rule_matching = {
    type  = data.cortexcloud_cloudsec_policy.example.rule_matching.type
    rules = data.cortexcloud_cloudsec_policy.example.rule_matching.rules
  }

  # Apply to all assets instead
  asset_matching = {
    type = "ALL_ASSETS"
  }

  # labels is a set of strings and may be null when the source policy has no
  # labels. coalesce() substitutes an empty set for null, then it is converted
  # to a list for concat (concat only accepts lists/tuples) and re-deduplicated
  # via toset.
  labels  = toset(concat(tolist(coalesce(data.cortexcloud_cloudsec_policy.example.labels, toset([]))), ["copy"]))
  enabled = true
}
