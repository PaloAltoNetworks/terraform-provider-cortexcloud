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
  value       = data.cortexcloud_cloudsec_policy.example.rule_matching.rule_ids
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
  rule_matching {
    type     = data.cortexcloud_cloudsec_policy.example.rule_matching.type
    rule_ids = data.cortexcloud_cloudsec_policy.example.rule_matching.rule_ids
  }

  # Apply to all assets instead
  asset_matching {
    type = "ALL_ASSETS"
  }

  labels  = concat(data.cortexcloud_cloudsec_policy.example.labels, ["copy"])
  enabled = true
}