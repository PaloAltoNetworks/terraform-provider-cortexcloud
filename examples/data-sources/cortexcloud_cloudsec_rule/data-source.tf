# Look up an existing CloudSec rule by ID
data "cortexcloud_cloudsec_rule" "example" {
  id = "12345678-1234-1234-1234-123456789012"
}

# Use the rule data in outputs
output "rule_name" {
  description = "Name of the CloudSec rule"
  value       = data.cortexcloud_cloudsec_rule.example.name
}

output "rule_severity" {
  description = "Severity level of the rule"
  value       = data.cortexcloud_cloudsec_rule.example.severity
}

output "rule_description" {
  description = "Description of what the rule detects"
  value       = data.cortexcloud_cloudsec_rule.example.description
}

output "rule_query" {
  description = "XQL query used by the rule"
  value       = data.cortexcloud_cloudsec_rule.example.query.xql
}

output "rule_asset_types" {
  description = "Asset types this rule applies to"
  value       = data.cortexcloud_cloudsec_rule.example.asset_types
}

output "rule_enabled" {
  description = "Whether the rule is currently enabled"
  value       = data.cortexcloud_cloudsec_rule.example.enabled
}

output "rule_providers" {
  description = "Cloud providers this rule applies to"
  value       = data.cortexcloud_cloudsec_rule.example.providers
}

# Example: Use rule data to create a policy
resource "cortexcloud_cloudsec_policy" "example_policy" {
  name        = "Policy for ${data.cortexcloud_cloudsec_rule.example.name}"
  description = "Policy applying rule: ${data.cortexcloud_cloudsec_rule.example.description}"

  rule_matching {
    type     = "RULES"
    rule_ids = [data.cortexcloud_cloudsec_rule.example.id]
  }

  asset_matching {
    type = "ALL_ASSETS"
  }

  enabled = true
}