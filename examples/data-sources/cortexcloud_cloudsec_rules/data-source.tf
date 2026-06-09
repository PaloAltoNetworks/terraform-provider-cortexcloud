# Example 1: List all CloudSec detection rules
data "cortexcloud_cloudsec_rules" "all_rules" {
  # No filter - returns all rules
}

output "total_rules" {
  value = data.cortexcloud_cloudsec_rules.all_rules.total_count
}

output "rule_names" {
  value = [for rule in data.cortexcloud_cloudsec_rules.all_rules.rules : rule.name]
}

# Example 2: Filter by severity
data "cortexcloud_cloudsec_rules" "critical_rules" {
  filter {
    field = "severity"
    type  = "EQ"
    value = "critical"
  }
}

output "critical_rule_count" {
  value = data.cortexcloud_cloudsec_rules.critical_rules.filter_count
}

# Example 3: Filter by enabled status
data "cortexcloud_cloudsec_rules" "enabled_rules" {
  filter {
    field = "enabled"
    type  = "EQ"
    value = "true"
  }
}

# Example 4: Pagination
data "cortexcloud_cloudsec_rules" "paginated" {
  search_from = 0
  search_to   = 10
}

# Example 5: Use rules data to create a policy
data "cortexcloud_cloudsec_rules" "high_severity" {
  filter {
    field = "severity"
    type  = "EQ"
    value = "high"
  }
}

resource "cortexcloud_cloudsec_policy" "high_severity_policy" {
  name        = "High Severity Rules Policy"
  description = "Policy applying all high severity rules"

  rule_matching = {
    type  = "RULES"
    rules = [for rule in data.cortexcloud_cloudsec_rules.high_severity.rules : rule.id]
  }

  asset_matching = {
    type = "ALL_ASSETS"
  }

  enabled = true
}
