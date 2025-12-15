# Scope configuration for a user group with multiple scope types
resource "cortexcloud_scope" "group_example" {
  entity_type = "group"
  entity_id   = "security-team"

  # Asset scope - limit access to specific asset groups
  assets {
    asset_groups = ["production-assets", "staging-assets"]
  }

  # Cases and issues scope
  cases_issues {
    case_types = ["security_incident", "compliance_violation"]
  }

  # Endpoints scope - limit access to specific endpoints
  endpoints {
    endpoint_groups = ["corporate-laptops", "servers"]
  }

  # Dataset rows scope with multiple datasets
  datasets_rows {
    dataset_name = "audit_logs"
    filter_json = jsonencode({
      field    = "department"
      operator = "equals"
      value    = "security"
    })
  }

  datasets_rows {
    dataset_name = "threat_intelligence"
    filter_json = jsonencode({
      field    = "severity"
      operator = "in"
      value    = ["critical", "high"]
    })
  }
}