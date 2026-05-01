# CloudSec policy with very complex nested filter criteria
# This example demonstrates the full power of the filter_criteria structure
# with multiple levels of nested AND/OR logic

resource "cortexcloud_cloudsec_policy" "advanced_security_policy" {
  name        = "Advanced Multi-Cloud Security Policy"
  description = "Complex policy demonstrating nested filter criteria for multi-cloud environments"

  rule_matching = {
    type = "RULE_FILTER"

    # Complex nested filter structure:
    # (
    #   (cloudType = aws AND (severity = high OR severity = critical)) OR
    #   (cloudType = azure AND severity = critical) OR
    #   (cloudType = gcp AND labels contains 'data-protection')
    # ) AND
    # (
    #   enabled = true AND systemDefault = false
    # )
    filter_criteria = {
      # Top-level AND: cloud-specific rules AND enabled custom rules
      and = {
        # First condition: Match cloud-specific severity rules
        or = {
          # AWS high or critical severity rules
          and = {
            search_field = "cloudType"
            search_type  = "EQ"
            search_value = "aws"
          }
          and ={
            or = {
              search_field = "severity"
              search_type  = "EQ"
              search_value = "high"
            }
            or = {
              search_field = "severity"
              search_type  = "EQ"
              search_value = "critical"
            }
          }
        }
        or = {
          # Azure critical severity rules only
          and = {
            search_field = "cloudType"
            search_type  = "EQ"
            search_value = "azure"
          }
          and = {
            search_field = "severity"
            search_type  = "EQ"
            search_value = "critical"
          }
        }
        or = {
          # GCP rules with data-protection label
          and = {
            search_field = "cloudType"
            search_type  = "EQ"
            search_value = "gcp"
          }
          and = {
            search_field = "labels"
            search_type  = "ARRAY_CONTAINS"
            search_value = "data-protection"
          }
        }
      }
      and = {
        # Second condition: Must be enabled
        search_field = "enabled"
        search_type  = "EQ"
        search_value = true
      }
      and = {
        # Third condition: Exclude system default rules
        search_field = "systemDefault"
        search_type  = "EQ"
        search_value = false
      }
    }
  }

  # Apply to all assets
  asset_matching = {
    type = "ALL_ASSETS"
  }

  labels = ["Multi-Cloud", "Advanced", "Custom Rules"]
  enabled = true
}

# Example: Policy with exclusion logic using NEQ operator
resource "cortexcloud_cloudsec_policy" "non_informational_rules" {
  name        = "Production Security Rules (Non-Informational)"
  description = "All production rules excluding informational severity"

  rule_matching = {
    type = "RULE_FILTER"

    # Filter: enabled = true AND severity != informational AND labels contains 'production'
    filter_criteria = {
      and = {
        search_field = "enabled"
        search_type  = "EQ"
        search_value = true
      }
      and = {
        # Exclude informational severity
        search_field = "severity"
        search_type  = "NEQ"
        search_value = "informational"
      }
      and = {
        # Must have production label
        search_field = "labels"
        search_type  = "ARRAY_CONTAINS"
        search_value = "production"
      }
    }
  }

  asset_matching = {
    type = "ALL_ASSETS"
  }

  labels  = ["Production", "Active Monitoring"]
  enabled = true
}
# Example: Policy targeting specific asset types with rule filters

resource "cortexcloud_cloudsec_policy" "database_security" {
  name        = "Database Security Policy"
  description = "Security rules for database resources across all clouds"

  rule_matching = {
    type = "RULE_FILTER"

    # Filter: assetTypes contains database-related resources
    filter_criteria = {
      and = {
        or = {
          search_field = "assetTypes"
          search_type  = "ARRAY_CONTAINS"
          search_value = "aws-rds-db-instance"
        }
        or = {
          search_field = "assetTypes"
          search_type  = "ARRAY_CONTAINS"
          search_value = "azure-sql-database"
        }
        or = {
          search_field = "assetTypes"
          search_type  = "ARRAY_CONTAINS"
          search_value = "gcp-sql-instance"
        }
      }
      and = {
        # Only medium severity and above
        or = {
          search_field = "severity"
          search_type  = "EQ"
          search_value = "medium"
        }
        or = {
          search_field = "severity"
          search_type  = "EQ"
          search_value = "high"
        }
        or = {
          search_field = "severity"
          search_type  = "EQ"
          search_value = "critical"
        }
      }
    }
  }

  asset_matching = {
    type = "ALL_ASSETS"
  }

  labels  = ["Database", "Data Security", "Multi-Cloud"]
  enabled = true
}