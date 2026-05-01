# CloudSec policy using rule filters to dynamically match rules
# This example shows how to use filter criteria with AND/OR logic

resource "cortexcloud_cloudsec_policy" "high_severity_aws_rules" {
  name        = "High Severity AWS Rules Policy"
  description = "Applies all high and critical severity AWS rules to production cloud accounts"

  # Use rule filter to dynamically match rules based on criteria
  rule_matching = {
    type = "RULE_FILTER"

    # Filter criteria: (severity = high OR severity = critical) AND cloudType = aws
    filter_criteria = {
      and = {
        # First AND condition: severity must be high or critical
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
      and = {
        # Second AND condition: must be AWS rules
        search_field = "cloudType"
        search_type  = "EQ"
        search_value = "aws"
      }
    }
  }

  # Apply to specific cloud accounts
  asset_matching = {
    type               = "CLOUD_ACCOUNTS"
    cloud_account_ids = [
      "123456789012", # Production AWS Account 1
      "987654321098", # Production AWS Account 2
    ]
  }

  # Custom labels
  labels = ["AWS", "High Priority", "Production"]

  # Enable the policy
  enabled = true
}

# Example: Policy with nested filter criteria for compliance rules
resource "cortexcloud_cloudsec_policy" "compliance_rules" {
  name        = "Compliance Rules Policy"
  description = "Applies compliance-related rules (PCI-DSS or HIPAA) with medium or higher severity"

  rule_matching = {
    type = "RULE_FILTER"

    # Complex filter: ((compliance contains PCI-DSS OR compliance contains HIPAA) AND 
    #                  (severity = medium OR severity = high OR severity = critical))
    filter_criteria = {
      and = {
        # Compliance standards filter
        or = {
          search_field = "complianceStandard"
          search_type  = "CONTAINS"
          search_value = "PCI-DSS"
        }
        or = {
          search_field = "complianceStandard"
          search_type  = "CONTAINS"
          search_value = "HIPAA"
        }
      }
      and = {
        # Severity filter
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

  # Apply to all assets
  asset_matching = {
    type = "ALL_ASSETS"
  }

  labels  = ["Compliance", "PCI-DSS", "HIPAA"]
  enabled = true
}