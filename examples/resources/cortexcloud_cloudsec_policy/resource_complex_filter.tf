# CloudSec policy examples using filter criteria.
# filter_criteria is expressed as an "operator" (AND/OR) plus a "criteria" list,
# where each criterion has "field", "type" and "value".

# Example: match enabled, non-informational rules across clouds.
resource "cortexcloud_cloudsec_policy" "advanced_security_policy" {
  name        = "Advanced Multi-Cloud Security Policy"
  description = "Enabled rules of high or critical severity"

  rule_matching = {
    type = "RULE_FILTER"

    # severity = high OR severity = critical
    filter_criteria = {
      operator = "OR"
      criteria = [
        {
          field = "severity"
          type  = "EQ"
          value = "high"
        },
        {
          field = "severity"
          type  = "EQ"
          value = "critical"
        },
      ]
    }
  }

  # Apply to all assets
  asset_matching = {
    type = "ALL_ASSETS"
  }

  labels  = ["multi-cloud", "advanced"]
  enabled = true
}

# Example: combine severity and cloud filters.
# Note: the "severity" field only supports the "EQ" search type, so
# non-informational severities are enumerated explicitly with an OR group.
resource "cortexcloud_cloudsec_policy" "non_informational_rules" {
  name        = "Production Security Rules (Non-Informational)"
  description = "AWS rules of low, medium, high or critical severity"

  rule_matching = {
    type = "RULE_FILTER"

    # (severity = low OR medium OR high OR critical) AND cloudType = aws
    filter_criteria = {
      operator = "AND"
      criteria = [
        {
          operator = "OR"
          criteria = [
            {
              field = "severity"
              type  = "EQ"
              value = "low"
            },
            {
              field = "severity"
              type  = "EQ"
              value = "medium"
            },
            {
              field = "severity"
              type  = "EQ"
              value = "high"
            },
            {
              field = "severity"
              type  = "EQ"
              value = "critical"
            },
          ]
        },
        {
          field = "cloudType"
          type  = "EQ"
          value = "aws"
        },
      ]
    }
  }

  asset_matching = {
    type = "ALL_ASSETS"
  }

  labels  = ["production"]
  enabled = true
}
