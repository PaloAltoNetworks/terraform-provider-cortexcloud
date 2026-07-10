# CloudSec policy using rule filters to dynamically match rules
# This example shows how to use filter criteria with an operator + criteria list.
#
# Valid rule-filter search fields are: cloudType, complianceStandards, severity,
# labels. The "complianceStandards" field requires the "ARRAY_CONTAINS" search
# type; the others use "EQ".

resource "cortexcloud_cloudsec_policy" "high_severity_aws_rules" {
  name        = "High Severity AWS Rules Policy"
  description = "Applies high severity AWS rules to all assets"

  # Use rule filter to dynamically match rules based on criteria.
  # filter_criteria uses an "operator" (AND/OR) and a "criteria" list where each
  # entry has "field", "type" and "value".
  rule_matching = {
    type = "RULE_FILTER"

    # Filter criteria: severity = high AND cloudType = aws
    filter_criteria = {
      operator = "AND"
      criteria = [
        {
          field = "severity"
          type  = "EQ"
          value = "high"
        },
        {
          field = "cloudType"
          type  = "EQ"
          value = "aws"
        },
      ]
    }
  }

  # Apply to all assets.
  # Note: the "CLOUD_ACCOUNTS" asset matching type is only supported when
  # rule_matching.type is "RULES"; with "RULE_FILTER" use "ALL_ASSETS" or
  # "ASSET_GROUPS".
  asset_matching = {
    type = "ALL_ASSETS"
  }

  # Custom labels
  labels = ["aws", "high-priority", "production"]

  # Enable the policy
  enabled = true
}

# Example: Policy matching compliance rules using an OR operator.
resource "cortexcloud_cloudsec_policy" "compliance_rules" {
  name        = "Compliance Rules Policy"
  description = "Applies compliance-related rules (PCI-DSS or HIPAA)"

  rule_matching = {
    type = "RULE_FILTER"

    # Filter: complianceStandards contains PCI-DSS OR complianceStandards contains HIPAA.
    # The complianceStandards field must use the ARRAY_CONTAINS search type.
    filter_criteria = {
      operator = "OR"
      criteria = [
        {
          field = "complianceStandards"
          type  = "ARRAY_CONTAINS"
          value = "PCI-DSS"
        },
        {
          field = "complianceStandards"
          type  = "ARRAY_CONTAINS"
          value = "HIPAA"
        },
      ]
    }
  }

  asset_matching = {
    type = "ALL_ASSETS"
  }

  labels  = ["compliance"]
  enabled = true
}
