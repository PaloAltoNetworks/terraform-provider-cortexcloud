# CloudSec policy that applies all rules to all assets
# This is the simplest policy configuration
resource "cortexcloud_cloudsec_policy" "all_rules_all_assets" {
  name        = "Global Security Policy"
  description = "Applies all CloudSec detection rules to all cloud assets across all environments"

  # Match all rules in the system
  rule_matching = {
    type = "ALL_RULES"
  }

  # Apply to all assets
  asset_matching = {
    type = "ALL_ASSETS"
  }

  # Custom labels for organization
  labels = ["Global", "All Environments"]

  # Enable the policy
  enabled = true
}