# NOTE: The rule_id and asset_group_ids below are placeholders. A CWP policy
# create request is rejected by the API ("Bad Request - The provided user data
# is invalid") unless every rule_id references a CWP rule that exists on your
# tenant and every asset_group_id references an existing asset group. Replace
# the placeholder values with real IDs from your environment before applying.
resource "cortexcloud_cwp_policy" "example" {
  name             = "Example CWP Policy"
  description      = "Example Cloud Workload Protection policy"
  type             = "COMPLIANCE"
  evaluation_stage = "RUNTIME"
  asset_group_ids  = [1, 2, 3] # replace with real asset group IDs
  policy_rules = [
    {
      rule_id  = "00000000-0000-0000-0000-000000000011" # replace with a real CWP rule ID
      action   = "ISSUE"
      severity = "HIGH"
    },
    {
      rule_id  = "00000000-0000-0000-0000-000000000302" # replace with a real CWP rule ID
      action   = "PREVENT"
      severity = "LOW"
    }
  ]
  remediation_guidance = "Review and remediate the identified issues."
}
