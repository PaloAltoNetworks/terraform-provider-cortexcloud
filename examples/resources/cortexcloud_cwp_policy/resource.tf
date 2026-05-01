resource "cortexcloud_cwp_policy" "example" {
  name             = "Example CWP Policy"
  description      = "Example Cloud Workload Protection policy"
  type             = "COMPLIANCE"
  evaluation_stage = "RUNTIME"
  asset_group_ids  = [1, 2, 3]
  policy_rules = [
    {
      rule_id  = "00000000-0000-0000-0000-000000000011"
      action   = "ISSUE"
      severity = "HIGH"
    },
    {
      rule_id  = "00000000-0000-0000-0000-000000000302"
      action   = "PREVENT"
      severity = "LOW"
    }
  ]
  remediation_guidance = "Review and remediate the identified issues."
}
