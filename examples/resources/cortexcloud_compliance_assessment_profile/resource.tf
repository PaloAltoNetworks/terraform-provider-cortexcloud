# Compliance assessment profile
resource "cortexcloud_compliance_assessment_profile" "monthly_aws" {
  name             = "Monthly AWS Compliance Check"
  standard_id      = cortexcloud_compliance_standard.custom_framework.id
  asset_group_id   = 1
  description      = "Monthly compliance assessment for AWS"
  report_type      = "PDF"
  report_targets   = ["security@example.com"]
  report_frequency = "0 12 1 * *" # First day of month at 12:00
}