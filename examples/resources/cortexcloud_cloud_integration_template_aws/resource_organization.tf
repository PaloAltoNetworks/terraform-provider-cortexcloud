# AWS organization onboarding template.
#
# This template will be created with the following configuration:
#   - Instance name of "AWS Organization"
#   - Scans scoped to the us-east-1 region 
#   - all additional capabilities enabled
#       - registry scanning configured to initially scan all discovered 
#         registries 
#   - audit log collection enabled 
#       - using the automated collection method
#       - Data event logs will not be collected
#   - apply the `environment` tag with the value `production` to all resources
#     created by Cortex in the target AWS environment
resource "cortexcloud_cloud_integration_template_aws" "organization" {
  scope         = "ORGANIZATION"
  instance_name = "AWS Organization"
  scan_mode     = "MANAGED"
  scope_modifications = {
    accounts = {
      enabled = true
      type    = "EXCLUDE"
      account_ids = [
        "012345678901",
        "345678901234",
      ]
    }
    regions = {
      enabled = true
      type    = "EXCLUDE"
      regions = [
        "us-west-1",
        "ca-central-1",
      ]
    }
  }
  additional_capabilities = {
    data_security_posture_management = true
    registry_scanning                = true
    registry_scanning_options = {
      type = "LATEST_TAG"
    }
    xsiam_analytics         = true
    agentless_disk_scanning = true
  }
  collection_configuration = {
    audit_logs = {
      enabled           = true
      collection_method = "AUTOMATED"
      data_events       = true
    }
  }
  custom_resources_tags = [
    {
      key   = "cost_center"
      value = "555123"
    },
    {
      key   = "department"
      value = "marketing"
    },
  ]
}
