# Azure subscription onboarding template.
#
# This template will be created with the following configuration:
#   - Instance name of "Azure Subscription"
#   - Scans scoped to the eastus and centralus regions
#   - Targeting Azure tenant ID "a1b2c3d4-e5f6-7890-1234-567890abcdef"
#   - All additional capabilities enabled
#       - Registry scanning configured to initially scan all discovered 
#         container images, including all versions (tags), in all discovered
#         ACR repositories
#   - Audit log (Azure Event Hubs) collection enabled 
#   - The "environment" tag with the value "production" will be applied to all 
#     resources created by Cortex Cloud in the target Azure environment
#       - An additional "managed_by" tag with the value "paloaltonetworks" is
#         applied by default for all onboarded CSP environments
resource "cortexcloud_cloud_integration_template_azure" "subscription" {
  scope         = "ACCOUNT"
  instance_name = "Azure Subscription"
  scan_mode     = "MANAGED"
  account_details = {
    organization_id = "a1b2c3d4-e5f6-7890-1234-567890abcdef" # Azure tenant ID
  }
  scope_modifications = {
    regions = {
      enabled = true
      type    = "INCLUDE"
      regions = [
        "eastus",
        "centralus",
      ]
    }
  }
  additional_capabilities = {
    data_security_posture_management = true
    registry_scanning                = true
    registry_scanning_options = {
      type = "ALL"
    }
    xsiam_analytics         = true
    agentless_disk_scanning = true
    serverless_scanning     = true
  }
  collection_configuration = {
    audit_logs = {
      enabled = true
    }
  }
  custom_resources_tags = [
    {
      key   = "environment"
      value = "production"
    },
  ]
}
