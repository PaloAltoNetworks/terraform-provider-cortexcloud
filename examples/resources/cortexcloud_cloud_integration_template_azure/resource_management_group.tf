# Azure management group onboarding template.
#
# This template will be created with the following configuration:
#   - Instance name of "Azure Management Group"
#   - Scans scoped to:
#     - eastus and centralus regions
#     - all subscriptions that do NOT have the following ID values:
#       - fe8dd810-6863-4795-bb65-19ed7f3f5d8a
#       - 0bb6c67d-95bb-499c-9efa-cdf91e63ccf5
#   - Targeting Azure tenant ID "0091a7ea-5021-42d3-a276-18004980b42b"
#   - All additional capabilities enabled
#       - Registry scanning configured to initially scan all discovered 
#         container images, including all versions (tags), in all discovered
#         ACR repositories
#   - Audit log (Azure Event Hubs) collection enabled 
#   - The "environment" tag with the value "production" will be applied to all 
#     resources created by Cortex Cloud in the target Azure environment
#       - An additional "managed_by" tag with the value "paloaltonetworks" is
#         applied by default for all onboarded CSP environments
resource "cortexcloud_cloud_integration_template_azure" "management-group" {
  scope         = "ACCOUNT_GROUP"
  instance_name = "Azure Management Group"
  scan_mode     = "MANAGED"
  account_details = {
    organization_id = "0091a7ea-5021-42d3-a276-18004980b42b" # Azure tenant ID
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
    subscriptions = {
      enabled = true
      type    = "EXCLUDE"
      subscription_ids = [
        "fe8dd810-6863-4795-bb65-19ed7f3f5d8a",
        "0bb6c67d-95bb-499c-9efa-cdf91e63ccf5",
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
      enabled           = true
      collection_method = "AUTOMATED"
      data_events       = false
    }
  }
  custom_resources_tags = [
    {
      key   = "environment"
      value = "production"
    },
  ]
}
