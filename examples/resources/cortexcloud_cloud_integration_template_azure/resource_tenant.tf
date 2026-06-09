# Azure tenant onboarding template.
# Azure tenant onboarding template.
#
# This template will be created with the following configuration:
#   - Instance name of "Azure Tenant"
#   - Scans scoped to:
#     - eastus and centralus regions
#     - all subscriptions that do NOT have the following ID values:
#       - fe8dd810-6863-4795-bb65-19ed7f3f5d8a
#       - 0bb6c67d-95bb-499c-9efa-cdf91e63ccf5
#   - Targeting Azure tenant ID "39b3bc2e-77f4-49c5-9298-8f8972abf448"
#   - All additional capabilities enabled
#       - Registry scanning configured to initially scan all discovered 
#         container images, including all versions (tags), in all discovered
#         ACR repositories
#   - Audit log (Azure Event Hubs) collection enabled 
#   - The "environment" tag with the value "production" will be applied to all 
#     resources created by Cortex Cloud in the target Azure environment
#       - An additional "managed_by" tag with the value "paloaltonetworks" is
#         applied by default for all onboarded CSP environments
#
# IMPORTANT: After running `terraform apply`, the integration will be in
# PENDING status. You must deploy the generated ARM template or Terraform
# module in your Azure environment to complete the onboarding. See the
# management group example for detailed instructions.
resource "cortexcloud_cloud_integration_template_azure" "tenant" {
  scope         = "ORGANIZATION"
  instance_name = "Azure Tenant"
  scan_mode     = "MANAGED"
  account_details = {
    organization_id = "39b3bc2e-77f4-49c5-9298-8f8972abf448" # Azure tenant ID
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

output "tenant_arm_template_url" {
  description = "Download and deploy this ARM template in your Azure environment to complete onboarding."
  value       = cortexcloud_cloud_integration_template_azure.tenant.arm_template_url
}

output "tenant_terraform_module_url" {
  description = "Alternatively, download and apply this Terraform module in your Azure environment."
  value       = cortexcloud_cloud_integration_template_azure.tenant.terraform_module_url
}
