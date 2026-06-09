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
#
# IMPORTANT: After running `terraform apply`, the integration will be in
# PENDING status. To complete the onboarding, you must deploy the generated
# ARM template or Terraform module in your Azure environment. See the output
# values below for the download URLs.
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

# =============================================================================
# Completing the onboarding
# =============================================================================
# After `terraform apply` succeeds, the template will be in PENDING status.
# You must deploy the generated template in your Azure environment to grant
# Cortex Cloud the necessary permissions and complete the onboarding.
#
# Steps:
#   1. Copy the `arm_template_url` output value below.
#   2. Open the URL in your browser to download the ARM template archive.
#   3. Extract the downloaded archive.
#   4. Ensure Azure CLI is installed and authenticated (run `az login`).
#   5. Run `bash onboard.sh` from the extracted directory.
#   6. Provide the prompted values:
#        - The management group or tenant ID to onboard
#        - A subscription ID to host the onboarding resource group
#        - The Azure location for creating onboarding resources
#   7. Wait for the script to complete. It will automatically notify Cortex
#      Cloud, and the integration status will transition from PENDING to
#      CONNECTED.
#
# Alternatively, you can use the `terraform_module_url` output to download
# a Terraform module instead of the ARM template.
# =============================================================================

output "arm_template_url" {
  description = "Download and deploy this ARM template in your Azure environment to complete onboarding."
  value       = cortexcloud_cloud_integration_template_azure.management-group.arm_template_url
}

output "terraform_module_url" {
  description = "Alternatively, download and apply this Terraform module in your Azure environment."
  value       = cortexcloud_cloud_integration_template_azure.management-group.terraform_module_url
}

output "tracking_guid" {
  description = "The unique ID of this integration template."
  value       = cortexcloud_cloud_integration_template_azure.management-group.tracking_guid
}

output "status" {
  description = "Current status of the integration (PENDING until the template is deployed in Azure)."
  value       = cortexcloud_cloud_integration_template_azure.management-group.status
}
