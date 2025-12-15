# GCP project onboarding template.
#
# This template will be created with the following configuration:
#   - Instance name of "GCP Project"
#   - Scans scoped to the us-east7 and europe-west10 regions
#   - All additional capabilities enabled
#       - Registry scanning configured to initially scan all discovered 
#         container images, including all versions (tags), in all discovered
#         GCP Artifact Registry repositories
#   - Audit log (GCP Pub/Sub) collection enabled 
#   - The "environment" tag with the value "production" will be applied to all 
#     resources created by Cortex Cloud in the target Azure environment
#       - An additional "managed_by" tag with the value "paloaltonetworks" is
#         applied by default for all onboarded CSP environments
resource "cortexcloud_cloud_integration_template_gcp" "project" {
  scope         = "ACCOUNT"
  instance_name = "GCP Project"
  scan_mode     = "MANAGED"
  scope_modifications = {
    regions = {
      enabled = true
      type    = "INCLUDE"
      regions = [
        "us-east7",
        "europe-west10",
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
