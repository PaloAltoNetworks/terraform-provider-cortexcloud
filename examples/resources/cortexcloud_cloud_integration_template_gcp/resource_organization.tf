# GCP organization onboarding template.
#
# This template will be created with the following configuration:
#   - Instance name of "GCP Organization"
#   - Scans scoped to:
#     - us-east7 and europe-west10 regions
#     - all projects that do NOT have the following ID values:
#       - test-app-1
#       - soc-automation
#   - All additional capabilities enabled
#       - Registry scanning configured to scan only container images that were
#         created or modified in the last 30 days within the discovered GCP
#         Artifact Registry repositories
#   - Audit log (GCP Pub/Sub) collection enabled 
#   - The "environment" tag with the value "production" will be applied to all 
#     resources created by Cortex Cloud in the target Azure environment
#       - An additional "managed_by" tag with the value "paloaltonetworks" is
#         applied by default for all onboarded CSP environments
resource "cortexcloud_cloud_integration_template_gcp" "organization" {
  scope         = "ORGANIZATION"
  instance_name = "GCP Organization"
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
    projects = {
      enabled = true
      type    = "EXCLUDE"
      project_ids = [
        "test-app-1",
        "soc-automation",
      ]
    }
  }
  additional_capabilities = {
    data_security_posture_management = true
    registry_scanning                = true
    registry_scanning_options = {
      type      = "TAGS_MODIFIED_DAYS"
      last_days = 30
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
