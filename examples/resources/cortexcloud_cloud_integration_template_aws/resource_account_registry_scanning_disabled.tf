# AWS account onboarding template with registry scanning disabled.
#
# When `registry_scanning` is set to `false`, do NOT set
# `registry_scanning_options`. The API requires registry scanning and its
# options to be provided together or not at all. The provider automatically
# omits the computed default options when registry scanning is disabled, so a
# configuration like the one below applies cleanly.
resource "cortexcloud_cloud_integration_template_aws" "account_registry_scanning_disabled" {
  scope         = "ACCOUNT"
  instance_name = "AWS Account (registry scanning disabled)"
  scan_mode     = "MANAGED"

  scope_modifications = {
    regions = {
      enabled = true
      type    = "INCLUDE"
      regions = [
        "us-east-1",
        "us-east-2",
      ]
    }
  }

  additional_capabilities = {
    registry_scanning = false
  }
}
