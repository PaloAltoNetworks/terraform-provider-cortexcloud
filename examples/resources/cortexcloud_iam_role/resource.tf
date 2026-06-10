# Basic IAM role with component permissions
# Valid permission tokens can be discovered from data.cortexcloud_iam_permission_config
resource "cortexcloud_iam_role" "example" {
  pretty_name = "Security Analyst"
  description = "Role for security analysts with read access to security components"

  component_permissions = [
    "access_management_view",
    "agent_groups_view",
    "app_sec_detection_rules_view",
  ]
}