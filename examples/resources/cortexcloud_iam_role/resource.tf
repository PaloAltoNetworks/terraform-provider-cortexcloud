# Basic IAM role with component permissions
resource "cortexcloud_iam_role" "example" {
  pretty_name = "Security Analyst"
  description = "Role for security analysts with read access to security components"

  component_permissions = [
    "alerts:read",
    "incidents:read",
    "investigations:read",
    "threat_intelligence:read"
  ]
}