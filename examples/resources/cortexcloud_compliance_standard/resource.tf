# Custom compliance standard with controls
resource "cortexcloud_compliance_standard" "custom_framework" {
  name        = "Custom Security Framework 2026"
  description = "Internal security compliance framework"
  labels      = ["aws", "azure", "production"]
  controls_ids = [
    cortexcloud_compliance_control.access_control.id,
  ]
}