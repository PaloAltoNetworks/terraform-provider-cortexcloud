# A custom control to associate with the standard below.
#
# Note: control "name" must be unique within your tenant. If a control with
# this name already exists, creation fails. Adjust the name as needed.
resource "cortexcloud_compliance_control" "access_control" {
  name        = "Custom Security Framework 2026 - Access Control"
  category    = "01.0 - Access Control"
  subcategory = "01.01 Business Requirement For Access Control"
  description = "Enforce access control policies and procedures"
}

# Custom compliance standard with controls
resource "cortexcloud_compliance_standard" "custom_framework" {
  name        = "Custom Security Framework 2026"
  description = "Internal security compliance framework"
  labels      = ["aws", "azure", "gcp"]
  controls_ids = [
    cortexcloud_compliance_control.access_control.id,
  ]
}
