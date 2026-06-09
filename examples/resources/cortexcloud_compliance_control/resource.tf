# Custom compliance control
resource "cortexcloud_compliance_control" "access_control" {
  name        = "Custom Access Control Policy"
  category    = "Access Control"
  subcategory = "AC-1"
  description = "Enforce access control policies and procedures"
}