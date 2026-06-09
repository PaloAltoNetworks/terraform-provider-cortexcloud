# Custom compliance control
# Valid category/subcategory values can be retrieved from:
# /public_api/v1/compliance/get_control_categories_and_subcategories/
resource "cortexcloud_compliance_control" "access_control" {
  name        = "Custom Access Control Policy"
  category    = "01.0 - Access Control"
  subcategory = "01.01 Business Requirement For Access Control"
  description = "Enforce access control policies and procedures"
}