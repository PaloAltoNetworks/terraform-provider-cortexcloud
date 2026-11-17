# Custom compliance control
# category and subcategory accept any free-text value. The API normalizes them
# to Title Case before storing them (whitespace trimmed, each word capitalized,
# remaining letters lowercased), e.g. "my custom category" is stored as
# "My Custom Category". Write them in Title Case to avoid a plan-time warning.
resource "cortexcloud_compliance_control" "access_control" {
  name        = "Custom Access Control Policy"
  category    = "01.0 - Access Control"
  subcategory = "01.01 Business Requirement For Access Control"
  description = "Enforce access control policies and procedures"
}
