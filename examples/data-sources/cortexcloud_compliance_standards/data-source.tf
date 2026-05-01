data "cortexcloud_compliance_standards" "custom" {
  search_from = 0
  search_to   = 50

  filter {
    field    = "is_custom"
    operator = "in"
    value    = "true"
  }
}