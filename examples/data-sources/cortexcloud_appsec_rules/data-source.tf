data "cortexcloud_appsec_rules" "custom" {
  is_custom = true
  limit     = 50
  offset    = 0
}