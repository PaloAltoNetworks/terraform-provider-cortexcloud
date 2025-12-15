resource "cortexcloud_outpost_template" "example" {
  cloud_provider = "AWS"
  custom_resources_tags = [
    {
      key   = "cost_center"
      value = "fin-123"
    },
    {
      key   = "criticality"
      value = "high"
    },
  ]
}
