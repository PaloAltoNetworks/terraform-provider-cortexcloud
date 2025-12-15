# Basic scope configuration for a user
resource "cortexcloud_scope" "example" {
  entity_type = "user"
  entity_id   = "user@example.com"

  # Asset scope - limit access to specific assets
  assets {
    asset_groups = ["production-servers", "development-servers"]
  }

  # Dataset rows scope - limit access to specific dataset rows
  datasets_rows {
    dataset_name = "security_logs"
    filter_json = jsonencode({
      field    = "severity"
      operator = "equals"
      value    = "high"
    })
  }
}