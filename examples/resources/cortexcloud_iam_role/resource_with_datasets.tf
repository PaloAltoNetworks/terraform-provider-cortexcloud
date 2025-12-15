# IAM role with component and dataset permissions
resource "cortexcloud_iam_role" "with_datasets" {
  pretty_name = "Data Analyst"
  description = "Role for data analysts with access to specific datasets"

  component_permissions = [
    "actions_center_action",
    "file_search"
  ]

  dataset_permissions {
    category   = "security_logs"
    access_all = false
    permissions = [
      "read",
      "query"
    ]
  }

  dataset_permissions {
    category   = "network_traffic"
    access_all = true
    permissions = [
      "read",
      "query",
      "export"
    ]
  }
}