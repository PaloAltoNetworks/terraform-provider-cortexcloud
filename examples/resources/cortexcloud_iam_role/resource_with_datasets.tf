# IAM role with component and dataset permissions.
#
# Valid component permission tokens and dataset categories are tenant-specific
# and can be discovered from the cortexcloud_iam_permission_config data source.
# Dataset categories are values such as: System, Lookup, Raw, Snapshot.
resource "cortexcloud_iam_role" "with_datasets" {
  pretty_name = "Data Analyst"
  description = "Role for data analysts with access to specific datasets"

  component_permissions = [
    "actions_center_action",
  ]

  dataset_permissions = [
    {
      category   = "System"
      access_all = false
    },
    {
      category   = "Lookup"
      access_all = true
    },
  ]
}
