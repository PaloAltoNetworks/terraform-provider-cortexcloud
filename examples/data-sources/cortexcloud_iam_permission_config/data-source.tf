# Fetch IAM permission configuration
data "cortexcloud_iam_permission_config" "example" {
}

# Output the available RBAC permissions
output "rbac_permissions" {
  value = data.cortexcloud_iam_permission_config.example.rbac_permissions
}

# Output the available dataset groups
output "dataset_groups" {
  value = data.cortexcloud_iam_permission_config.example.dataset_groups
}