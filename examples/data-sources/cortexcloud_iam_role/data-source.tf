# Fetch an IAM role by role_id
data "cortexcloud_iam_role" "example" {
  role_id = "example-role-id"
}

# Output the role details
output "role_name" {
  value = data.cortexcloud_iam_role.example.pretty_name
}

output "role_description" {
  value = data.cortexcloud_iam_role.example.description
}

output "is_custom_role" {
  value = data.cortexcloud_iam_role.example.is_custom
}