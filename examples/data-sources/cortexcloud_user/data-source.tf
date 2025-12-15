# Fetch a user by email
data "cortexcloud_user" "example" {
  user_email = "user@example.com"
}

output "user_role" {
  value = data.cortexcloud_user.example.role_name
}

output "user_status" {
  value = data.cortexcloud_user.example.status
}

output "user_groups" {
  value = data.cortexcloud_user.example.groups
}