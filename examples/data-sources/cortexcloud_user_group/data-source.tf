# Fetch a user group by group_name
data "cortexcloud_user_group" "example" {
  group_name = "example-group"
}

# Output the group details
output "group_id" {
  value = data.cortexcloud_user_group.example.id
}

output "group_description" {
  value = data.cortexcloud_user_group.example.description
}

output "group_role" {
  value = data.cortexcloud_user_group.example.pretty_role_name
}

output "group_users" {
  value = data.cortexcloud_user_group.example.users
}