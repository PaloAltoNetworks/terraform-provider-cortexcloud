# Create User Group
resource "cortexcloud_user_group" "example" {
  group_name  = "readonly-analysts-1"
  description = "Read-only access for analysts"
  users = [
    "jdoe@paloaltonetworks.com"
  ]
  nested_groups = [
    {
      group_id = "<UUID>"
    },
    {
      group_id = "<UUID>"
    }
  ]
}
