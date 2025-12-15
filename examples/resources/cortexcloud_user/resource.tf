# Update user configuration
resource "cortexcloud_user" "example" {
  user_email      = "john.doe@example.com"
  phone_number    = "+1-555-0123"
  status          = "active"

  # Assign user to groups
  groups = [
    "security-team",
    "analysts"
  ]
}