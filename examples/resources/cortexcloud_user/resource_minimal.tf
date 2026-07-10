# Minimal user configuration with only required fields.
# NOTE: user_email must reference a user that already exists in your tenant.
# This resource manages an existing user's configuration; the API rejects the
# request with a 400 Bad Request if the user does not exist. Replace the email
# with a real user from your environment before applying.
resource "cortexcloud_user" "minimal_example" {
  user_email   = "jane.smith@example.com" # replace with a real user email
  phone_number = "+1-555-0100"
}