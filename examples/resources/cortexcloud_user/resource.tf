# Update user configuration
# NOTE: user_email must reference a user that already exists in your tenant.
# This resource manages an existing user's configuration; the API rejects the
# request with a 400 Bad Request if the user does not exist. Replace the email
# with a real user from your environment before applying.
resource "cortexcloud_user" "example" {
  user_email   = "john.doe@example.com" # replace with a real user email
  phone_number = "+1-555-0123"
  status       = "active"

  # Optional: assign the user to groups by their group IDs. Each group_id must
  # be a real group ID from your tenant (e.g. from the cortexcloud_user_group
  # data source). The API rejects the request with a 400 Bad Request if a
  # group_id is not a valid, existing group. Uncomment and set real IDs to use:
  #
  # group_ids = [
  #   "00000000-0000-0000-0000-000000000001",
  #   "00000000-0000-0000-0000-000000000002",
  # ]
}
