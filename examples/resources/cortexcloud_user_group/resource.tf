# Create User Group
resource "cortexcloud_user_group" "example" {
  group_name  = "readonly-analysts-1"
  description = "Read-only access for analysts"

  # Optional: add members by email. Each address must belong to a user that
  # already exists in your tenant. The API rejects the request with a 400 Bad
  # Request ("User with email ... not found") if a user does not exist.
  # Uncomment and set real user emails to use:
  #
  # users = [
  #   "jdoe@example.com",
  # ]

  # Optional: nest existing groups inside this group. Each group_id must be a
  # real user-group ID from your tenant (e.g. from the cortexcloud_user_group
  # data source). The API rejects the request with a 400 Bad Request if a
  # group_id is not a valid, existing group. Uncomment and set real IDs to use:
  #
  # nested_groups = [
  #   { group_id = "00000000-0000-0000-0000-000000000001" },
  #   { group_id = "00000000-0000-0000-0000-000000000002" },
  # ]
}
