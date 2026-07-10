# Basic scope configuration for a user
# NOTE: entity_id must reference a user that already exists in your tenant.
# The API rejects the request with a 400 Bad Request if the user is not found.
# Replace "user@example.com" with a real user email from your environment
# (e.g. from the cortexcloud_user data source). Likewise, the asset_group_id
# values below must reference existing asset groups.
resource "cortexcloud_scope" "example" {
  entity_type = "user"
  entity_id   = "user@example.com" # replace with a real user email

  # Asset scope - limit access to specific asset groups.
  # mode is required; the API expects "scope" to restrict access to the
  # listed asset groups. asset_groups are referenced by their numeric IDs.
  assets = {
    mode = "scope"
    asset_groups = [
      # These are placeholder IDs. Replace 101/102 with real asset group IDs
      # from your tenant (e.g. from the cortexcloud asset group resource).
      { asset_group_id = 101 },
      { asset_group_id = 102 },
    ]
  }

  # Dataset rows scope - limit access to specific dataset rows.
  # default_filter_mode is required (one of "no_scope", "see_all").
  # filter is a raw XQL query string that selects the rows in scope.
  datasets_rows = {
    default_filter_mode = "no_scope"
    filters = [
      {
        # Replace "amazon_aws_raw" with a real dataset name that exists in
        # your tenant (this is only an example dataset name).
        dataset = "amazon_aws_raw"
        filter  = "severity = \"high\""
      },
    ]
  }
}
