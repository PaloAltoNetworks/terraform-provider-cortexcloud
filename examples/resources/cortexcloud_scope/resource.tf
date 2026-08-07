# Basic scope configuration for a user
resource "cortexcloud_scope" "example" {
  entity_type = "user"
  entity_id   = "user@example.com" # replace with a real user email in your tenant

  # Asset scope - limit access to specific asset groups.
  # mode is required; use "scope" to restrict to the listed groups,
  # "no_scope" for none, or "see_all" for all.
  # asset_groups are referenced by their numeric IDs - replace the
  # placeholder IDs below with real asset group IDs from your tenant.
  assets = {
    mode = "scope"
    asset_groups = [
      { asset_group_id = 101 }, # replace with a real asset group ID
      { asset_group_id = 102 }, # replace with a real asset group ID
    ]
  }

  # Dataset rows scope. Include this block only when dataset-level SBAC is
  # enabled on your tenant, and omit it entirely when SBAC is disabled.
  # default_filter_mode is required (one of "no_scope", "see_all").
  # Each filter's `dataset` must be a real dataset in your tenant and
  # `filter` must be a valid XQL predicate referencing fields that exist
  # in that dataset's schema. The example below uses the built-in
  # amazon_aws_raw dataset; adjust the field/value to match your data.
  datasets_rows = {
    default_filter_mode = "no_scope"
    filters = [
      {
        dataset = "amazon_aws_raw"
        filter  = "eventSource = \"s3.amazonaws.com\""
      },
    ]
  }
}
