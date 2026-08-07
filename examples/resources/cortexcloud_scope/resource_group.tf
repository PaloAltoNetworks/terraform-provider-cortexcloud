# Scope configuration for a user group with multiple scope types
resource "cortexcloud_scope" "group_example" {
  entity_type = "user-group"
  # For a user group, entity_id is the group's UUID (not its display name).
  # Replace the placeholder below with a real group ID from your tenant.
  entity_id = "00000000-0000-0000-0000-000000000000"

  # Asset scope - limit access to specific asset groups (by numeric ID).
  # Replace the placeholder IDs with real asset group IDs from your tenant.
  assets = {
    mode = "scope"
    asset_groups = [
      { asset_group_id = 201 }, # replace with a real asset group ID
      { asset_group_id = 202 }, # replace with a real asset group ID
    ]
  }

  # Cases and issues scope - limit access by tags.
  # tag_name values must be real case/issue tags that exist in your tenant.
  cases_issues = {
    mode = "scope"
    tags = [
      { tag_name = "example-case-tag" },  # replace with a real case/issue tag
      { tag_name = "example-issue-tag" }, # replace with a real case/issue tag
    ]
  }

  # Endpoints scope - limit access to specific endpoint groups and/or tags.
  # tag_name values must be real endpoint tags that exist in your tenant.
  endpoints = {
    endpoint_groups = {
      mode = "scope"
      tags = [
        { tag_name = "example-endpoint-tag-1" }, # replace with a real endpoint tag
        { tag_name = "example-endpoint-tag-2" }, # replace with a real endpoint tag
      ]
    }
  }

  # Dataset rows scope with multiple datasets.
  # Each `dataset` must be a real dataset in your tenant and each `filter`
  # must be a valid XQL predicate referencing fields in that dataset's schema.
  datasets_rows = {
    default_filter_mode = "no_scope"
    filters = [
      {
        dataset = "amazon_aws_raw"
        filter  = "eventSource = \"s3.amazonaws.com\""
      },
      {
        dataset = "amazon_aws_raw"
        filter  = "eventName in (\"DeleteBucket\", \"PutBucketPolicy\")"
      },
    ]
  }
}
