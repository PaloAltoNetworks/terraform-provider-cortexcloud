# Scope configuration for a user group with multiple scope types
# NOTE: entity_id must reference a user group that already exists in your
# tenant. The API rejects the request with a 400 Bad Request ("Group not
# found") if the group does not exist. entity_id expects the group's UUID
# (not its display name); use the group UUID from your environment (e.g. from
# the cortexcloud_user_group data source). The asset_group_id, tag, and
# endpoint values below must likewise reference existing objects in your tenant.
resource "cortexcloud_scope" "group_example" {
  entity_type = "user-group"
  # Replace with a real user-group UUID (the API expects the group UUID, not
  # the group name).
  entity_id = "00000000-0000-0000-0000-000000000000"

  # Asset scope - limit access to specific asset groups (by numeric ID).
  # mode is required; the API expects "scope" to restrict access to the
  # listed asset groups.
  assets = {
    mode = "scope"
    asset_groups = [
      # These are placeholder IDs. Replace 201/202 with real asset group IDs
      # from your tenant.
      { asset_group_id = 201 },
      { asset_group_id = 202 },
    ]
  }

  # Cases and issues scope - limit access by tags.
  cases_issues = {
    mode = "scope"
    tags = [
      { tag_name = "security_incident" },
      { tag_name = "compliance_violation" },
    ]
  }

  # Endpoints scope - limit access to specific endpoint groups and/or tags.
  endpoints = {
    endpoint_groups = {
      mode = "scope"
      tags = [
        { tag_name = "corporate-laptops" },
        { tag_name = "servers" },
      ]
    }
  }

  # Dataset rows scope with multiple datasets.
  # filter is a raw XQL query string that selects the rows in scope.
  # Replace the dataset names below with real dataset names that exist in your
  # tenant (these are only example dataset names).
  datasets_rows = {
    default_filter_mode = "no_scope"
    filters = [
      {
        dataset = "amazon_aws_raw"
        filter  = "department = \"security\""
      },
      {
        dataset = "msft_azure_raw"
        filter  = "severity in (\"critical\", \"high\")"
      },
    ]
  }
}
