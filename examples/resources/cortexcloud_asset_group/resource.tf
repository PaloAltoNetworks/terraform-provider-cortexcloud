# Dynamic asset group scoped to AWS production application servers
resource "cortexcloud_asset_group" "example" {
  name        = "AWS Production Application Servers"
  type        = "Dynamic"
  description = "Production application servers hosted in AWS."
  membership_predicate = {
    # Scope asset group membership to all assets that:
    #   - are hosted in AWS
    #   - contain the string "prod" in their name
    #   - have a class type of "Application"
    and = [
      {
        search_field = "xdm.asset.provider"
        search_type  = "EQ"
        search_value = "AWS"
      },
      {
        search_field = "xdm.asset.name"
        search_type  = "CONTAINS"
        search_value = "prod"
      },
      {
        search_field = "xdm.asset.type.class"
        search_type  = "EQ"
        search_value = "Application"
      },
    ]
    # Also include assets with static values
    or = [
      {
        search_field = "xdm.asset.id"
        search_type  = "EQ"
        search_value = "1bec2857-73d0-4acf-aa5f-ed6b46649b51"
      },
      {
        search_field = "xdm.asset.name"
        search_type  = "EQ"
        search_value = "legacy-app-server-us-east-1"
      },
    ]
  }
}
