# Basic asset group with simple membership predicate
resource "cortexcloud_asset_group" "example" {
  name        = "production-servers"
  type        = "ASSET"
  description = "Production server assets"

  membership_predicate {
    and {
      search_field = "asset.type"
      search_type  = "EQUALS"
      search_value = "server"
    }
    and {
      search_field = "asset.environment"
      search_type  = "EQUALS"
      search_value = "production"
    }
  }
}