# Manage an existing, connected cloud integration instance.
#
# This resource does NOT create a new integration instance. It manages an
# instance that already exists and is connected in Cortex Cloud, allowing
# in-place edits (for example toggling additional_capabilities) to be applied
# via the platform's edit API instead of forcing a destroy-and-recreate.
#
# The instance MUST be imported into Terraform state before it can be managed.
# See import.sh for the import command. The "id" value is the unique
# identifier of the connected integration instance.
resource "cortexcloud_cloud_integration_instance" "example" {
  id             = "your-integration-instance-id"
  cloud_provider = "AWS"

  additional_capabilities = {
    serverless_scanning = true
  }
}
