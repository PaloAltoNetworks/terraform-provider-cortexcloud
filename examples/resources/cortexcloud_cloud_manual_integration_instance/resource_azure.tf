# Onboard an Azure subscription whose application registration was created
# outside Cortex Cloud.
#
# Three Azure-specific points are worth knowing before you run this:
#
#   - client_id is reported by the platform but is not offered as a write
#     attribute here. Read it back from reported_manual_details instead.
#   - account_name must not be set to an empty string; the platform rejects
#     that. Either give it a real value or leave it out entirely.
#   - some capability toggles are validated in pairs. registry_scanning has to
#     be enabled together with registry_scanning_options, and automation
#     together with automation_log_level; enabling one without the other is
#     refused. The second example below shows both pairs.
#
# additional_capabilities, collection_configuration and scope_modifications are
# all required, because the API contract marks them required. Stating them
# explicitly is what keeps the connector's configuration the one you wrote:
# nothing is filled in on your behalf.
resource "cortexcloud_cloud_manual_integration_instance" "azure_subscription" {
  cloud_provider = "AZURE"
  scope          = "ACCOUNT"
  scan_mode      = "MANAGED"

  instance_name = "azure-production-subscription"

  manual_details = {
    # subscription_id is accepted on write but never reported back, so
    # Terraform cannot detect drift in it and an import cannot recover it.
    subscription_id = "00000000-1111-2222-3333-444444444444"
    tenant_id       = "55555555-6666-7777-8888-999999999999"
    account_name    = "production-subscription"

    resource_group_name     = "cortex-cloud-rg"
    resource_group_location = "eastus"
  }

  additional_capabilities = {
    xsiam_analytics = true

    # Required. Set it to true only alongside registry_scanning_options:
    # the platform refuses either one without the other.
    registry_scanning = false
  }

  collection_configuration = {
    audit_logs = {
      # This connector does not collect audit logs. The three members are
      # required even when collection is off, so the configuration says so
      # rather than leaving it to be inferred.
      enabled           = false
      data_events       = false
      collection_method = "CUSTOM"
    }
  }

  scope_modifications = {
    # Leave every region in scope. Set enabled = true and list regions to
    # restrict the connector to a subset.
    regions = {
      enabled = false
    }
  }
}

# Onboard an Azure tenant and collect audit logs from an Event Hub.
#
# An ORGANIZATION-scoped connector must also declare the account-level scope
# bucket -- subscriptions for Azure, accounts for AWS, projects for GCP.
# Without it the platform refuses the request with "Incorrect Scope
# modifications detail provided for scoped connector".
resource "cortexcloud_cloud_manual_integration_instance" "azure_organization" {
  cloud_provider = "AZURE"
  scope          = "ORGANIZATION"
  scan_mode      = "MANAGED"

  instance_name = "azure-tenant"

  manual_details = {
    subscription_id = "00000000-1111-2222-3333-444444444444"
    tenant_id       = "55555555-6666-7777-8888-999999999999"
    account_name    = "corporate-tenant"

    resource_group_name     = "cortex-cloud-rg"
    resource_group_location = "eastus"

    eventhub_name                            = "cortex-audit-logs"
    eventhub_namespace                       = "cortex-audit-namespace"
    eventhub_resource_group_name             = "cortex-cloud-rg"
    azure_audit_eventhub_consumer_group_name = "cortex-consumer-group"
    storage_account_name                     = "cortexauditcheckpoint"
  }

  # Both paired toggles, set together. Either one alone is refused with
  # "... must both be provided together or neither should be provided".
  additional_capabilities = {
    registry_scanning         = true
    registry_scanning_options = { type = "ALL" }

    automation           = true
    automation_log_level = "OFF"
  }

  collection_configuration = {
    audit_logs = {
      enabled           = true
      data_events       = false
      collection_method = "CUSTOM"
    }
  }

  scope_modifications = {
    regions = {
      enabled = false
    }

    # Required for an ORGANIZATION-scoped Azure connector. enabled = false
    # onboards every subscription in the tenant; set enabled = true with a
    # type and subscription_ids to narrow it.
    subscriptions = {
      enabled = false
    }
  }
}

# client_id is reported by the platform and refused on write, so
# reported_manual_details is the only place it can be read. It is populated on
# the first read after the connector is created; nothing outside Terraform is
# needed to obtain it.
output "azure_application_id" {
  description = "The Azure application Cortex Cloud authenticates as."
  value       = cortexcloud_cloud_manual_integration_instance.azure_subscription.reported_manual_details.client_id
}
