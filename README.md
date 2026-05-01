# Cortex Cloud Provider

This is the official Terraform Provider for the Palo Alto Networks Cortex Cloud platform.

## Example Usage

```terraform
terraform {
  required_providers {
    cortexcloud = {
      source  = "paloaltonetworks/cortexcloud"
      version = "1.0.4"
    }
  }
}

# Configure the Cortex Cloud provider
provider "cortexcloud" {
  api_url       = "https://api-cortexcloud.xdr.us.paloaltonetworks.com"
  api_key       = "your-api-key-here"
  api_key_id    = 100
  api_key_type  = "advanced" # Possible values are "standard" or "advanced". Defaults to "advanced".
}
```

## Authentication and Configuration

Before you begin using the provider, you will need to [create an API key in your Cortex Cloud tenant](https://docs-cortex.paloaltonetworks.com/r/Cortex-Cloud-Platform-APIs/Create-a-new-API-key). This can be done by opening the console in your web browser and navigating to `Settings > Configurations`, selecting `API Keys` under the `Integrations` section, and clicking the `New Key` button in the top-right corner.

You will also need to retrieve your API URL by clicking the `Copy API URL` button on the same page, next to the `New Key` button. If you cannot access this page, you can derive your API URL by taking your tenant's FQDN and prepending `api-` to it (i.e. `https://api-{fqdn}`).

>[!NOTE]
>It is recommended that you create a dedicated API key for use with the Cortex Cloud Terraform provider so that you may easily track any changes to your configurations made via Terraform.

>[!NOTE]
>While not a hard requirement, we recommend using an Advanced API Key for added security. Additional information on API key types can be found in the official documentation as well as the schema breakdown below.
>
>Ensure that the provider's `api_key_type` value matches the type of API key being provided (`"standard"` for a standard key or `"advanced"` for an advanced key).

There are multiple ways to specify the provider configuration values. The supported methods are listed below, in the order in which they are applied:
1) Parameters in the provider block
2) Environment variables
3) Configuration file (in JSON format)

### Provider Block Parameters

Credentials can be provided through the `cortexcloud` provider block:

```terraform
provider "cortexcloud" {
  # Required
  api_url                   = "https://api-cortexcloud.xdr.us.paloaltonetworks.com"
  api_key                   = "your-api-key-here"
  api_key_id                = 100

  # Optional
  api_key_type              = "advanced"
  sdk_log_level             = "info"
  request_timeout           = 60
  request_max_retries       = 3
  request_max_retry_delay   = 60
  crash_stack_dir           = "/var/tmp"
}
```

### Environment Variables

Credentials can be provided by using the `CORTEXCLOUD_API_URL`, `CORTEXCLOUD_API_KEY`, `CORTEXCLOUD_API_KEY_ID` environment variables.

If you are using an Advanced API key, you will also need to set the `api_key_type` attribute using the `CORTEXCLOUD_API_KEY_TYPE` environment variable.

Example:

```terraform
provider "cortexcloud" {}
```

```shell
export CORTEXCLOUD_API_URL="https://api-cortexcloud.xdr.us.paloaltonetworks.com"
export CORTEXCLOUD_API_KEY="your-api-key-here"
export CORTEXCLOUD_API_KEY_ID=100
export CORTEXCLOUD_API_KEY_TYPE="advanced"
```

### Configuration File

Credentials can be provided by creating a JSON file with the following structure and configuring the provider's `config_file` attribute with the full or relative filepath:

```terraform
provider "cortexcloud" {
  config_file = "./cortexcloud_config.json"
}
```

```json
{
    "api_url": "https://api-cortexcloud.xdr.us.paloaltonetworks.com",
    "api_key": "your-api-key-here",
    "api_key_id": 100,
    "api_key_type": "advanced",
    "sdk_log_level": "info",
    "request_timeout": 60,
    "request_max_retries": 3,
    "request_max_retry_delay": 60,
    "crash_stack_dir": "/var/tmp"
}
```

## Release Notes

### v1.0.4

#### Features
* **New Resource**: `cortexcloud_appsec_rule`
* **New Resource**: `cortexcloud_appsec_policy`
* **New Resource**: `cortexcloud_cloudsec_rule`
* **New Resource**: `cortexcloud_cloudsec_policy`
* **New Resource**: `cortexcloud_compliance_assessment_profile`
* **New Resource**: `cortexcloud_compliance_control`
* **New Resource**: `cortexcloud_compliance_standard`
* **New Resource**: `cortexcloud_cwp_policy`
* **New Resource**: `cortexcloud_notification_forwarding_config_agent_audit_logs`
* **New Resource**: `cortexcloud_notification_forwarding_config_mgmt_audit_logs`
* **New Resource**: `cortexcloud_notification_forwarding_config_cases`
* **New Resource**: `cortexcloud_notification_forwarding_config_issues`
* **New Resource**: `cortexcloud_vulnerability_policy`
* **New Data Source**: `cortexcloud_appsec_rule`
* **New Data Source**: `cortexcloud_appsec_rules`
* **New Data Source**: `cortexcloud_appsec_rule_labels`
* **New Data Source**: `cortexcloud_appsec_policy`
* **New Data Source**: `cortexcloud_appsec_policies`
* **New Data Source**: `cortexcloud_cloudsec_policy`
* **New Data Source**: `cortexcloud_cloudsec_rule`
* **New Data Source**: `cortexcloud_cloudsec_rules`
* **New Data Source**: `cortexcloud_compliance_assessment_profile`
* **New Data Source**: `cortexcloud_compliance_control`
* **New Data Source**: `cortexcloud_compliance_controls`
* **New Data Source**: `cortexcloud_compliance_standard`
* **New Data Source**: `cortexcloud_compliance_standards`
* **New Data Source**: `cortexcloud_cwp_policy`
* **New Data Source**: `cortexcloud_cwp_policies`
* **New Data Source**: `cortexcloud_vulnerability_policy`
* **New Data Source**: `cortexcloud_vulnerability_policies`

#### Enhancements
* Addressed missing attribute descriptions in various resource and data sources across all domains
* Added validation check against the `api_key_type` attribute in the provider configuration block.

#### Bug Fixes
* Fixed `cortexcloud_user_group` resource not accounting for users with effective membership via SSO/JIT authentication against one or more of the configured SAML groups. The `users` attribute now reflects only users that have been directly added to the group in the Terraform resource. See resource documentation page for more information.
* Changed attribute types for the `cortexcloud_user_group` resource's `idp_groups`, `nested_groups` and `users` attributes from List to Set to preserve ordering from the upstream API response.
* Fixed `outpost_id` not being honored on create or update for the `cortexcloud_cloud_integration_template_aws`, `cortexcloud_cloud_integration_template_azure`, and `cortexcloud_cloud_integration_template_gcp` resources. The configured outpost (or the platform-managed outpost used when the `scan_mode` attribute is set to `"MANAGED"`) is now correctly applied and refreshed on read.
* Fixed an incorrect attribute description on the `collector` field of the `cortexcloud_cloud_integration_instance` data source, which previously mirrored the `cloud_provider` description.

### v1.0.3

#### Breaking Changes
* The provider's `fqdn` configuration attribute and the `CORTEXCLOUD_FQDN` environment variable have been removed. Use `api_url` (or `CORTEXCLOUD_API_URL`) instead.

#### Enhancements
* Updated documentation for outpost resources and data sources with additional details and improved clarity.
* Correct reference to unreleased version in usage example in README
* Updated examples for asset group resource with working implementation and an additional example for static scope filters.
* Various minor updates to project documentation.

#### Bug Fixes
* Fixed sprawling attribute schema in asset group resource documentation and added patch step to prevent overwriting in future doc updates.


### v1.0.2

#### Features
* Initial GA release
