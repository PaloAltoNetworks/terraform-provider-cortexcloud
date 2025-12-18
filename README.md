# Cortex Cloud Provider

Cortex&reg; Cloud is the industry-leading unified cloud security platform by Palo Alto Networks&reg;. The `cortexcloud` provider allows for the configuration and management of resources in your Cortex Cloud tenant.

## Example Usage

```terraform
terraform {
  required_providers {
    cortexcloud = {
      source  = "paloaltonetworks/cortexcloud"
      version = "1.0.1"
    }
  }
}

# Configure the Cortex Cloud provider
provider "cortexcloud" {
  api_url       = "https://api-cortexcloud.xdr.us.paloaltonetworks.com"
  api_key       = "REPLACE_WITH_YOUR_API_KEY"
  api_key_id    = 100
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
>Be sure to set the `api_key_type` attribute in the provider configuration to the appropriate key type (`"standard"` for a Standard API key or `"advanced"` for an Advanced API key) to prevent authentication errors.

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
  api_key                   = "REPLACE_WITH_YOUR_API_KEY"
  api_key_id                = 100

  # Optional
  api_key_type              = "standard"
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
export CORTEXCLOUD_API_KEY="REPLACE_WITH_YOUR_API_KEY"
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
    "api_key": "REPLACE_WITH_YOUR_API_KEY",
    "api_key_id": 100,
    "api_key_type": "standard",
    "sdk_log_level": "info",
    "request_timeout": 60,
    "request_max_retries": 3,
    "request_max_retry_delay": 60,
    "crash_stack_dir": "/var/tmp"
}
```

## Release Notes

<!-- 
Format: 

### v1.2.3 

#### FEATURES
- **New Resource**: `cortexcloud_foo`
- Added support for authenticating via bar
- resource/cortexcloud_foo_bar: Added support for singleton

#### ENHANCEMENTS
- Improved Error Handling: Added additional guidance for 503 errors (#14)
- data_source/cortexcloud_foobar: Added additional tests and examples

#### BUG FIXES
- resource/cortexcloud_boo_far: Fixed refresh operation timing out (#22)
- resource/cortexcloud_far_boo: Fixed type not being updated (#25)
-->

### v0.0.1

#### FEATURES
- Initial release

