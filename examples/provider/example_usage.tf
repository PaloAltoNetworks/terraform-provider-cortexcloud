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
  api_url      = "https://api-cortexcloud.xdr.us.paloaltonetworks.com"
  api_key      = "your-api-key-here"
  api_key_id   = 100
  api_key_type = "advanced" # Possible values are "standard" or "advanced". Defaults to "advanced".
}
