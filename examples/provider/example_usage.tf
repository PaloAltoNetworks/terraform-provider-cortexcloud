terraform {
  required_providers {
    cortexcloud = {
      source  = "paloaltonetworks/cortexcloud"
      version = "0.0.1"
    }
  }
}

# Configure the Cortex Cloud provider
provider "cortexcloud" {
  api_url    = "https://api-cortexcloud.xdr.us.paloaltonetworks.com"
  api_key    = "REPLACE_WITH_YOUR_API_KEY"
  api_key_id = 100
}
