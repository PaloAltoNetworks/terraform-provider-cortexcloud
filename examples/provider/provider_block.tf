provider "cortexcloud" {
  # Required
  api_url    = "https://api-cortexcloud.xdr.us.paloaltonetworks.com"
  api_key    = "REPLACE_WITH_YOUR_API_KEY"
  api_key_id = 100

  # Optional
  api_key_type            = "standard"
  sdk_log_level           = "info"
  request_timeout         = 60
  request_max_retries     = 3
  request_max_retry_delay = 60
  crash_stack_dir         = "/var/tmp"
}
