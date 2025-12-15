data "cortexcloud_cloud_integration_instances" "example" {
  cloud_provider        = "AWS"
  name                  = "development"
  status                = "CONNECTED"
  scope                 = "ORGANIZATION"
  scan_mode             = "MANAGED"
  creation_time         = "1765482473231"
  outpost_id            = "f53de73a3f944ec69881cbf22c7c75cf"
  authentication_method = "TF"
  instance_id           = "97ae1f5ce81c4efb9426a414ac44f94a"
}
