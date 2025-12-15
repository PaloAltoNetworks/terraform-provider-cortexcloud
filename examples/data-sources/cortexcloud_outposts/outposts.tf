data "cortexcloud_outposts" "example" {
  cloud_provider       = "AWS"
  status               = "ERROR"
  outpost_account_name = "production"
  outpost_account_id   = "b06fc42ae2694fcd9b91bba3736d760a"
  created_at = {
    from = 1000000000000
    from = 2000000000000
  }
  number_of_instances = {
    condition = "LT"
    value     = "10"
  }
}
