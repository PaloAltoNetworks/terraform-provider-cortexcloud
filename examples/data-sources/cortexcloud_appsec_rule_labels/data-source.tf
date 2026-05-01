data "cortexcloud_appsec_rule_labels" "all" {
}

output "available_labels" {
  value = data.cortexcloud_appsec_rule_labels.all.labels
}