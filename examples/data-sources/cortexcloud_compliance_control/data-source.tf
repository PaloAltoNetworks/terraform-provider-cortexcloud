data "cortexcloud_compliance_control" "existing" {
  id = "ctrl-123"
}

output "control_name" {
  value = data.cortexcloud_compliance_control.existing.name
}