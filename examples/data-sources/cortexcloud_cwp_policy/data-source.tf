data "cortexcloud_cwp_policy" "example" {
  id = "policy-id-123"
}

# Access policy attributes
output "policy_name" {
  value = data.cortexcloud_cwp_policy.example.name
}

output "policy_type" {
  value = data.cortexcloud_cwp_policy.example.type
}

output "policy_severity" {
  value = data.cortexcloud_cwp_policy.example.severity
}
