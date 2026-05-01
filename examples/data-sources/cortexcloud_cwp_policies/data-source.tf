# Get all CWP policies
data "cortexcloud_cwp_policies" "all" {
}

# Get only compliance policies
data "cortexcloud_cwp_policies" "compliance_only" {
  policy_types = ["COMPLIANCE"]
}

# Get malware and secret policies
data "cortexcloud_cwp_policies" "malware_and_secret" {
  policy_types = ["MALWARE", "SECRET"]
}

# Output the total number of CWP policies
output "all_policy_count" {
  value = length(data.cortexcloud_cwp_policies.all.policies)
}

# Output the names of all of the compliance type policies
output "compliance_policy_names" {
  value = [for p in data.cortexcloud_cwp_policies.compliance_only.policies : p.name]
}
