# AWS account template with only required values defined.
#
# This template will be created with the following configuration:
#   - No instance name
#   - All AWS regions in scanning scope
#   - All additional capabilities except Data Security Posture Management 
#     enabled
#       - Registry scanning configured to initially scan all discovered 
#         container images, including all versions (tags), in all discovered
#         ECR repositories
#   - Audit log collection enabled 
#       - Using the automated collection method
#       - Data event logs will not be collected
#   - No additional tags will be applied to Cortex Cloud resources other
#     than the "managed_by" tag with the value "paloaltonetworks", which is
#     applied by default
#
# These default values are equivaluent to the default values that are used when 
# creating this type of template in the Cortex Cloud console. See schema 
# section for more information.
resource "cortexcloud_cloud_integration_template_aws" "account_minimum_config" {
  scope     = "ACCOUNT"
  scan_mode = "MANAGED"
}
