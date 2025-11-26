# AWS account onboarding template.
#
# This template will be created with the following configuration:
#   - Instance name of "AWS Account"
#   - Scoped to the us-east-1 region 
#   - All additional capabilities enabled
#       - Registry scanning configured to initially scan all discovered 
#         container images, including all versions (tags), in all discovered
#         ECR repositories
#   - Audit log collection enabled 
#       - Using the automated collection method
#       - Data event logs will not be collected
#   - The "environment" tag with the value "production" will be applied to all 
#     resources created by Cortex Cloud in the target AWS environment
#       - An additional "managed_by" tag with the value "paloaltonetworks" is
#         applied by default for all onboarded CSP environments
resource "cortexcloud_cloud_integration_template_aws" "account" {
    scope = "ACCOUNT"
    instance_name = "AWS Account"
    scan_mode = "MANAGED"
    scope_modifications = {
        regions = {
            enabled = true
            type = "INCLUDE"
            regions = [ "us-east-1" ]
        }
    }
    additional_capabilities = {
        data_security_posture_management = true
        registry_scanning = true
        registry_scanning_options = {
            type = "ALL" 
        }
        xsiam_analytics = true
        agentless_disk_scanning = true
    }
    collection_configuration = {
        audit_logs = {
            enabled = true
            collection_method = "AUTOMATED"
            data_events = false
        }
    }
    custom_resources_tags = [
        {
            key = "environment"
            value = "production"
        },
    ]
}
