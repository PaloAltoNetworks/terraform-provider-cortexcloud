# AWS account onboarding template that is automatically deployed using the AWS 
# Terraform Provider.
# 
# This template will be created with the following configuration:
#   - Instance name of `AWS Account`
#   - All AWS regions in scanning scope
#   - All additional capabilities enabled
#       - Registry scanning configured to scan only container images that were
#         created or modified in the last 7 days within the discovered ECR 
#         repositories
#   - Audit log collection enabled 
#       - Using a custom (user-defined) collection method
#   - No additional tags will be applied to Cortex Cloud resources other
#     than the "managed_by" tag with the value "paloaltonetworks", which is
#     applied by default
#
# After creation, this template will be deployed as a CloudFormation stack in 
# the target AWS environment. See AWS Terraform provider documentation page for
# the `aws_cloudformation_stack` resource for more information.
resource "cortexcloud_cloud_integration_template_aws" "account_auto_deploy" {
  scope         = "ACCOUNT"
  instance_name = "AWS Account"
  scan_mode     = "MANAGED"
  scope_modifications = {
    regions = {
      enabled = false
    }
  }
  additional_capabilities = {
    data_security_posture_management = true
    registry_scanning                = true
    registry_scanning_options = {
      type      = "TAGS_MODIFIED_DAYS"
      last_days = 7
    }
    xsiam_analytics         = true
    agentless_disk_scanning = true
  }
  collection_configuration = {
    audit_logs = {
      enabled           = true
      collection_method = "CUSTOM"
    }
  }
}

# Using the value of the template resource's `cloudformation_template_url`
# attribute as the argument for the CloudFormation stack resource's
# `template_url` attribute.
#
# PREREQUISITE: This example uses the `aws_cloudformation_stack` resource from
# the official AWS Terraform provider (hashicorp/aws). To apply it you must:
#   1. Declare the `aws` provider in your configuration's `required_providers`
#      block and run `terraform init`.
#   2. Configure the AWS provider with valid credentials for the target
#      account (for example via the `AWS_ACCESS_KEY_ID` /
#      `AWS_SECRET_ACCESS_KEY` environment variables, a shared credentials
#      profile, or an assumed IAM role). The credentials must have permission
#      to create CloudFormation stacks and the named IAM resources they define.
#
# Note: the `CAPABILITY_NAMED_IAM` capability is required in order to
# successfully deploy the CloudFormation stack.
resource "aws_cloudformation_stack" "cortex_cloud_account_integration" {
  name         = "cortex-cloud"
  template_url = resource.cortexcloud_cloud_integration_template_aws.account_auto_deploy.cloudformation_template_url
  capabilities = ["CAPABILITY_NAMED_IAM"] // Required
}
