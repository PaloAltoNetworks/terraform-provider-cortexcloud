# Onboard an AWS account whose IAM roles were created outside Cortex Cloud.
#
# Use this resource when the cloud-side identities already exist -- created by
# your own CloudFormation, Terraform AWS provider configuration, or by hand --
# and you are supplying them to Cortex Cloud. If you want Cortex Cloud to
# generate a deployment template for you instead, use
# cortexcloud_cloud_integration_template_aws.
#
# cloud_provider, scope and scan_mode are fixed when the connector is created.
# Changing any of them replaces the connector.
resource "cortexcloud_cloud_manual_integration_instance" "aws_account" {
  cloud_provider = "AWS"
  scope          = "ACCOUNT"
  scan_mode      = "MANAGED"

  instance_name = "aws-production-account"

  manual_details = {
    account_id   = "123456789012"
    account_name = "production"

    # The role Cortex Cloud assumes, and the external ID that guards it.
    role_arn    = "arn:aws:iam::123456789012:role/CortexCloudAccess"
    external_id = "5f3c1d90-6a4e-4f2b-9c8d-1e7a2b3c4d5e"
  }

  additional_capabilities = {
    xsiam_analytics         = true
    agentless_disk_scanning = true
  }

  # "managed_by" is reserved by Cortex Cloud: it is accepted only with the
  # platform's own value, and onboarding is refused outright if you set it to
  # anything else. Use your own key instead.
  custom_resources_tags = [
    {
      key   = "provisioned_by"
      value = "terraform"
    }
  ]
}

# Onboard an AWS organization and collect CloudTrail audit logs.
#
# cloudtrail_role and sqs_url are accepted by the platform but never reported
# back, so Terraform cannot detect drift in them and "terraform import" cannot
# recover them. Keep your configuration as the source of truth for both.
resource "cortexcloud_cloud_manual_integration_instance" "aws_organization" {
  cloud_provider = "AWS"
  scope          = "ORGANIZATION"
  scan_mode      = "MANAGED"

  instance_name = "aws-organization"

  manual_details = {
    account_id      = "123456789012"
    account_name    = "management-account"
    organization_id = "o-a1b2c3d4e5"

    role_arn    = "arn:aws:iam::123456789012:role/CortexCloudAccess"
    external_id = "5f3c1d90-6a4e-4f2b-9c8d-1e7a2b3c4d5e"

    cloudtrail_role = "arn:aws:iam::123456789012:role/CortexCloudCloudTrail"
    sqs_url         = "https://sqs.us-east-1.amazonaws.com/123456789012/cortex-cloudtrail"
  }

  collection_configuration = {
    audit_logs = {
      enabled           = true
      data_events       = false
      collection_method = "CUSTOM"
    }
  }
}
