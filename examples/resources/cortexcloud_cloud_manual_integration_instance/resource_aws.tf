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
#
# additional_capabilities, collection_configuration and scope_modifications are
# all required, because the API contract marks them required. Stating them
# explicitly is what keeps the connector's configuration the one you wrote:
# nothing is filled in on your behalf.
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

    # Required. Set it to true only alongside registry_scanning_options:
    # the platform refuses either one without the other.
    registry_scanning = false
  }

  collection_configuration = {
    audit_logs = {
      # This connector does not collect audit logs. The three members are
      # required even when collection is off, so the configuration says so
      # rather than leaving it to be inferred.
      enabled           = false
      data_events       = false
      collection_method = "CUSTOM"
    }
  }

  scope_modifications = {
    # Leave every region in scope. Set enabled = true and list regions to
    # restrict the connector to a subset.
    regions = {
      enabled = false
    }
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
#
# An ORGANIZATION-scoped connector must also declare the account-level scope
# bucket -- accounts for AWS, subscriptions for Azure, projects for GCP.
# Without it the platform refuses the request with "Incorrect Scope
# modifications detail provided for scoped connector".
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

  additional_capabilities = {
    registry_scanning = false
  }

  collection_configuration = {
    audit_logs = {
      enabled           = true
      data_events       = false
      collection_method = "CUSTOM"
    }
  }

  # Restrict this connector to two regions. Omit type and regions, and set
  # enabled = false, to leave every region in scope.
  scope_modifications = {
    regions = {
      enabled = true
      type    = "INCLUDE"
      regions = ["us-east-1", "us-west-2"]
    }

    # Required for an ORGANIZATION-scoped AWS connector. enabled = false
    # onboards every account in the organization; set enabled = true with a
    # type and account_ids to narrow it.
    accounts = {
      enabled = false
    }
  }
}
