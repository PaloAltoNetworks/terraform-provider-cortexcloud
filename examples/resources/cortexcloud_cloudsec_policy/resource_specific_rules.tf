# CloudSec policy that applies specific rules to specific asset groups
# This example shows how to create a targeted policy for S3 security

# First, create the CloudSec rules
resource "cortexcloud_cloudsec_rule" "s3_public_access" {
  name        = "S3 Bucket Public Access"
  class       = "config"
  asset_types = ["aws-s3-bucket"]
  severity    = "high"

  query = {
    xql = "config from cloud.resource where cloud.type = 'aws' AND api.name = 'aws-s3api-get-bucket-acl' AND json.rule = acl.grants[?(@.grantee=='AllUsers')] exists"
  }
}

resource "cortexcloud_cloudsec_rule" "s3_encryption" {
  name        = "S3 Bucket Encryption Disabled"
  class       = "config"
  asset_types = ["aws-s3-bucket"]
  severity    = "medium"

  query = {
    xql = "config from cloud.resource where cloud.type = 'aws' AND api.name = 'aws-s3api-get-bucket-encryption' AND json.rule = serverSideEncryptionConfiguration does not exist"
  }
}

# Create an asset group for production S3 buckets
resource "cortexcloud_asset_group" "production_s3" {
  name        = "production-s3-buckets"
  type        = "ASSET"
  description = "Production S3 bucket assets"

  membership_predicate = {
    and = [
      {
        search_field = "asset.type"
        search_type  = "EQUALS"
        search_value = "aws-s3-bucket"
      },
      {
        search_field = "asset.tags.environment"
        search_type  = "EQUALS"
        search_value = "production"
      }
    ]
  }
}

# Create a policy that applies specific S3 rules to production asset groups
resource "cortexcloud_cloudsec_policy" "s3_security_policy" {
  name        = "S3 Security Policy for Production"
  description = "Applies S3 security rules to production S3 buckets"

  # Match specific rules by their IDs
  rule_matching = {
    type = "RULES"
    rule_ids = [
      cortexcloud_cloudsec_rule.s3_public_access.id,
      cortexcloud_cloudsec_rule.s3_encryption.id,
    ]
  }

  # Apply to specific asset groups
  asset_matching = {
    type            = "ASSET_GROUPS"
    asset_group_ids = [cortexcloud_asset_group.production_s3.id]
  }

  # Custom labels
  labels = ["S3", "Production", "Security"]

  # Enable the policy
  enabled = true
}