# CloudSec policy that applies specific rules to specific asset groups
# This example shows how to create a targeted policy for S3 security

# First, create the CloudSec rules.
# The XQL query must select from the "asset_inventory" dataset and its final
# "fields" stage must include an "asset_type_id" column (the API requires it).
# NOTE: rule "name" and policy "name" must be unique within your tenant. The
# API returns a 409 Conflict if a rule or policy with the same name already
# exists. Change the names below if they collide with existing objects.
resource "cortexcloud_cloudsec_rule" "s3_public_access" {
  name        = "Example - S3 bucket public access"
  description = "Detects S3 buckets with public access via ACL grants"
  class       = "config"
  asset_types = ["S3_BUCKET"]
  severity    = "high"

  query = {
    xql = "dataset = asset_inventory | filter xdm.asset.provider = \"aws\" and xdm.asset.type.id = \"S3_BUCKET\" | fields xdm.asset.id as asset_id, xdm.asset.type.id as asset_type_id, xdm.asset.name as asset_name"
  }
}

resource "cortexcloud_cloudsec_rule" "s3_encryption" {
  name        = "Example - S3 bucket encryption disabled"
  description = "Detects S3 buckets without server-side encryption configured"
  class       = "config"
  asset_types = ["S3_BUCKET"]
  severity    = "medium"

  query = {
    xql = "dataset = asset_inventory | filter xdm.asset.provider = \"aws\" and xdm.asset.type.id = \"S3_BUCKET\" | fields xdm.asset.id as asset_id, xdm.asset.type.id as asset_type_id, xdm.asset.name as asset_name"
  }
}

# Create an asset group for production S3 buckets.
# Use filterable asset fields such as "xdm.asset.type.id" and "xdm.asset.name".
# NOTE: depends_on serializes this create after the rules above. Creating many
# platform objects concurrently in a single apply can intermittently trip a
# backend 500; ordering the creates avoids that race.
resource "cortexcloud_asset_group" "production_s3" {
  name        = "production-s3-buckets"
  type        = "Dynamic"
  description = "Production S3 bucket assets"

  depends_on = [
    cortexcloud_cloudsec_rule.s3_public_access,
    cortexcloud_cloudsec_rule.s3_encryption,
  ]

  membership_predicate = {
    and = [
      {
        search_field = "xdm.asset.type.id"
        search_type  = "EQ"
        search_value = "S3_BUCKET"
      },
      {
        search_field = "xdm.asset.name"
        search_type  = "CONTAINS"
        search_value = "prod"
      }
    ]
  }
}

# Create a policy that applies specific S3 rules to production asset groups
resource "cortexcloud_cloudsec_policy" "s3_security_policy" {
  name        = "S3 Security Policy for Production"
  description = "Applies S3 security rules to production S3 buckets"

  # Match specific rules by their IDs. Order is not significant.
  rule_matching = {
    type = "RULES"
    rules = [
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
