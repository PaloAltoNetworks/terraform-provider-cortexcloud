# Basic CloudSec detection rule for identifying S3 buckets with public access
resource "cortexcloud_cloudsec_rule" "s3_public_access" {
  name        = "AWS S3 Bucket with Public Access"
  description = "Identifies S3 buckets that allow public access through ACLs or bucket policies"
  class       = "config"
  asset_types = ["aws-s3-bucket"]
  severity    = "high"

  # XQL query to detect public S3 buckets
  query = {
    xql = "config from cloud.resource where cloud.type = 'aws' AND api.name = 'aws-s3api-get-bucket-acl' AND json.rule = acl.grants[?(@.grantee=='AllUsers' || @.grantee=='AuthenticatedUsers')] exists"
  }

  # Remediation guidance
  metadata = {
    issue = {
      recommendation = <<-EOT
        To remediate this issue:
        1. Navigate to the S3 bucket in AWS Console
        2. Go to the Permissions tab
        3. Review and remove any public access grants from the ACL
        4. Ensure "Block all public access" is enabled
        5. Review bucket policies to ensure they don't grant public access
      EOT
    }
  }

  # Custom labels for categorization
  labels = ["S3", "Public Access", "Data Exposure"]

  # Enable the rule
  enabled = true
}