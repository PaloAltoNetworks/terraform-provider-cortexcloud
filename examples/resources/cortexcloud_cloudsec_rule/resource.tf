# Cloud Security rule for detecting S3 buckets with access logging disabled.
# NOTE: "name" must be unique within your tenant, including across the built-in
# Cortex detection rules. The API rejects a create request with a 409 Conflict
# ("a detection rule with the same name already exists") if the name is already
# in use. The name below is deliberately example-scoped to avoid colliding with
# a built-in rule; change it to suit your environment.
resource "cortexcloud_cloudsec_rule" "aws-s3-access-logging-disabled" {
  name        = "Example - S3 access logging disabled"
  description = <<-EOF
Overly permissive key policies on AWS S3 buckets encrypted with Customer Managed Keys (CMKs) allow unauthorized access to sensitive data, leading to data breaches and compliance violations.

AWS S3 utilizes Customer Managed Keys (CMKs) for encryption, stored and managed within AWS Key Management Service (KMS). A misconfigured KMS key policy granting excessive permissions to untrusted principals, exposes the encryption key. Attackers exploiting this misconfiguration can decrypt and access sensitive data stored in the S3 bucket.

The impact of this misconfiguration includes data breaches, financial losses, reputational damage, and regulatory penalties for non-compliance. Restricting permissions to only necessary principals minimizes the potential impact of a compromised key. Following the principle of least privilege ensures only authorized entities can access the encryption key.

Mitigate this risk by implementing least privilege access controls on the KMS key policy. Grant required permissions only to trusted entities and services requiring access. Regularly review and audit the KMS key policy to identify and remove unnecessary permissions. Use a strong, unique CMK for each S3 bucket, and avoid using wildcard characters in the KMS key policy.
EOF
  class       = "config"
  asset_types = ["S3_BUCKET"]
  severity    = "high"
  query = {
    xql = <<-EOF
dataset = asset_inventory
| filter xdm.asset.provider = "aws" and xdm.asset.type.id = "S3_BUCKET"
| alter LoggingConfiguration = json_extract(xdm.asset.raw_fields, "$.Platform Discovery.Properties.LoggingConfiguration")
| alter targetBucket = json_extract_scalar(xdm.asset.raw_fields, "$.Platform Discovery.Properties.LoggingConfiguration.TargetBucket")
| alter targetPrefix = json_extract_scalar(xdm.asset.raw_fields, "$.Platform Discovery.Properties.LoggingConfiguration.TargetPrefix")
| filter (LoggingConfiguration = null or targetBucket = null or targetPrefix = null)
| fields xdm.asset.id as asset_id, xdm.asset.type.id as asset_type_id, xdm.asset.name as asset_name
EOF
  }
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
  labels  = ["S3", "Public Access", "Data Exposure"]
  enabled = true
}

