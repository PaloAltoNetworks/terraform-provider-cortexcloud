# WARNING: Custom compliance controls, standards and rules MUST be created
# in the order defined by the Cortex platform's ORM model. Namely, compliance
# controls must be associated with a compliance standard before they can be 
# attached to detection rules.
#
# To ensure that the full resource stack is created successfully, configure your
# Terraform module to declare the resources in the following order:
#
#   1. Controls
#   2. Standards (referencing IDs for relevant compliance controls)
#   3. Rules (referencing IDs to relevant compliance controls)
#
# The example below demonstrates the correct order of resource creation and
# associations.
#
# Attempting to create these resources in any other order will raise errors in 
# the upstream Cortex API and halt the entire Terraform operation.

# Step 1: Create a new compliance control
resource "cortexcloud_compliance_control" "data-protection-s3-encryption" {
  name        = "S3 Encryption Control"
  category    = "Data Protection"
  subcategory = "1.1"
  description = "Ensure all S3 buckets have server-side encryption enabled"
}

# Step 2: Create a new compliance standard with the control from step 1
resource "cortexcloud_compliance_standard" "critical-security-controls" {
  name = "Organization XYZ Critical Security Controls"
  controls_ids = [
    cortexcloud_compliance_control.data-protection-s3-encryption.id
  ]
}

# Step 3: Create a new detection rule associated with the standard from step 2
resource "cortexcloud_cloudsec_rule" "aws-s3-access-logging-disabled" {
  depends_on  = [cortexcloud_compliance_standard.critical-security-controls]
  name        = "AWS Access logging not enabled on S3 buckets"
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
  compliance_metadata = [
    {
      control_id = cortexcloud_compliance_control.data-protection-s3-encryption.id
    }
  ]
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
  labels  = ["S3", "Encryption", "Compliance", "Data Protection"]
  enabled = true
}

