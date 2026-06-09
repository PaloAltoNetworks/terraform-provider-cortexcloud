# CloudSec detection rule with built-in compliance controls
resource "cortexcloud_cloudsec_rule" "s3_encryption_compliance" {
  name        = "AWS S3 Bucket Encryption Not Enabled"
  description = "Identifies S3 buckets that do not have server-side encryption enabled, which may violate compliance requirements"
  class       = "config"
  asset_types = ["aws-s3-bucket"]
  severity    = "medium"

  # XQL query to detect unencrypted S3 buckets
  query = {
    xql = "config from cloud.resource where cloud.type = 'aws' AND api.name = 'aws-s3api-get-bucket-encryption' AND json.rule = serverSideEncryptionConfiguration does not exist"
  }

  # Detailed remediation guidance
  metadata = {
    issue = {
      recommendation = <<-EOT
        To enable encryption on the S3 bucket:
        
        AWS Console:
        1. Navigate to the S3 bucket in AWS Console
        2. Go to the Properties tab
        3. Scroll to "Default encryption"
        4. Click "Edit"
        5. Select either SSE-S3 or SSE-KMS encryption
        6. Save changes
        
        AWS CLI:
        aws s3api put-bucket-encryption \
          --bucket <bucket-name> \
          --server-side-encryption-configuration '{
            "Rules": [{
              "ApplyServerSideEncryptionByDefault": {
                "SSEAlgorithm": "AES256"
              }
            }]
          }'
        
        Terraform:
        resource "aws_s3_bucket_server_side_encryption_configuration" "example" {
          bucket = aws_s3_bucket.example.id
          rule {
            apply_server_side_encryption_by_default {
              sse_algorithm = "AES256"
            }
          }
        }
      EOT
    }
  }

  # Map to built-in compliance standards and controls
  compliance_metadata = [
    {
      control_id = "CIS-AWS-2.1.5"
      # The following fields are automatically populated by the API:
      # standard_id, standard_name, control_name
    },
    {
      control_id = "NIST-800-53-SC-28"
    },
    {
      control_id = "PCI-DSS-3.4"
    },
    {
      control_id = "HIPAA-164.312(a)(2)(iv)"
    }
  ]

  # Custom labels for organization
  labels = ["S3", "Encryption", "Compliance", "Data Protection"]

  # Enable the rule
  enabled = true
}

# CloudSec detection rule with a CUSTOM compliance control
#
# IMPORTANT: Custom controls must be associated with a compliance standard
# before they can be referenced in compliance_metadata. The correct workflow is:
#   1. Create the custom control
#   2. Create a standard and associate the control with it
#   3. Create the rule referencing the custom control
#
# Without step 2, the CloudSec API will reject the control ID with:
#   "Invalid Control ID provided for Compliance Metadata"

# Step 1: Create a custom compliance control
resource "cortexcloud_compliance_control" "custom_encryption" {
  name        = "Custom S3 Encryption Control"
  category    = "Data Protection"
  subcategory = "Encryption at Rest"
  description = "Ensure all S3 buckets have server-side encryption enabled"
}

# Step 2: Create a custom standard and associate the control
resource "cortexcloud_compliance_standard" "custom_standard" {
  name         = "Custom Cloud Security Standard"
  controls_ids = [cortexcloud_compliance_control.custom_encryption.id]
}

# Step 3: Create the rule with the custom control in compliance_metadata
resource "cortexcloud_cloudsec_rule" "s3_encryption_custom" {
  name        = "Custom S3 Encryption Check"
  description = "Custom rule with custom compliance control"
  class       = "config"
  asset_types = ["aws-s3-bucket"]
  severity    = "high"

  query = {
    xql = "config from cloud.resource where cloud.type = 'aws' AND api.name = 'aws-s3api-get-bucket-encryption' AND json.rule = serverSideEncryptionConfiguration does not exist"
  }

  compliance_metadata = [
    {
      control_id = cortexcloud_compliance_control.custom_encryption.id
    }
  ]

  # Ensure the standard is created (with the control associated) before the rule
  depends_on = [cortexcloud_compliance_standard.custom_standard]
}