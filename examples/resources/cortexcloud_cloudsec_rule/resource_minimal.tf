# Minimal CloudSec detection rule with only required fields
resource "cortexcloud_cloudsec_rule" "ec2_public_ip_minimal" {
  name        = "AWS EC2 Instance with Public IP"
  description = "Detects EC2 instances that have a public IP address assigned"
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
}
