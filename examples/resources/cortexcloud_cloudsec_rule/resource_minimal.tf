# Minimal CloudSec detection rule with only required fields
resource "cortexcloud_cloudsec_rule" "s3_logging_disabled_minimal" {
  name        = "AWS S3 Bucket without Access Logging"
  description = "Detects S3 buckets that do not have server access logging enabled"
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
