# Minimal CloudSec detection rule with only required fields
resource "cortexcloud_cloudsec_rule" "ec2_public_ip_minimal" {
  name        = "AWS EC2 Instance with Public IP"
  class       = "config"
  asset_types = ["aws-ec2-instance"]
  severity    = "low"

  query = {
    xql = "config from cloud.resource where cloud.type = 'aws' AND api.name = 'aws-ec2-describe-instances' AND json.rule = publicIpAddress exists"
  }
}