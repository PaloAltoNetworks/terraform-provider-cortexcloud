# Custom AppSec rule for Terraform
resource "cortexcloud_appsec_rule" "custom_iac_rule" {
  name         = "Custom Terraform Security Rule"
  severity     = "CRITICAL"
  scanner      = "IAC"
  category     = "NETWORKING"
  sub_category = "INGRESS_CONTROLS"
  description  = "Detect insecure ingress configurations in Terraform"

  frameworks {
    name                    = "TERRAFORM"
    definition              = "resource \"aws_security_group\" \"example\" { ingress { cidr_blocks = [\"0.0.0.0/0\"] } }"
    definition_link         = "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group"
    remediation_description = "Restrict ingress to specific IP ranges"
  }

  labels = ["production", "networking", "aws"]
}