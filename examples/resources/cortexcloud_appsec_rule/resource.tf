# Custom AppSec rule for Terraform
resource "cortexcloud_appsec_rule" "custom_iac_rule" {
  name         = "Custom Terraform Security Rule"
  severity     = "CRITICAL"
  scanner      = "IAC"
  category     = "NETWORKING"
  sub_category = "INGRESS_CONTROLS"
  description  = "Detect insecure ingress configurations in Terraform"

  frameworks {
    name = "TERRAFORM"
    # The definition is a Checkov custom-policy YAML document, not raw HCL.
    # This policy flags aws_security_group resources that allow ingress from
    # 0.0.0.0/0.
    definition = <<-EOT
      scope:
        provider: "aws"
      definition:
        cond_type: "attribute"
        resource_types:
          - "aws_security_group"
        attribute: "ingress.cidr_blocks"
        operator: "not_contains"
        value: "0.0.0.0/0"
    EOT
    definition_link         = "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group"
    remediation_description = "Restrict ingress to specific IP ranges"
  }

  labels = ["networking", "aws"]
}

# Custom AppSec rule mapped to a Cloud Security (CSPM) rule.
# Use `cspm_rule_id` to associate a custom Application Security rule with an
# existing CSPM rule so findings are correlated across both engines.
resource "cortexcloud_appsec_rule" "cspm_mapped_rule" {
  name         = "S3 Bucket Public Access Check"
  severity     = "HIGH"
  scanner      = "IAC"
  category     = "PUBLIC"
  sub_category = "STORAGE_BUCKETS"
  description  = "Detects S3 buckets with public access enabled"

  # Map this custom AppSec rule to a Cloud Security (CSPM) rule by its ID.
  # cspm_rule_id is write-only: the API accepts it on create/update but does not
  # return it on read, so the configured value is preserved in state.
  cspm_rule_id = "ff6a26a5-f036-4d3a-a650-d5de1d568bab"

  frameworks {
    name = "TERRAFORM"
    definition = <<-EOT
      definition:
        cond_type: attribute
        resource_types:
          - aws_s3_bucket_public_access_block
        attribute: block_public_acls
        operator: equals
        value: false
    EOT
    remediation_description = "Set block_public_acls to true in aws_s3_bucket_public_access_block resource"
  }

  labels = ["Custom-Rule", "S3-Security"]
}
