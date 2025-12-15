# Basic SAML authentication settings configuration
resource "cortexcloud_authentication_settings" "example" {
  name   = "corporate-sso"
  domain = "example.com"

  # SAML attribute mappings
  mappings {
    email      = "emailaddress"
    first_name = "givenname"
    last_name  = "surname"
    group_name = "groups"
  }

  # IdP configuration
  idp_issuer      = "https://idp.example.com"
  idp_sso_url     = "https://idp.example.com/sso"
  idp_certificate = file("${path.module}/idp-certificate.pem")

  # Default role for authenticated users
  default_role = "viewer"
}