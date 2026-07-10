# Basic SAML authentication settings configuration
#
# PREREQUISITE: Applying this resource configures SAML SSO on your tenant.
# The Cortex Cloud backend validates and processes the SAML configuration
# against your Identity Provider (IdP). If the tenant is not set up for SAML
# (or the IdP metadata/certificate does not match a reachable, configured
# IdP), the public API may return an HTTP 500 while processing the request.
# Ensure your IdP is provisioned and that the idp_issuer, idp_sso_url, and
# idp_certificate values below correspond to that IdP before applying.
resource "cortexcloud_authentication_settings" "example" {
  name   = "corporate-sso"
  domain = "example.com"

  # SAML attribute mappings (assignment syntax for the nested attribute)
  mappings = {
    email      = "emailaddress"
    first_name = "givenname"
    last_name  = "surname"
    group_name = "groups"
  }

  # IdP configuration
  idp_issuer  = "https://idp.example.com"
  idp_sso_url = "https://idp.example.com/sso"

  # The IdP's X.509 signing certificate in PEM format. Replace the value below
  # with your IdP certificate. You can also load it from a file on disk with
  # idp_certificate = file("${path.module}/idp-certificate.pem").
  idp_certificate = <<-EOT
    -----BEGIN CERTIFICATE-----
    MIIDExampleCertificateReplaceWithYourIdPSigningCertificateValue==
    -----END CERTIFICATE-----
  EOT

  # Default role for authenticated users
  default_role = "viewer"
}
