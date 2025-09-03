// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package acceptance

const (
	AccTestAuthSettings1Name              string = "tf-provider-acc-test-auth-settings"
	AccTestAuthSettings1Domain            string = "test.com"
	AccTestAuthSettings1DefaultRole       string = "Instance Administrator"
	AccTestAuthSettings1IsAccountRole     bool   = false
	AccTestAuthSettings1MappingsEmail            = "email"
	AccTestAuthSettings1MappingsFirstName        = "firstName"
	AccTestAuthSettings1MappingsLastName         = "lastName"
	AccTestAuthSettings1MappingsGroupName        = "group"
	AccTestAuthSettings1IdpSsoUrl                = "https://paloaltonetworks.com/app/signin"
	AccTestAuthSettings1IdpCertificate           = "MIIDuzCCAqOgAwIBAgIUQs1LRebZYRe1emleU6a8mBHxRJwwDQYJKoZIhvcNAQELBQAwbTELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkFSMRQwEgYDVQQHDAtMaXR0bGUgUm9jazEbMBkGA1UECgwSUGFsbyBBbHRvIE5ldHdvcmtzMR4wHAYDVQQLDBVQcm9mZXNzaW9uYWwgU2VydmljZXMwHhcNMjUwODIxMTYxNzI4WhcNMjYwODIxMTYxNzI4WjBtMQswCQYDVQQGEwJVUzELMAkGA1UECAwCQVIxFDASBgNVBAcMC0xpdHRsZSBSb2NrMRswGQYDVQQKDBJQYWxvIEFsdG8gTmV0d29ya3MxHjAcBgNVBAsMFVByb2Zlc3Npb25hbCBTZXJ2aWNlczCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKvLWHO1gwgMv5thWY3XR5+NCIuYZFxFHi1mva8w1e0b0A1nwwqO+eowzzxsEBcSIKf7rBkezDYrRJqnEuCqDKOI/jV/HAKU1h/ZJW3qgRFogO7eEmhPvvSOWXkExJmJ8ic7jS48pAbG9+dg9fZtAN6waMeB93mHAS0aY4sPuuyCbl8uyc0ovXJ2nqHTdB1Ff4W4wLtKJJsoK9N8E+Pz0YAI5dp2Ir2fgoERKDU9JjN5dwMGraQNa3LJCMpQj+1vrkBrL0bLfKI8daRk6MicYDTVnuBo/YDBRu+aLXftBpw7hyvmMivgwktDJDziBhmPoRv29A1bTOsxVEUt6w59QP8CAwEAAaNTMFEwHQYDVR0OBBYEFK3rXPMkuBe+hDNW3B4eYbnawCMAMB8GA1UdIwQYMBaAFK3rXPMkuBe+hDNW3B4eYbnawCMAMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAAJaB3Q3DvEu3LwPHFNCRnHwN8fAcGP1ItPB1G7f/EqBhzIOU0ZaxvqLnECPesy8LQqoHX8vdcAv6n1U+zPZp2zCSVVPd+sbZECqBhs9VsI2WF6LlkLvKDti0PESgkj1+K54xFDMiK56YmIUBP0rpOxL+MT+fzJCiG4H86uvc/jtMGVS96mWbl32Cf9MFhONhwDaxXDVhycWv197unvfIjrpMCOOxQCWGsU2MHGgidrtApHU9sufROCbjrm6wnuV0ndbHWUkK+oWmExIY/5h4qv7kQgme9tRkoKD3zyV8oqPt9NRzHTBR/5QDoaC/tvwb52Ohp+zKH/iD3CNrLPY5LQ="
	AccTestAuthSettings1IdpIssuer                = "https://www.test.com/a1b2c3d4e5f6g7h8i9j0"
	AccTestAuthSettings1MetadataUrl              = ""

	AccTestAuthSettings1NameUpdated   string = "tf-provider-acc-test-auth-settings-updated"
	AccTestAuthSettings1DomainUpdated string = "test1.com"

	AccTestAuthSettings1ConfigTmpl = `resource "cortexcloud_authentication_settings" "test" {
  name   = %s
  domain = %s
  default_role = %s
  is_account_role = %t
  mappings = {
    email      = %s
    first_name = %s
    last_name  = %s
    group_name = %s
  }
  idp_sso_url = %s
  idp_certificate = %s
  idp_issuer = %s
  metadata_url = %s
}`
)
