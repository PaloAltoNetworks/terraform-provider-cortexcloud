# Authentication settings are imported using the SSO integration name and its
# email domain, separated by a comma: "<name>,<domain>".
terraform import cortexcloud_authentication_settings.example "corporate-sso,example.com"

# The default SSO integration has an empty domain; keep the trailing comma.
terraform import cortexcloud_authentication_settings.default "default-sso,"

# Names may contain commas; the last comma is always treated as the separator.
terraform import cortexcloud_authentication_settings.acme "Acme, Inc SSO,acme.com"
