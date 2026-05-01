## Release Notes

### v1.0.4

#### Features
* **New Resource**: `cortexcloud_appsec_rule`
* **New Resource**: `cortexcloud_appsec_policy`
* **New Resource**: `cortexcloud_cloudsec_rule`
* **New Resource**: `cortexcloud_cloudsec_policy`
* **New Resource**: `cortexcloud_compliance_assessment_profile`
* **New Resource**: `cortexcloud_compliance_control`
* **New Resource**: `cortexcloud_compliance_standard`
* **New Resource**: `cortexcloud_cwp_policy`
* **New Resource**: `cortexcloud_notification_forwarding_config_agent_audit_logs`
* **New Resource**: `cortexcloud_notification_forwarding_config_mgmt_audit_logs`
* **New Resource**: `cortexcloud_notification_forwarding_config_cases`
* **New Resource**: `cortexcloud_notification_forwarding_config_issues`
* **New Resource**: `cortexcloud_vulnerability_policy`
* **New Data Source**: `cortexcloud_appsec_rule`
* **New Data Source**: `cortexcloud_appsec_rules`
* **New Data Source**: `cortexcloud_appsec_rule_labels`
* **New Data Source**: `cortexcloud_appsec_policy`
* **New Data Source**: `cortexcloud_appsec_policies`
* **New Data Source**: `cortexcloud_cloudsec_policy`
* **New Data Source**: `cortexcloud_cloudsec_rule`
* **New Data Source**: `cortexcloud_cloudsec_rules`
* **New Data Source**: `cortexcloud_compliance_assessment_profile`
* **New Data Source**: `cortexcloud_compliance_control`
* **New Data Source**: `cortexcloud_compliance_controls`
* **New Data Source**: `cortexcloud_compliance_standard`
* **New Data Source**: `cortexcloud_compliance_standards`
* **New Data Source**: `cortexcloud_cwp_policy`
* **New Data Source**: `cortexcloud_cwp_policies`
* **New Data Source**: `cortexcloud_vulnerability_policy`
* **New Data Source**: `cortexcloud_vulnerability_policies`

#### Enhancements
* Addressed missing attribute descriptions in various resource and data sources across all domains
* Added validation check against the `api_key_type` attribute in the provider configuration block.

#### Bug Fixes
* Fixed `cortexcloud_user_group` resource not accounting for users with effective membership via SSO/JIT authentication against one or more of the configured SAML groups. The `users` attribute now reflects only users that have been directly added to the group in the Terraform resource. See resource documentation page for more information.
* Changed attribute types for the `cortexcloud_user_group` resource's `idp_groups`, `nested_groups` and `users` attributes from List to Set to preserve ordering from the upstream API response.
* Fixed `outpost_id` not being honored on create or update for the `cortexcloud_cloud_integration_template_aws`, `cortexcloud_cloud_integration_template_azure`, and `cortexcloud_cloud_integration_template_gcp` resources. The configured outpost (or the platform-managed outpost used when the `scan_mode` attribute is set to `"MANAGED"`) is now correctly applied and refreshed on read.
* Fixed an incorrect attribute description on the `collector` field of the `cortexcloud_cloud_integration_instance` data source, which previously mirrored the `cloud_provider` description.

### v1.0.3

#### Breaking Changes
* The provider's `fqdn` configuration attribute and the `CORTEXCLOUD_FQDN` environment variable have been removed. Use `api_url` (or `CORTEXCLOUD_API_URL`) instead.

#### Enhancements
* Updated documentation for outpost resources and data sources with additional details and improved clarity.
* Correct reference to unreleased version in usage example in README
* Updated examples for asset group resource with working implementation and an additional example for static scope filters.
* Various minor updates to project documentation.

#### Bug Fixes
* Fixed sprawling attribute schema in asset group resource documentation and added patch step to prevent overwriting in future doc updates.


### v1.0.2

#### Features
* Initial GA release
