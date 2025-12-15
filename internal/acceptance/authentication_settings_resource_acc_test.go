// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package acceptance

import (
	"context"
	"fmt"
	"strconv"
	"slices"
	"testing"

	"github.com/PaloAltoNetworks/cortex-cloud-go/log"
	"github.com/PaloAltoNetworks/cortex-cloud-go/platform"
	types "github.com/PaloAltoNetworks/cortex-cloud-go/types/platform"
	"github.com/hashicorp/terraform-plugin-log/tfsdklog"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

const (
	authSettingsSSOName                  string = "tf-provider-acctest-sso"
	authSettingsMetadataName             string = "tf-provider-acctest-metadata"
	authSettingsDomain                   string = "test.com"
	authSettingsDefaultRole              string = "Instance Administrator"
	authSettingsIsAccountRole            bool   = false
	authSettingsMappingsEmail                   = "email"
	authSettingsMappingsFirstName               = "firstName"
	authSettingsMappingsLastName                = "lastName"
	authSettingsMappingsGroupName               = "group"
	authSettingsIDPSSOURL                       = "https://test-paloaltonetworks.com/app/signin"
	authSettingsIDPCertificate                  = "TestIDPCertificate"
	authSettingsIDPIssuer                       = "https://www.test.com/a1b2c3d4e5f6g7h8i9j0"
	authSettingsMetadataURL                     = "https://cortex-test.okta.com/app/exkbuuzw77Bh04V6M6b8/sso/saml/metadata"
	authSettingsSSONameUpdated           string = "tf-provider-acctest-sso-updated"
	authSettingsMetadataNameUpdated      string = "tf-provider-acctest-metadata-updated"
	authSettingsDomainUpdated            string = "test1.com"
	authSettingsMappingsEmailUpdated            = "emailUpdated"
	authSettingsMappingsFirstNameUpdated        = "firstNameUpdated"
	authSettingsMappingsLastNameUpdated         = "lastNameUpdated"
	authSettingsMappingsGroupNameUpdated        = "groupUpdated"

	authSettingsResourceType             = "cortexcloud_authentication_settings"
	authSettingsIDPSSOResourceName       = "sso"
	authSettingsIDPSSOResourceConfigTmpl = `
resource "%s" "%s" {
  name   = "%s"
  domain = "%s"
  default_role = "%s"
  is_account_role = %t
  mappings = {
    email      = "%s"
    first_name = "%s"
    last_name  = "%s"
    group_name = "%s"
  }
  idp_sso_url = "%s"
  idp_certificate = "%s"
  idp_issuer = "%s"
}`
	authSettingsIDPMetadataResourceName       = "metadata"
	authSettingsIDPMetadataResourceConfigTmpl = `
resource "%s" "%s" {
  name   = "%s"
  domain = "%s"
  default_role = "%s"
  is_account_role = %t
  mappings = {
    email      = "%s"
    first_name = "%s"
    last_name  = "%s"
    group_name = "%s"
  }
  metadata_url = "%s"
}`
)

var (
	authSettingsIDPSSOResourceNameFull = fmt.Sprintf("%s.%s", authSettingsResourceType, authSettingsIDPSSOResourceName)
	authSettingsIDPSSOResourceConfig   = fmt.Sprintf(
		authSettingsIDPSSOResourceConfigTmpl,
		authSettingsResourceType,
		authSettingsIDPSSOResourceName,
		authSettingsSSOName,
		authSettingsDomain,
		authSettingsDefaultRole,
		authSettingsIsAccountRole,
		authSettingsMappingsEmail,
		authSettingsMappingsFirstName,
		authSettingsMappingsLastName,
		authSettingsMappingsGroupName,
		authSettingsIDPSSOURL,
		authSettingsIDPCertificate,
		authSettingsIDPIssuer,
	)
	authSettingsIDPSSOResourceUpdatedConfig = fmt.Sprintf(
		authSettingsIDPSSOResourceConfigTmpl,
		authSettingsResourceType,
		authSettingsIDPSSOResourceName,
		authSettingsSSONameUpdated,
		authSettingsDomainUpdated,
		authSettingsDefaultRole,
		authSettingsIsAccountRole,
		authSettingsMappingsEmailUpdated,
		authSettingsMappingsFirstNameUpdated,
		authSettingsMappingsLastNameUpdated,
		authSettingsMappingsGroupNameUpdated,
		authSettingsIDPSSOURL,
		authSettingsIDPCertificate,
		authSettingsIDPIssuer,
	)
	authSettingsIDPMetadataResourceNameFull = fmt.Sprintf("%s.%s", authSettingsResourceType, authSettingsIDPMetadataResourceName)
	authSettingsIDPMetadataResourceConfig   = fmt.Sprintf(
		authSettingsIDPMetadataResourceConfigTmpl,
		authSettingsResourceType,
		authSettingsIDPMetadataResourceName,
		authSettingsMetadataName,
		authSettingsDomain,
		authSettingsDefaultRole,
		authSettingsIsAccountRole,
		authSettingsMappingsEmail,
		authSettingsMappingsFirstName,
		authSettingsMappingsLastName,
		authSettingsMappingsGroupName,
		authSettingsMetadataURL,
	)
	authSettingsIDPMetadataResourceUpdatedConfig = fmt.Sprintf(
		authSettingsIDPMetadataResourceConfigTmpl,
		authSettingsResourceType,
		authSettingsIDPMetadataResourceName,
		authSettingsMetadataNameUpdated,
		authSettingsDomainUpdated,
		authSettingsDefaultRole,
		authSettingsIsAccountRole,
		authSettingsMappingsEmailUpdated,
		authSettingsMappingsFirstNameUpdated,
		authSettingsMappingsLastNameUpdated,
		authSettingsMappingsGroupNameUpdated,
		authSettingsMetadataURL,
	)
)

func TestAccAuthenticationSettingsResourceIDPSSO(t *testing.T) {
	providerConfig := getProviderConfig(t, dotEnvPath, true)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { 
			testAccPreCheck(t) 
			testAccAuthSettingsPreCheck(t) 
		},
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				PreConfig: func() {
					t.Log("Executing Create test step")
					//t.Logf("Using the following test config: \n\n%s\n", authSettingsIDPSSOResourceConfig)
				},
				Config: providerConfig + authSettingsIDPSSOResourceConfig,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(authSettingsIDPSSOResourceNameFull, "name", authSettingsSSOName),
					resource.TestCheckResourceAttr(authSettingsIDPSSOResourceNameFull, "domain", authSettingsDomain),
					resource.TestCheckResourceAttr(authSettingsIDPSSOResourceNameFull, "default_role", authSettingsDefaultRole),
					resource.TestCheckResourceAttr(authSettingsIDPSSOResourceNameFull, "is_account_role", strconv.FormatBool(authSettingsIsAccountRole)),
					resource.TestCheckResourceAttr(authSettingsIDPSSOResourceNameFull, "mappings.email", authSettingsMappingsEmail),
					resource.TestCheckResourceAttr(authSettingsIDPSSOResourceNameFull, "mappings.first_name", authSettingsMappingsFirstName),
					resource.TestCheckResourceAttr(authSettingsIDPSSOResourceNameFull, "mappings.last_name", authSettingsMappingsLastName),
					resource.TestCheckResourceAttr(authSettingsIDPSSOResourceNameFull, "mappings.group_name", authSettingsMappingsGroupName),
					resource.TestCheckResourceAttr(authSettingsIDPSSOResourceNameFull, "idp_sso_url", authSettingsIDPSSOURL),
					resource.TestCheckResourceAttr(authSettingsIDPSSOResourceNameFull, "idp_certificate", authSettingsIDPCertificate),
					resource.TestCheckResourceAttr(authSettingsIDPSSOResourceNameFull, "idp_issuer", authSettingsIDPIssuer),
					resource.TestCheckResourceAttr(authSettingsIDPSSOResourceNameFull, "metadata_url", ""),
				),
			},
			// Update and Read testing
			{
				PreConfig: func() {
					t.Log("Executing Update test step")
					//t.Logf("Using the following test config: \n\n%s\n", authSettingsIDPSSOResourceUpdatedConfig)
				},
				Config: providerConfig + authSettingsIDPSSOResourceUpdatedConfig,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(authSettingsIDPSSOResourceNameFull, "name", authSettingsSSONameUpdated),
					resource.TestCheckResourceAttr(authSettingsIDPSSOResourceNameFull, "domain", authSettingsDomainUpdated),
					resource.TestCheckResourceAttr(authSettingsIDPSSOResourceNameFull, "default_role", authSettingsDefaultRole),
					resource.TestCheckResourceAttr(authSettingsIDPSSOResourceNameFull, "is_account_role", strconv.FormatBool(authSettingsIsAccountRole)),
					resource.TestCheckResourceAttr(authSettingsIDPSSOResourceNameFull, "mappings.email", authSettingsMappingsEmailUpdated),
					resource.TestCheckResourceAttr(authSettingsIDPSSOResourceNameFull, "mappings.first_name", authSettingsMappingsFirstNameUpdated),
					resource.TestCheckResourceAttr(authSettingsIDPSSOResourceNameFull, "mappings.last_name", authSettingsMappingsLastNameUpdated),
					resource.TestCheckResourceAttr(authSettingsIDPSSOResourceNameFull, "mappings.group_name", authSettingsMappingsGroupNameUpdated),
					resource.TestCheckResourceAttr(authSettingsIDPSSOResourceNameFull, "idp_sso_url", authSettingsIDPSSOURL),
					resource.TestCheckResourceAttr(authSettingsIDPSSOResourceNameFull, "idp_certificate", authSettingsIDPCertificate),
					resource.TestCheckResourceAttr(authSettingsIDPSSOResourceNameFull, "idp_issuer", authSettingsIDPIssuer),
					resource.TestCheckResourceAttr(authSettingsIDPSSOResourceNameFull, "metadata_url", ""),
				),
			},
			// Delete and Read testing
			{
				PreConfig: func() {
					t.Log("Executing Delete test step")
				},
				Config: providerConfig,
			},
		},
		CheckDestroy: testAccCheckAuthSettingsDestroy,
	})
}

func TestAccAuthenticationSettingsResourceIDPMetadata(t *testing.T) {
	providerConfig := getProviderConfig(t, dotEnvPath, true)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { 
			testAccPreCheck(t) 
			testAccAuthSettingsPreCheck(t) 
		},
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				PreConfig: func() {
					t.Log("Executing Create test step")
					//t.Logf("Using the following test config: \n\n%s\n", providerConfig+resourceConfigCreate)
				},
				Config: providerConfig + authSettingsIDPMetadataResourceConfig,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(authSettingsIDPMetadataResourceNameFull, "name", authSettingsMetadataName),
					resource.TestCheckResourceAttr(authSettingsIDPMetadataResourceNameFull, "domain", authSettingsDomain),
					resource.TestCheckResourceAttr(authSettingsIDPMetadataResourceNameFull, "default_role", authSettingsDefaultRole),
					resource.TestCheckResourceAttr(authSettingsIDPMetadataResourceNameFull, "is_account_role", strconv.FormatBool(authSettingsIsAccountRole)),
					resource.TestCheckResourceAttr(authSettingsIDPMetadataResourceNameFull, "mappings.email", authSettingsMappingsEmail),
					resource.TestCheckResourceAttr(authSettingsIDPMetadataResourceNameFull, "mappings.first_name", authSettingsMappingsFirstName),
					resource.TestCheckResourceAttr(authSettingsIDPMetadataResourceNameFull, "mappings.last_name", authSettingsMappingsLastName),
					resource.TestCheckResourceAttr(authSettingsIDPMetadataResourceNameFull, "mappings.group_name", authSettingsMappingsGroupName),
					resource.TestCheckResourceAttr(authSettingsIDPMetadataResourceNameFull, "idp_sso_url", ""),
					resource.TestCheckResourceAttr(authSettingsIDPMetadataResourceNameFull, "idp_certificate", ""),
					resource.TestCheckResourceAttr(authSettingsIDPMetadataResourceNameFull, "idp_issuer", ""),
					resource.TestCheckResourceAttr(authSettingsIDPMetadataResourceNameFull, "metadata_url", authSettingsMetadataURL),
				),
			},
			// Update and Read testing
			{
				PreConfig: func() {
					t.Log("Executing Update test step")
				},
				Config: providerConfig + authSettingsIDPMetadataResourceUpdatedConfig,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(authSettingsIDPMetadataResourceNameFull, "name", authSettingsMetadataNameUpdated),
					resource.TestCheckResourceAttr(authSettingsIDPMetadataResourceNameFull, "domain", authSettingsDomainUpdated),
					resource.TestCheckResourceAttr(authSettingsIDPMetadataResourceNameFull, "default_role", authSettingsDefaultRole),
					resource.TestCheckResourceAttr(authSettingsIDPMetadataResourceNameFull, "is_account_role", strconv.FormatBool(authSettingsIsAccountRole)),
					resource.TestCheckResourceAttr(authSettingsIDPMetadataResourceNameFull, "mappings.email", authSettingsMappingsEmailUpdated),
					resource.TestCheckResourceAttr(authSettingsIDPMetadataResourceNameFull, "mappings.first_name", authSettingsMappingsFirstNameUpdated),
					resource.TestCheckResourceAttr(authSettingsIDPMetadataResourceNameFull, "mappings.last_name", authSettingsMappingsLastNameUpdated),
					resource.TestCheckResourceAttr(authSettingsIDPMetadataResourceNameFull, "mappings.group_name", authSettingsMappingsGroupNameUpdated),
					resource.TestCheckResourceAttr(authSettingsIDPMetadataResourceNameFull, "idp_sso_url", ""),
					resource.TestCheckResourceAttr(authSettingsIDPMetadataResourceNameFull, "idp_certificate", ""),
					resource.TestCheckResourceAttr(authSettingsIDPMetadataResourceNameFull, "idp_issuer", ""),
					resource.TestCheckResourceAttr(authSettingsIDPMetadataResourceNameFull, "metadata_url", authSettingsMetadataURL),
				),
			},
			// Delete and Read testing
			{
				PreConfig: func() {
					t.Log("Executing Delete test step")
				},
				Config: providerConfig,
			},
		},
		CheckDestroy: testAccCheckAuthSettingsDestroy,
	})
}

// testAccAuthSettingsPreCheck checks if there's at least 1
// authentication settings configuration in the tenant that
// has no domain, and gracefully fails the test if not. This
// default configuration is a necessary pre-condition for adding
// additional configurations.
func testAccAuthSettingsPreCheck(t *testing.T) error {
	ctx := context.Background()
	tfsdklog.Debug(ctx, "Confirming resource destruction")

	platformClient, err := platform.NewClient(
		platform.WithCortexAPIURL(testAPIURL),
		platform.WithCortexAPIKey(testAPIKey),
		platform.WithCortexAPIKeyID(testAPIKeyID),
		platform.WithCortexAPIKeyType("standard"),
		platform.WithLogger(log.TflogAdapter{}),
		platform.WithLogLevel("debug"),
	)

	if err != nil {
		return fmt.Errorf("error creating SDK client for pre-condition check: %s", err.Error())
	}

	authSettings, err := platformClient.ListAuthSettings(ctx)
	if err != nil {
		return fmt.Errorf("error listing authentication settings for pre-condition check: %s", err.Error())
	}

	hasSettingsWithNoDomain := slices.ContainsFunc(authSettings, func(settings types.AuthSettings) bool {
		return settings.Domain == ""
	})

	if len(authSettings) < 1 || !hasSettingsWithNoDomain {
		return fmt.Errorf("no default authentication settings configuration exists, need at least one configuration with an empty domain")
	}

	return nil
}

func testAccCheckAuthSettingsDestroy(s *terraform.State) error {
	ctx := context.Background()
	tfsdklog.Debug(ctx, "Confirming resource destruction")

	platformClient, err := platform.NewClient(
		platform.WithCortexAPIURL(testAPIURL),
		platform.WithCortexAPIKey(testAPIKey),
		platform.WithCortexAPIKeyID(testAPIKeyID),
		platform.WithCortexAPIKeyType("standard"),
		platform.WithLogger(log.TflogAdapter{}),
		platform.WithLogLevel("debug"),
	)

	if err != nil {
		return fmt.Errorf("error creating SDK client for destruction check: %s", err.Error())
	}

	for _, rs := range s.RootModule().Resources {
		if rs.Type != authSettingsResourceType {
			continue
		}

		authSettings, err := platformClient.ListAuthSettings(ctx)
		if err != nil {
			return fmt.Errorf("error listing authentication settings for destruction check: %s", err.Error())
		}

		if len(authSettings) > 1 {
			return fmt.Errorf("Authentication settings still exist")
		}
	}

	return nil
}
