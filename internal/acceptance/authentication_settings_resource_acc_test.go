// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package acceptance

import (
	"fmt"
	"strconv"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccAuthenticationSettingsResource(t *testing.T) {
	t.Log("Creating test configurations")

	resourceName := "cortexcloud_authentication_settings.test"
	resourceConfigCreate := fmt.Sprintf(
		AccTestAuthSettings1ConfigTmpl,
		strconv.Quote(AccTestAuthSettings1Name),
		strconv.Quote(AccTestAuthSettings1Domain),
		strconv.Quote(AccTestAuthSettings1DefaultRole),
		AccTestAuthSettings1IsAccountRole,
		strconv.Quote(AccTestAuthSettings1MappingsEmail),
		strconv.Quote(AccTestAuthSettings1MappingsFirstName),
		strconv.Quote(AccTestAuthSettings1MappingsLastName),
		strconv.Quote(AccTestAuthSettings1MappingsGroupName),
		strconv.Quote(AccTestAuthSettings1IdpSsoUrl),
		strconv.Quote(AccTestAuthSettings1IdpCertificate),
		strconv.Quote(AccTestAuthSettings1IdpIssuer),
		strconv.Quote(AccTestAuthSettings1MetadataUrl),
	)
	resourceConfigUpdate := fmt.Sprintf(
		AccTestAuthSettings1ConfigTmpl,
		strconv.Quote(AccTestAuthSettings1NameUpdated),
		strconv.Quote(AccTestAuthSettings1DomainUpdated),
		strconv.Quote(AccTestAuthSettings1DefaultRole),
		AccTestAuthSettings1IsAccountRole,
		strconv.Quote(AccTestAuthSettings1MappingsEmail),
		strconv.Quote(AccTestAuthSettings1MappingsFirstName),
		strconv.Quote(AccTestAuthSettings1MappingsLastName),
		strconv.Quote(AccTestAuthSettings1MappingsGroupName),
		strconv.Quote(AccTestAuthSettings1IdpSsoUrl),
		strconv.Quote(AccTestAuthSettings1IdpCertificate),
		strconv.Quote(AccTestAuthSettings1IdpIssuer),
		strconv.Quote(AccTestAuthSettings1MetadataUrl),
	)

	t.Log("Running tests")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				Config: resourceConfigCreate,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", AccTestAuthSettings1Name),
					resource.TestCheckResourceAttr(resourceName, "domain", AccTestAuthSettings1Domain),
					resource.TestCheckResourceAttr(resourceName, "default_role", AccTestAuthSettings1DefaultRole),
					resource.TestCheckResourceAttr(resourceName, "mappings.email", AccTestAuthSettings1MappingsEmail),
					resource.TestCheckResourceAttr(resourceName, "mappings.first_name", AccTestAuthSettings1MappingsFirstName),
					resource.TestCheckResourceAttr(resourceName, "mappings.last_name", AccTestAuthSettings1MappingsLastName),
					resource.TestCheckResourceAttr(resourceName, "mappings.group_name", AccTestAuthSettings1MappingsGroupName),
				),
			},
			// Update and Read testing
			{
				Config: resourceConfigUpdate,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", AccTestAuthSettings1NameUpdated),
					resource.TestCheckResourceAttr(resourceName, "domain", AccTestAuthSettings1DomainUpdated),
				),
			},
		},
	})
}
