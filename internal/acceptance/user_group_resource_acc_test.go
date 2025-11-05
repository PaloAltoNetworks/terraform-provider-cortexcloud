// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package acceptance

import (
	"fmt"
	"strconv"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

const (
	AccTestUserGroup1Name               = "test-group-2"
	AccTestUserGroup1NameUpdated        = "test-group-2-updated"
	AccTestUserGroup1Description        = "This is a test user group."
	AccTestUserGroup1DescriptionUpdated = "This is an updated test user group."
)

func TestAcc_UserGroupResource(t *testing.T) {
	t.Log("Creating test configurations")

	providerConfig := getProviderConfig(t, dotEnvPath, true)
	resourceName := "cortexcloud_user_group.test"
	resourceConfigCreate := fmt.Sprintf(
		`resource "cortexcloud_user_group" "test" {
			group_name = %s
			description = %s
		}`,
		strconv.Quote(AccTestUserGroup1Name),
		strconv.Quote(AccTestUserGroup1Description),
	)
	resourceConfigUpdate := fmt.Sprintf(
		`resource "cortexcloud_user_group" "test" {
			group_name = %s
			description = %s
		}`,
		strconv.Quote(AccTestUserGroup1NameUpdated),
		strconv.Quote(AccTestUserGroup1DescriptionUpdated),
	)

	t.Log("Running tests")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				Config: providerConfig + resourceConfigCreate,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "group_name", AccTestUserGroup1Name),
					resource.TestCheckResourceAttr(resourceName, "description", AccTestUserGroup1Description),
				),
			},
			// Update and Read testing
			{
				Config: providerConfig + resourceConfigUpdate,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "group_name", AccTestUserGroup1NameUpdated),
					resource.TestCheckResourceAttr(resourceName, "description", AccTestUserGroup1DescriptionUpdated),
				),
			},
		},
	})
}
