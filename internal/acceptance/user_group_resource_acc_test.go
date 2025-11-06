// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package acceptance

import (
	"fmt"
	"strconv"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAcc_UserGroupResource(t *testing.T) {
	t.Log("Creating test configurations")

	providerConfig := getProviderConfig(t, dotEnvPath, true)
	resourceName := "cortexcloud_user_group.test"

	suffix := acctest.RandString(6)
	nameCreate := fmt.Sprintf("test-group-%s", suffix)
	nameUpdate := fmt.Sprintf("test-group-%s-updated", suffix)

	resourceConfigCreate := fmt.Sprintf(
		`resource "cortexcloud_user_group" "test" {
			group_name  = %s
			description = %s
		}`,
		strconv.Quote(nameCreate),
		strconv.Quote("This is a test user group."),
	)

	resourceConfigUpdate := fmt.Sprintf(
		`resource "cortexcloud_user_group" "test" {
			group_name  = %s
			description = %s
		}`,
		strconv.Quote(nameUpdate),
		strconv.Quote("This is an updated test user group."),
	)

	t.Log("Running tests")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create & Read
			{
				Config: providerConfig + resourceConfigCreate,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "group_name", nameCreate),
					resource.TestCheckResourceAttr(resourceName, "description", "This is a test user group."),
				),
			},
			{
				Config: providerConfig + resourceConfigUpdate,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "group_name", nameUpdate),
					resource.TestCheckResourceAttr(resourceName, "description", "This is an updated test user group."),
				),
			},
			{
				Config:  providerConfig,
				Destroy: true,
			},
		},
	})
}
