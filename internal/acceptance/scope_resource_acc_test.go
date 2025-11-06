// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package acceptance

import (
	"fmt"
	"os"
	"strconv"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAcc_ScopeResource(t *testing.T) {
	t.Log("Creating test configurations")

	entityID := firstNonEmpty(
		os.Getenv("TF_ACC_TEST_ENTITY_ID"),
	)
	if entityID == "" {
		t.Skip("skipping: please set TF_ACC_TEST_ENTITY_ID ")
	}
	entityType := os.Getenv("TF_ACC_TEST_ENTITY_TYPE")
	if entityType == "" {
		t.Skip("skipping: please set TF_ACC_TEST_ENTITY_TYPE ")
	}

	providerConfig := getProviderConfig(t, dotEnvPath, true)
	resourceName := "cortexcloud_scope.test"

	resourceConfigCreate := fmt.Sprintf(
		`resource "cortexcloud_scope" "test" {
			entity_type = %s
			entity_id   = %s

			assets = {
				mode = "see_all"
				asset_groups = []
			}

			endpoints = {
				endpoint_groups = {
					mode  = "see_all"
					names = []
				}
				endpoint_tags = {
					mode  = "any"
					names = []
				}
			}

			cases_issues = {
				mode  = "see_all"
				names = []
			}

			datasets_rows = {
				default_filter_mode = "see_all"
				filters = []
			}
		}`,
		strconv.Quote(entityType),
		strconv.Quote(entityID),
	)

	t.Log("Running tests")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + resourceConfigCreate,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "entity_type", entityType),
					resource.TestCheckResourceAttr(resourceName, "entity_id", entityID),

					resource.TestCheckResourceAttr(resourceName, "assets.mode", "see_all"),
					resource.TestCheckResourceAttr(resourceName, "datasets_rows.default_filter_mode", "see_all"),

					resource.TestCheckResourceAttr(resourceName, "endpoints.endpoint_groups.mode", "see_all"),
					resource.TestCheckResourceAttr(resourceName, "endpoints.endpoint_tags.mode", "any"),

					resource.TestCheckResourceAttr(resourceName, "cases_issues.mode", "see_all"),
				),
			},
		},
	})
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
