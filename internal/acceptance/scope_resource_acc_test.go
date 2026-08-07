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
					mode = "see_all"
					tags = []
				}
				endpoint_tags = {
					mode = "any"
					tags = []
				}
			}

			cases_issues = {
				mode = "see_all"
				tags = []
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

// TestAcc_ScopeResource_DatasetsRowsOmitted verifies that a scope omitting the
// datasets_rows block applies cleanly with no drift on a tenant where dataset
// SBAC is disabled. Set TF_ACC_TEST_SBAC_DISABLED_ENTITY_ID (and _TYPE, default
// "user-group") to run it.
func TestAcc_ScopeResource_DatasetsRowsOmitted(t *testing.T) {
	entityID := os.Getenv("TF_ACC_TEST_SBAC_DISABLED_ENTITY_ID")
	if entityID == "" {
		t.Skip("skipping: set TF_ACC_TEST_SBAC_DISABLED_ENTITY_ID to a scope entity on an SBAC-disabled tenant")
	}
	entityType := os.Getenv("TF_ACC_TEST_SBAC_DISABLED_ENTITY_TYPE")
	if entityType == "" {
		entityType = "user-group"
	}

	providerConfig := getProviderConfig(t, dotEnvPath, true)
	resourceName := "cortexcloud_scope.test"

	// NOTE: datasets_rows is intentionally OMITTED here.
	config := providerConfig + fmt.Sprintf(
		`resource "cortexcloud_scope" "test" {
			entity_type = %s
			entity_id   = %s

			assets = {
				mode = "no_scope"
				asset_groups = []
			}

			endpoints = {
				endpoint_groups = {
					mode = "no_scope"
					tags = []
				}
				endpoint_tags = {
					mode = "no_scope"
					tags = []
				}
			}

			cases_issues = {
				mode = "no_scope"
				tags = []
			}
		}`,
		strconv.Quote(entityType),
		strconv.Quote(entityID),
	)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "entity_type", entityType),
					resource.TestCheckResourceAttr(resourceName, "entity_id", entityID),
					resource.TestCheckResourceAttr(resourceName, "assets.mode", "no_scope"),
					// datasets_rows must remain null (not resurrected by read-back).
					resource.TestCheckNoResourceAttr(resourceName, "datasets_rows.default_filter_mode"),
				),
			},
			{
				// Re-plan must be a no-op: no perpetual "datasets_rows will be added" drift.
				Config:   config,
				PlanOnly: true,
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
