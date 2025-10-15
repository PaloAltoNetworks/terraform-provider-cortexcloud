// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package acceptance

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"testing"

	"github.com/PaloAltoNetworks/cortex-cloud-go/enums"
	"github.com/PaloAltoNetworks/cortex-cloud-go/log"
	"github.com/PaloAltoNetworks/cortex-cloud-go/platform"
	filterTypes "github.com/PaloAltoNetworks/cortex-cloud-go/types/filter"
	platformTypes "github.com/PaloAltoNetworks/cortex-cloud-go/types/platform"
	"github.com/hashicorp/terraform-plugin-log/tfsdklog"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

// TODO: fix issue with testAccCheckAssetGroupExists and
// testAccCheckAssetGroupDestroy returning 401

func testdataAssetGroupConfig(name, groupType, description string, predicate string) string {
	return fmt.Sprintf(`
resource "cortexcloud_asset_group" "test" {
    name = "%s"
    type = "%s"
    description = "%s"
    membership_predicate = {
		%s
	}
}
`, name, groupType, description, predicate)
}

func TestAccAssetGroupResourceDynamicLifecycle(t *testing.T) {
	t.Log("Beginning dynamic asset group lifecycle test")

	providerConfig := getProviderConfig(t, true)

	testGroupType := "Dynamic"
	initialTestGroupName := "test-asset-group"
	initialTestGroupDesc := "acceptance test"
	initialTestGroupPredicate := `and = [
			{
				search_field = "xdm.asset.name"
				search_type = "NEQ"
				search_value = "test"
			}
		]`
	initialResourceConfig := testdataAssetGroupConfig(
		initialTestGroupName,
		testGroupType,
		initialTestGroupDesc,
		initialTestGroupPredicate,
	)

	updatedTestGroupName := "test-asset-group-updated"
	updatedTestGroupDesc := "acceptance test updated"
	updatedTestGroupPredicate := `and = [
			{
				search_field = "xdm.asset.name"
				search_type = "NEQ"
				search_value = "test-updated"
			}
		]`
	updatedResourceConfig := testdataAssetGroupConfig(
		updatedTestGroupName,
		testGroupType,
		updatedTestGroupDesc,
		updatedTestGroupPredicate,
	)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				PreConfig: func() {
					t.Log("Executing Create test step")
					//t.Logf("Using the following test config: \n\n%s\n", providerConfig+initialResourceConfig)
				},
				Config: providerConfig + initialResourceConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("cortexcloud_asset_group.test", "name", initialTestGroupName),
					resource.TestCheckResourceAttr("cortexcloud_asset_group.test", "type", testGroupType),
					resource.TestCheckResourceAttr("cortexcloud_asset_group.test", "description", initialTestGroupDesc),
					resource.TestCheckResourceAttr("cortexcloud_asset_group.test", "membership_predicate.and.#", "1"),
					resource.TestCheckResourceAttr("cortexcloud_asset_group.test", "membership_predicate.or.#", "0"),
					//testAccCheckAssetGroupExists(t.Context(), "cortexcloud_asset_group.test"),
				),
			},
			// Update and Read testing
			{
				PreConfig: func() {
					t.Log("Executing Update test step")
					//t.Logf("Using the following test config: \n\n%s\n", providerConfig+updatedResourceConfig)
				},
				Config: providerConfig + updatedResourceConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("cortexcloud_asset_group.test", "name", updatedTestGroupName),
					resource.TestCheckResourceAttr("cortexcloud_asset_group.test", "type", testGroupType),
					resource.TestCheckResourceAttr("cortexcloud_asset_group.test", "description", updatedTestGroupDesc),
					resource.TestCheckResourceAttr("cortexcloud_asset_group.test", "membership_predicate.and.#", "1"),
					resource.TestCheckResourceAttr("cortexcloud_asset_group.test", "membership_predicate.or.#", "0"),
					//testAccCheckAssetGroupExists(t.Context(), "cortexcloud_asset_group.test"),
				),
			},
			// Delete and Read testing
			{
				PreConfig: func() {
					t.Log("Running delete step")
					//t.Logf("Using the following test config: \n\n%s\n", providerConfig+updatedResourceConfig)
				},
				Config: providerConfig,
			},
		},
		CheckDestroy: testAccCheckAssetGroupDestroy,
	})

	t.Log("Dynamic asset group lifecycle test complete")
}

func testAccCheckAssetGroupExists(ctx context.Context, n string) resource.TestCheckFunc {
	tfsdklog.Debug(context.Background(), "Confirming resource existence")

	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[n]
		if !ok {
			return fmt.Errorf("Not found: %s", n)
		}

		if rs.Primary.ID == "" {
			return fmt.Errorf("No ID is set")
		}

		id, err := strconv.Atoi(rs.Primary.ID)
		if err != nil {
			return fmt.Errorf("Error parsing ID: %s", err.Error())
		}
		var (
			testFQDN       string = os.Getenv(testFQDNEnvVar)
			testAPIKey     string = os.Getenv(testAPIKeyEnvVar)
			testAPIKeyID   int
			testAPIKeyType string = os.Getenv(testAPIKeyTypeEnvVar)
		)

		client, err := platform.NewClient(
			platform.WithCortexFQDN(testFQDN),
			platform.WithCortexAPIKey(testAPIKey),
			platform.WithCortexAPIKeyID(testAPIKeyID),
			platform.WithCortexAPIKeyType(testAPIKeyType),
			platform.WithLogger(log.TflogAdapter{}),
			platform.WithLogLevel("debug"),
		)

		if err != nil {
			return fmt.Errorf("error creating SDK client for existance check: %s", err.Error())
		}

		listReq := platformTypes.ListAssetGroupsRequest{
			Filters: filterTypes.NewSearchFilter(
				"XDM.ASSET_GROUP.ID",
				enums.SearchTypeEqualTo.String(),
				strconv.Itoa(id),
			),
		}

		assetGroups, err := client.ListAssetGroups(ctx, listReq)
		if err != nil {
			return fmt.Errorf("error listing asset groups for existance check: %s", err.Error())
		}

		if len(assetGroups) != 1 {
			return fmt.Errorf("Asset group not found")
		}

		return nil
	}
}

func testAccCheckAssetGroupDestroy(s *terraform.State) error {
	ctx := context.Background()
	tfsdklog.Debug(ctx, "Confirming resource destruction")

	platformClient, err := platform.NewClient(
		platform.WithCortexFQDN(testFQDN),
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
		if rs.Type != "cortexcloud_asset_group" {
			continue
		}

		id, err := strconv.Atoi(rs.Primary.ID)
		if err != nil {
			return fmt.Errorf("Error parsing ID: %s", err.Error())
		}

		listReq := platformTypes.ListAssetGroupsRequest{
			Filters: filterTypes.NewSearchFilter(
				"XDM.ASSET_GROUP.ID",
				enums.SearchTypeEqualTo.String(),
				strconv.Itoa(id),
			),
		}
		assetGroups, err := platformClient.ListAssetGroups(ctx, listReq)
		if err != nil {
			return fmt.Errorf("error listing asset groups for destruction check: %s", err.Error())
		}

		if len(assetGroups) > 0 {
			return fmt.Errorf("Asset group still exists")
		}
	}

	return nil
}
