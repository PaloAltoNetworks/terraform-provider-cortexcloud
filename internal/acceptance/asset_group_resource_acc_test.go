// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package acceptance

import (
	"context"
	"fmt"
	"strconv"
	"testing"

	"github.com/PaloAltoNetworks/cortex-cloud-go/enums"
	"github.com/PaloAltoNetworks/cortex-cloud-go/log"
	"github.com/PaloAltoNetworks/cortex-cloud-go/platform"
	filterTypes "github.com/PaloAltoNetworks/cortex-cloud-go/types/filter"
	platformTypes "github.com/PaloAltoNetworks/cortex-cloud-go/types/platform"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

func TestAccAssetGroupResource(t *testing.T) {
	t.Log("Beginning Asset Group lifecycle test")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				Config: testdataAssetGroupConfig("test-asset-group", "static", "Initial asset group", ""),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("cortexcloud_asset_group.test", "name", "test-asset-group"),
					resource.TestCheckResourceAttr("cortexcloud_asset_group.test", "type", "static"),
					resource.TestCheckResourceAttr("cortexcloud_asset_group.test", "description", "Initial asset group"),
					//testAccCheckAssetGroupExists(t.Context(), "cortexcloud_asset_group.test"),
				),
			},
			// Update and Read testing
			{
				Config: testdataAssetGroupConfig("test-asset-group-updated", "dynamic", "Updated asset group", `
or = [
    {
        and = [
            {
                field = "xdm.asset.asset_name"
                operator = "eq"
                value = "test-asset"
            }
        ]
    }
]
`),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("cortexcloud_asset_group.test", "name", "test-asset-group-updated"),
					resource.TestCheckResourceAttr("cortexcloud_asset_group.test", "type", "dynamic"),
					resource.TestCheckResourceAttr("cortexcloud_asset_group.test", "description", "Updated asset group"),
					resource.TestCheckResourceAttr("cortexcloud_asset_group.test", "membership_predicate.or.#", "1"),
					//testAccCheckAssetGroupExists(t.Context(), "cortexcloud_asset_group.test"),
				),
			},
			// Delete testing automatically occurs in TestMain
		},
		//CheckDestroy: testAccCheckAssetGroupDestroy,
	})
}

func testAccCheckAssetGroupExists(ctx context.Context, n string) resource.TestCheckFunc {
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

		tflog.Debug(ctx, fmt.Sprintf("URL = %s", apiURL))
		tflog.Debug(ctx, fmt.Sprintf("Key = %s", apiKey))
		tflog.Debug(ctx, fmt.Sprintf("KeyID = %d", apiKeyID))
		client, err := platform.NewClient(
			platform.WithCortexAPIURL(apiURL),
			platform.WithCortexAPIKey(apiKey),
			platform.WithCortexAPIKeyID(apiKeyID),
			platform.WithLogger(log.TflogAdapter{}),
			platform.WithLogLevel("debug"),
		)
		if err != nil {
			return err
		}
		listReq := platformTypes.ListAssetGroupsRequest{
			Filters: filterTypes.NewSearchFilter(
				"XDM.ASSET_GROUP.ID",
				enums.SearchTypeEqualTo.String(),
				strconv.Itoa(id),
			),
		}
		assetGroups, err := client.ListAssetGroups(context.Background(), listReq)
		if err != nil {
			return err
		}

		if len(assetGroups) != 1 {
			return fmt.Errorf("Asset group not found")
		}

		return nil
	}
}

func testAccCheckAssetGroupDestroy(s *terraform.State) error {
	client, err := platform.NewClient(
		platform.WithCortexAPIURL(apiURL),
		platform.WithCortexAPIKey(apiKey),
		platform.WithCortexAPIKeyID(apiKeyID),
		platform.WithLogger(log.TflogAdapter{}),
		platform.WithLogLevel("debug"),
	)
	if err != nil {
		return err
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
		assetGroups, err := client.ListAssetGroups(context.Background(), listReq)
		if err != nil {
			return err
		}

		if len(assetGroups) > 0 {
			return fmt.Errorf("Asset group still exists")
		}
	}

	return nil
}
