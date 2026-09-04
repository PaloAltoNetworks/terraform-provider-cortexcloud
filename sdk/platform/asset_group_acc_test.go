// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

//go:build acceptance

package platform

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"testing"
	"time"

	filterTypes "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/types/filter"
	platformTypes "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/types/platform"
	"github.com/stretchr/testify/assert"
)

func setupAcceptanceTest(t *testing.T) *Client {
	apiUrl := os.Getenv("TEST_CORTEX_API_URL")
	apiKey := os.Getenv("TEST_CORTEX_API_KEY")
	apiKeyIDStr := os.Getenv("TEST_CORTEX_API_KEY_ID")

	apiKeyID, err := strconv.Atoi(apiKeyIDStr)
	if err != nil {
		t.Fatalf("failed to convert API key ID \"%s\" to int: %s", apiKeyIDStr, err.Error())
	}

	client, err := NewClient(
		WithCortexAPIURL(apiUrl),
		WithCortexAPIKey(apiKey),
		WithCortexAPIKeyID(apiKeyID),
		WithCortexAPIKeyType("standard"),
		WithLogLevel("debug"),
	)
	assert.NoError(t, err)
	assert.NotNil(t, client)

	return client
}

func TestAccDynamicAssetGroupLifecycle(t *testing.T) {
	client := setupAcceptanceTest(t)
	ctx := context.Background()
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)

	// Create
	groupName := fmt.Sprintf("go-sdk-acctest-account-group-%s", timestamp)
	groupType := "Dynamic"
	groupDescription := fmt.Sprintf("Go SDK Acceptance Test %s", timestamp)
	andCriteria1Field := "xdm.asset.name"
	andCriteria1Type := "NCONTAINS"
	andCriteria1Value := "test"
	andFilter := filterTypes.NewAndFilter(
		filterTypes.NewSearchFilter(
			andCriteria1Field,
			andCriteria1Type,
			andCriteria1Value,
		),
	)
	membershipPredicate := filterTypes.NewRootFilter(
		[]filterTypes.Filter{andFilter},
		nil,
	)

	createReq := platformTypes.CreateOrUpdateAssetGroupRequest{
		GroupName:           groupName,
		GroupType:           groupType,
		GroupDescription:    groupDescription,
		MembershipPredicate: membershipPredicate,
	}

	createSuccess, groupID, err := client.CreateAssetGroup(ctx, createReq)
	if err != nil {
		t.Fatalf("error creating asset group: %s", err.Error())
	}
	if !createSuccess {
		t.Fatalf("asset group creation unsuccessful: %s", err.Error())
	}

	// Check
	assert.Equal(t, true, createSuccess)
	assert.Positive(t, groupID)

	// Defer Delete check
	testDeleteAssetGroup := func(t *testing.T, ctx context.Context, groupID int) {
		// Delete
		success, err := client.DeleteAssetGroup(ctx, groupID)

		// Check
		if err != nil {
			t.Fatalf("error deleting asset group: %s", err.Error())
		}
		if !success {
			t.Fatalf("asset group deletion unsuccessful: %s", err.Error())
		}
		assert.Equal(t, true, success)
	}
	defer testDeleteAssetGroup(t, ctx, groupID)

	// Read
	listReq := platformTypes.ListAssetGroupsRequest{
		Filters: filterTypes.NewAndFilter(
			filterTypes.NewSearchFilter(
				"XDM.ASSET_GROUP.NAME",
				"CONTAINS",
				groupName,
			),
		),
	}
	assetGroups, err := client.ListAssetGroups(ctx, listReq)
	if err != nil {
		t.Fatalf("error fetching asset group: %s", err.Error())
	}

	// Check
	expectedFilter := []platformTypes.AssetGroupFilter{
		{
			PrettyName: "name",
			DataType:   "TEXT",
			RenderType: "attribute",
		},
		{
			PrettyName: "doesn't contain",
			RenderType: "operator",
		},
		{
			PrettyName: andCriteria1Value,
			RenderType: "value",
		},
	}

	assert.NotNil(t, assetGroups)
	assert.Len(t, assetGroups, 1)
	assetGroup := assetGroups[0]
	assert.Equal(t, groupID, assetGroup.ID)
	assert.Equal(t, groupName, assetGroup.Name)
	assert.Equal(t, groupType, assetGroup.Type)
	assert.Equal(t, groupDescription, assetGroup.Description)
	assert.Equal(t, membershipPredicate, assetGroup.MembershipPredicate)
	assert.Equal(t, expectedFilter, assetGroup.Filter)

	// Update
	updatedGroupName := fmt.Sprintf("%s-updated", groupName)
	updatedGroupDescription := fmt.Sprintf("%s (Updated)", groupDescription)
	andCriteria2Field := "xdm.asset.name"
	andCriteria2Type := "NCONTAINS"
	andCriteria2Value := "test"
	andFilter.AddAnd(
		filterTypes.NewSearchFilter(
			andCriteria2Field,
			andCriteria2Type,
			andCriteria2Value,
		),
	)

	membershipPredicate = filterTypes.NewRootFilter(
		[]filterTypes.Filter{andFilter},
		nil,
	)

	updateReq := platformTypes.CreateOrUpdateAssetGroupRequest{
		GroupName:           updatedGroupName,
		GroupType:           groupType,
		GroupDescription:    updatedGroupDescription,
		MembershipPredicate: membershipPredicate,
	}

	updateSuccess, err := client.UpdateAssetGroup(ctx, groupID, updateReq)
	if err != nil {
		t.Fatalf("error creating asset group: %s", err.Error())
	}
	if !updateSuccess {
		t.Fatalf("asset group update unsuccessful: %s", err.Error())
	}

	// Check
	assert.Equal(t, true, updateSuccess)
	updatedAssetGroups, err := client.ListAssetGroups(ctx, listReq)
	if err != nil {
		t.Fatalf("error fetching updated asset group: %s", err.Error())
	}

	expectedUpdatedFilter := append(expectedFilter,
		platformTypes.AssetGroupFilter{
			PrettyName: "AND",
			RenderType: "connector",
		},
		platformTypes.AssetGroupFilter{
			PrettyName: andCriteria2Value,
			RenderType: "value",
		},
	)

	assert.NotNil(t, updatedAssetGroups)
	assert.Len(t, updatedAssetGroups, 1)
	updatedAssetGroup := updatedAssetGroups[0]
	assert.Equal(t, groupID, updatedAssetGroup.ID)
	assert.Equal(t, updatedGroupName, updatedAssetGroup.Name)
	assert.Equal(t, groupType, updatedAssetGroup.Type)
	assert.Equal(t, updatedGroupDescription, updatedAssetGroup.Description)
	assert.Equal(t, membershipPredicate, updatedAssetGroup.MembershipPredicate)
	assert.Equal(t, expectedUpdatedFilter, updatedAssetGroup.Filter)
}
