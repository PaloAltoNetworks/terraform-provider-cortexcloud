// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

//go:build acceptance

package compliance

import (
	"context"
	"fmt"
	"strconv"
	"testing"
	"time"

	types "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/types/compliance"
	util "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/types/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAccStandardLifecycle(t *testing.T) {
	client := setupAcceptanceTest(t)
	ctx := context.Background()
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)

	// Create Standard
	standardName := fmt.Sprintf("go-sdk-acctest-standard-%s", timestamp)
	standardDescription := fmt.Sprintf("Go SDK Acceptance Test Standard %s", timestamp)
	labels := []string{"aws", "k8s", "linux"}

	createReq := types.CreateStandardRequest{
		StandardName: standardName,
		Description:  standardDescription,
		Labels:       labels,
	}

	createSuccess, err := client.CreateStandard(ctx, createReq)
	require.NoError(t, err, "failed to create standard")
	require.True(t, createSuccess, "standard creation unsuccessful")

	t.Logf("Created standard: %s", standardName)

	// List to get the created standard ID
	listReq := types.ListStandardsRequest{
		Filters: []types.Filter{
			{
				Field:    "name",
				Operator: "contains",
				Value:    standardName,
			},
		},
	}

	listResp, err := client.ListStandards(ctx, listReq)
	require.NoError(t, err, "failed to list standards")
	require.NotNil(t, listResp, "list response is nil")
	require.Greater(t, len(listResp.Standards), 0, "created standard not found in list")

	createdStandard := listResp.Standards[0]
	standardID := createdStandard.ID

	t.Logf("Found created standard with ID: %s", standardID)

	// Defer cleanup
	defer func() {
		deleteReq := types.DeleteStandardRequest{
			ID: standardID,
		}
		deleteSuccess, err := client.DeleteStandard(ctx, deleteReq)
		if err != nil {
			t.Logf("Warning: failed to delete standard: %s", err.Error())
		} else if !deleteSuccess {
			t.Logf("Warning: standard deletion unsuccessful")
		} else {
			t.Logf("Successfully deleted standard: %s", standardID)
		}
	}()

	// Get Standard by ID
	getReq := types.GetStandardRequest{
		ID: standardID,
	}

	standard, err := client.GetStandard(ctx, getReq)
	require.NoError(t, err, "failed to get standard")
	require.NotNil(t, standard, "standard is nil")

	// Verify created standard details
	assert.Equal(t, standardID, standard.ID)
	assert.Equal(t, standardName, standard.Name)
	assert.Equal(t, standardDescription, standard.Description)
	assert.ElementsMatch(t, labels, standard.Labels)
	assert.True(t, standard.IsCustom, "custom standard should have IsCustom=true")
	assert.NotZero(t, standard.InsertTS)
	assert.NotZero(t, standard.ModifyTS)

	t.Logf("Verified standard details match creation request")

	// Update Standard
	updatedStandardName := fmt.Sprintf("%s-updated", standardName)
	updatedDescription := fmt.Sprintf("%s (Updated)", standardDescription)
	updatedLabels := []string{"aws", "azure", "gcp", "k8s"}

	updateReq := types.UpdateStandardRequest{
		ID:           standardID,
		StandardName: updatedStandardName,
		Description:  updatedDescription,
		Labels:       updatedLabels,
	}

	updateSuccess, err := client.UpdateStandard(ctx, updateReq)
	require.NoError(t, err, "failed to update standard")
	require.True(t, updateSuccess, "standard update unsuccessful")

	t.Logf("Updated standard: %s", standardID)

	// Verify update
	updatedStandard, err := client.GetStandard(ctx, getReq)
	require.NoError(t, err, "failed to get updated standard")
	require.NotNil(t, updatedStandard, "updated standard is nil")

	assert.Equal(t, standardID, updatedStandard.ID)
	assert.Equal(t, updatedStandardName, updatedStandard.Name)
	assert.Equal(t, updatedDescription, updatedStandard.Description)
	assert.ElementsMatch(t, updatedLabels, updatedStandard.Labels)

	t.Logf("Verified updated standard details")

	// Test List with filters
	listWithFilterReq := types.ListStandardsRequest{
		Filters: []types.Filter{
			{
				Field:    "is_custom",
				Operator: "in",
				Value:    []string{"yes"},
			},
			{
				Field:    "name",
				Operator: "contains",
				Value:    updatedStandardName,
			},
		},
		SearchFrom: util.ToPointer(0),
		SearchTo:   util.ToPointer(10),
	}

	filteredListResp, err := client.ListStandards(ctx, listWithFilterReq)
	require.NoError(t, err, "failed to list standards with filter")
	require.NotNil(t, filteredListResp, "filtered list response is nil")
	require.Greater(t, len(filteredListResp.Standards), 0, "no standards found with filter")

	foundStandard := false
	for _, s := range filteredListResp.Standards {
		if s.ID == standardID {
			foundStandard = true
			assert.Equal(t, updatedStandardName, s.Name)
			assert.True(t, s.IsCustom)
			break
		}
	}
	assert.True(t, foundStandard, "updated standard not found in filtered list")

	t.Logf("Successfully completed standard lifecycle test")
}

func TestAccStandardList(t *testing.T) {
	client := setupAcceptanceTest(t)
	ctx := context.Background()

	// Test basic list without filters
	listReq := types.ListStandardsRequest{
		SearchFrom: util.ToPointer(0),
		SearchTo:   util.ToPointer(5),
	}

	listResp, err := client.ListStandards(ctx, listReq)
	require.NoError(t, err, "failed to list standards")
	require.NotNil(t, listResp, "list response is nil")

	t.Logf("Found %d total standards, returned %d", listResp.TotalCount, listResp.ResultCount)

	// Verify response structure
	assert.GreaterOrEqual(t, listResp.TotalCount, 0)
	assert.GreaterOrEqual(t, listResp.ResultCount, 0)
	assert.LessOrEqual(t, listResp.ResultCount, 5)

	// If there are standards, verify their structure
	if len(listResp.Standards) > 0 {
		standard := listResp.Standards[0]
		assert.NotEmpty(t, standard.ID, "standard ID is empty")
		assert.NotEmpty(t, standard.Name, "standard name is empty")
		assert.NotZero(t, standard.InsertTS, "insert timestamp is zero")
		t.Logf("Sample standard: ID=%s, Name=%s, IsCustom=%v", standard.ID, standard.Name, standard.IsCustom)
	}
}

func TestAccStandardFilterByLabels(t *testing.T) {
	client := setupAcceptanceTest(t)
	ctx := context.Background()

	// Test filtering by labels
	listReq := types.ListStandardsRequest{
		Filters: []types.Filter{
			{
				Field:    "labels",
				Operator: "contains",
				Value:    "aws",
			},
		},
		SearchFrom: util.ToPointer(0),
		SearchTo:   util.ToPointer(10),
	}

	listResp, err := client.ListStandards(ctx, listReq)
	require.NoError(t, err, "failed to list standards with label filter")
	require.NotNil(t, listResp, "list response is nil")

	t.Logf("Found %d standards with 'aws' label", listResp.ResultCount)

	// Verify all returned standards have the 'aws' label
	for _, standard := range listResp.Standards {
		hasAwsLabel := false
		for _, label := range standard.Labels {
			if label == "aws" {
				hasAwsLabel = true
				break
			}
		}
		assert.True(t, hasAwsLabel, "standard %s does not have 'aws' label", standard.ID)
	}
}

func TestAccStandardSorting(t *testing.T) {
	client := setupAcceptanceTest(t)
	ctx := context.Background()

	// Test sorting by insertion time descending
	listReq := types.ListStandardsRequest{
		Sort: &types.SortFilter{
			Field:   "insertion_time",
			Keyword: "desc",
		},
		SearchFrom: util.ToPointer(0),
		SearchTo:   util.ToPointer(10),
	}

	listResp, err := client.ListStandards(ctx, listReq)
	require.NoError(t, err, "failed to list standards with sorting")
	require.NotNil(t, listResp, "list response is nil")

	t.Logf("Retrieved %d standards sorted by insertion_time desc", listResp.ResultCount)

	// Verify sorting if we have multiple standards
	if len(listResp.Standards) > 1 {
		for i := 0; i < len(listResp.Standards)-1; i++ {
			current := listResp.Standards[i]
			next := listResp.Standards[i+1]
			assert.GreaterOrEqual(t, current.InsertTS, next.InsertTS,
				"standards not sorted correctly by insertion_time desc")
		}
		t.Logf("Verified sorting order is correct")
	}
}

func TestAccStandardFilterByCustom(t *testing.T) {
	client := setupAcceptanceTest(t)
	ctx := context.Background()

	// Test filtering for built-in standards (not custom)
	listReq := types.ListStandardsRequest{
		Filters: []types.Filter{
			{
				Field:    "is_custom",
				Operator: "in",
				Value:    []string{"no"},
			},
		},
		SearchFrom: util.ToPointer(0),
		SearchTo:   util.ToPointer(5),
	}

	listResp, err := client.ListStandards(ctx, listReq)
	require.NoError(t, err, "failed to list built-in standards")
	require.NotNil(t, listResp, "list response is nil")

	t.Logf("Found %d built-in standards", listResp.ResultCount)

	// Verify all returned standards are not custom
	for _, standard := range listResp.Standards {
		assert.False(t, standard.IsCustom, "standard %s should not be custom", standard.ID)
	}
}
