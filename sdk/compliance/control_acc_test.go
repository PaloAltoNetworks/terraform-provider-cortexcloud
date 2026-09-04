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

func TestAccControlLifecycle(t *testing.T) {
	client := setupAcceptanceTest(t)
	ctx := context.Background()
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)

	// Use hardcoded category and subcategory values for testing
	category := "Access Control"
	subcategory := "AC-1"

	t.Logf("Using category: %s, subcategory: %s", category, subcategory)

	// Create Control
	controlName := fmt.Sprintf("go-sdk-acctest-control-%s", timestamp)
	controlDescription := fmt.Sprintf("Go SDK Acceptance Test Control %s", timestamp)

	createReq := types.CreateControlRequest{
		ControlName: controlName,
		Description: controlDescription,
		Category:    category,
		Subcategory: subcategory,
	}

	createResp, err := client.CreateControl(ctx, createReq)
	require.NoError(t, err, "failed to create control")
	require.NotNil(t, createResp, "create response is nil")
	require.True(t, createResp.Success, "control creation unsuccessful")
	require.NotEmpty(t, createResp.ControlID, "control ID not returned")

	controlID := createResp.ControlID
	t.Logf("Created control: %s with ID: %s", controlName, controlID)

	// Defer cleanup
	defer func() {
		deleteReq := types.DeleteControlRequest{
			ID: controlID,
		}
		deleteSuccess, err := client.DeleteControl(ctx, deleteReq)
		if err != nil {
			t.Logf("Warning: failed to delete control: %s", err.Error())
		} else if !deleteSuccess {
			t.Logf("Warning: control deletion unsuccessful")
		} else {
			t.Logf("Successfully deleted control: %s", controlID)
		}
	}()

	// Get Control by ID
	getReq := types.GetControlRequest{
		ID: controlID,
	}

	control, err := client.GetControl(ctx, getReq)
	require.NoError(t, err, "failed to get control")
	require.NotNil(t, control, "control is nil")

	// Verify created control details
	assert.Equal(t, controlID, control.ID)
	assert.Equal(t, controlName, control.Name)
	assert.Equal(t, controlDescription, control.Description)
	assert.Equal(t, category, control.Category)
	assert.Equal(t, subcategory, control.Subcategory)
	assert.True(t, control.IsCustom, "custom control should have IsCustom=true")
	assert.NotZero(t, control.InsertionTime)
	assert.NotZero(t, control.ModificationTime)

	t.Logf("Verified control details match creation request")

	// Update Control
	updatedControlName := fmt.Sprintf("%s-updated", controlName)
	updatedDescription := fmt.Sprintf("%s (Updated)", controlDescription)

	updateReq := types.UpdateControlRequest{
		ID:          controlID,
		ControlName: updatedControlName,
		Description: updatedDescription,
	}

	updateSuccess, err := client.UpdateControl(ctx, updateReq)
	require.NoError(t, err, "failed to update control")
	require.True(t, updateSuccess, "control update unsuccessful")

	t.Logf("Updated control: %s", controlID)

	// Verify update
	updatedControl, err := client.GetControl(ctx, getReq)
	require.NoError(t, err, "failed to get updated control")
	require.NotNil(t, updatedControl, "updated control is nil")

	assert.Equal(t, controlID, updatedControl.ID)
	assert.Equal(t, updatedControlName, updatedControl.Name)
	assert.Equal(t, updatedDescription, updatedControl.Description)

	t.Logf("Verified updated control details")

	// Test List with filters
	listWithFilterReq := types.ListControlsRequest{
		Filters: []types.Filter{
			{
				Field:    "is_custom",
				Operator: "in",
				Value:    []string{"yes"},
			},
			{
				Field:    "name",
				Operator: "contains",
				Value:    updatedControlName,
			},
		},
		SearchFrom: util.ToPointer(0),
		SearchTo:   util.ToPointer(10),
	}

	filteredListResp, err := client.ListControls(ctx, listWithFilterReq)
	require.NoError(t, err, "failed to list controls with filter")
	require.NotNil(t, filteredListResp, "filtered list response is nil")
	require.Greater(t, len(filteredListResp.Controls), 0, "no controls found with filter")

	foundControl := false
	for _, c := range filteredListResp.Controls {
		if c.ID == controlID {
			foundControl = true
			assert.Equal(t, updatedControlName, c.Name)
			assert.True(t, c.IsCustom)
			break
		}
	}
	assert.True(t, foundControl, "updated control not found in filtered list")

	t.Logf("Successfully completed control lifecycle test")
}

func TestAccControlList(t *testing.T) {
	client := setupAcceptanceTest(t)
	ctx := context.Background()

	// Test basic list without filters
	listReq := types.ListControlsRequest{
		SearchFrom: util.ToPointer(0),
		SearchTo:   util.ToPointer(5),
	}

	listResp, err := client.ListControls(ctx, listReq)
	require.NoError(t, err, "failed to list controls")
	require.NotNil(t, listResp, "list response is nil")

	t.Logf("Found %d total controls, returned %d", listResp.TotalCount, listResp.ResultCount)

	// Verify response structure
	assert.GreaterOrEqual(t, listResp.TotalCount, 0)
	assert.GreaterOrEqual(t, listResp.ResultCount, 0)
	assert.LessOrEqual(t, listResp.ResultCount, 5)

	// If there are controls, verify their structure
	if len(listResp.Controls) > 0 {
		control := listResp.Controls[0]
		assert.NotEmpty(t, control.ID, "control ID is empty")
		assert.NotEmpty(t, control.Name, "control name is empty")
		assert.NotEmpty(t, control.Category, "category is empty")
		assert.NotEmpty(t, control.Subcategory, "subcategory is empty")
		assert.NotZero(t, control.InsertionTime, "insertion time is zero")
		t.Logf("Sample control: ID=%s, Name=%s, Category=%s, IsCustom=%v",
			control.ID, control.Name, control.Category, control.IsCustom)
	}
}

func TestAccControlFilterByCategory(t *testing.T) {
	client := setupAcceptanceTest(t)
	ctx := context.Background()

	// Use hardcoded category value for testing
	category := "Access Control"

	// Test filtering by category
	listReq := types.ListControlsRequest{
		Filters: []types.Filter{
			{
				Field:    "category",
				Operator: "eq",
				Value:    category,
			},
		},
		SearchFrom: util.ToPointer(0),
		SearchTo:   util.ToPointer(10),
	}

	listResp, err := client.ListControls(ctx, listReq)
	require.NoError(t, err, "failed to list controls with category filter")
	require.NotNil(t, listResp, "list response is nil")

	t.Logf("Found %d controls in category '%s'", listResp.ResultCount, category)

	// Verify all returned controls have the correct category
	for _, control := range listResp.Controls {
		assert.Equal(t, category, control.Category, "control %s has wrong category", control.ID)
	}
}

func TestAccControlSorting(t *testing.T) {
	client := setupAcceptanceTest(t)
	ctx := context.Background()

	// Test sorting by creation time descending
	listReq := types.ListControlsRequest{
		Sort: &types.SortFilter{
			Field:   "creation_time",
			Keyword: "desc",
		},
		SearchFrom: util.ToPointer(0),
		SearchTo:   util.ToPointer(10),
	}

	listResp, err := client.ListControls(ctx, listReq)
	require.NoError(t, err, "failed to list controls with sorting")
	require.NotNil(t, listResp, "list response is nil")

	t.Logf("Retrieved %d controls sorted by creation_time desc", listResp.ResultCount)

	// Verify sorting if we have multiple controls
	if len(listResp.Controls) > 1 {
		for i := 0; i < len(listResp.Controls)-1; i++ {
			current := listResp.Controls[i]
			next := listResp.Controls[i+1]
			assert.GreaterOrEqual(t, current.InsertionTime, next.InsertionTime,
				"controls not sorted correctly by creation_time desc")
		}
		t.Logf("Verified sorting order is correct")
	}
}

func TestAccControlFilterByCustom(t *testing.T) {
	client := setupAcceptanceTest(t)
	ctx := context.Background()

	// Test filtering for built-in controls (not custom)
	listReq := types.ListControlsRequest{
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

	listResp, err := client.ListControls(ctx, listReq)
	require.NoError(t, err, "failed to list built-in controls")
	require.NotNil(t, listResp, "list response is nil")

	t.Logf("Found %d built-in controls", listResp.ResultCount)

	// Verify all returned controls are not custom
	for _, control := range listResp.Controls {
		assert.False(t, control.IsCustom, "control %s should not be custom", control.ID)
	}
}
