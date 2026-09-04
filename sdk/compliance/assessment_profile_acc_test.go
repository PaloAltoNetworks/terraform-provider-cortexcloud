// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

//go:build acceptance

package compliance

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"testing"
	"time"

	types "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/types/compliance"
	util "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/types/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupAcceptanceTest(t *testing.T) *Client {
	apiUrl := os.Getenv("TEST_CORTEX_API_URL")
	apiKey := os.Getenv("TEST_CORTEX_API_KEY")
	apiKeyIDStr := os.Getenv("TEST_CORTEX_API_KEY_ID")

	if apiUrl == "" || apiKey == "" || apiKeyIDStr == "" {
		t.Skip("Skipping acceptance test: TEST_CORTEX_API_URL, TEST_CORTEX_API_KEY, or TEST_CORTEX_API_KEY_ID not set")
	}

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
	require.NoError(t, err)
	require.NotNil(t, client)

	return client
}

func TestAccAssessmentProfileLifecycle(t *testing.T) {
	client := setupAcceptanceTest(t)
	ctx := context.Background()
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)

	// First, we need to get a valid standard ID and asset group ID
	// List standards to get a valid standard ID
	listStandardsReq := types.ListStandardsRequest{
		SearchFrom: util.ToPointer(0),
		SearchTo:   util.ToPointer(1),
	}
	standardsResp, err := client.ListStandards(ctx, listStandardsReq)
	require.NoError(t, err, "failed to list standards")
	require.NotNil(t, standardsResp, "standards response is nil")

	var standardID string
	var createdStandard bool

	if len(standardsResp.Standards) == 0 {
		// No standards exist, create one for testing
		t.Log("No existing standards found, creating one for testing")
		standardName := fmt.Sprintf("go-sdk-acctest-standard-%s", timestamp)
		createStandardReq := types.CreateStandardRequest{
			StandardName: standardName,
			Description:  "Temporary standard for acceptance testing",
			Labels:       []string{},
			ControlsIDs:  []string{},
		}
		createSuccess, err := client.CreateStandard(ctx, createStandardReq)
		require.NoError(t, err, "failed to create standard")
		require.True(t, createSuccess, "standard creation unsuccessful")

		// List again to get the created standard's ID
		standardsResp, err = client.ListStandards(ctx, listStandardsReq)
		require.NoError(t, err, "failed to list standards after creation")
		require.Greater(t, len(standardsResp.Standards), 0, "created standard not found")

		standardID = standardsResp.Standards[0].ID
		createdStandard = true
		t.Logf("Created and using standard ID: %s", standardID)
	} else {
		standardID = standardsResp.Standards[0].ID
		t.Logf("Using existing standard ID: %s", standardID)
	}

	// Defer cleanup of created standard if we created one
	if createdStandard {
		defer func() {
			deleteStandardReq := types.DeleteStandardRequest{
				ID: standardID,
			}
			deleteSuccess, err := client.DeleteStandard(ctx, deleteStandardReq)
			if err != nil {
				t.Logf("Warning: failed to delete standard: %s", err.Error())
			} else if !deleteSuccess {
				t.Logf("Warning: standard deletion unsuccessful")
			} else {
				t.Logf("Successfully deleted standard: %s", standardID)
			}
		}()
	}

	// For asset group, we'll use a default value of "1" which typically exists
	// In a real scenario, you might want to list asset groups first
	assetGroupID := "1"

	// Create Assessment Profile
	profileName := fmt.Sprintf("go-sdk-acctest-profile-%s", timestamp)
	profileDescription := fmt.Sprintf("Go SDK Acceptance Test %s", timestamp)

	createReq := types.CreateAssessmentProfileRequest{
		ProfileName:   profileName,
		AssetGroupID:  assetGroupID,
		StandardID:    standardID,
		Description:   profileDescription,
		ReportType:    "NONE",
		ReportTargets: []string{},
	}

	createSuccess, err := client.CreateAssessmentProfile(ctx, createReq)
	require.NoError(t, err, "failed to create assessment profile")
	require.True(t, createSuccess, "assessment profile creation unsuccessful")

	t.Logf("Created assessment profile: %s", profileName)

	// List to get the created profile ID
	listReq := types.ListAssessmentProfilesRequest{
		Filters: []types.Filter{
			{
				Field:    "name",
				Operator: "contains",
				Value:    profileName,
			},
		},
	}

	listResp, err := client.ListAssessmentProfiles(ctx, listReq)
	require.NoError(t, err, "failed to list assessment profiles")
	require.NotNil(t, listResp, "list response is nil")
	require.Greater(t, len(listResp.AssessmentProfiles), 0, "created profile not found in list")

	createdProfile := listResp.AssessmentProfiles[0]
	profileID := createdProfile.ID

	t.Logf("Found created profile with ID: %s", profileID)

	// Defer cleanup
	defer func() {
		deleteReq := types.DeleteAssessmentProfileRequest{
			ID: profileID,
		}
		deleteSuccess, err := client.DeleteAssessmentProfile(ctx, deleteReq)
		if err != nil {
			t.Logf("Warning: failed to delete assessment profile: %s", err.Error())
		} else if !deleteSuccess {
			t.Logf("Warning: assessment profile deletion unsuccessful")
		} else {
			t.Logf("Successfully deleted assessment profile: %s", profileID)
		}
	}()

	// Get Assessment Profile by ID
	getReq := types.GetAssessmentProfileRequest{
		ID: profileID,
	}

	profile, err := client.GetAssessmentProfile(ctx, getReq)
	require.NoError(t, err, "failed to get assessment profile")
	require.NotNil(t, profile, "profile is nil")

	// Verify created profile details
	assert.Equal(t, profileID, profile.ID)
	assert.Equal(t, profileName, profile.Name)
	assert.Equal(t, profileDescription, profile.Description)
	assert.Equal(t, standardID, profile.StandardID)
	// AssetGroupID is returned as int, not string
	assert.NotZero(t, profile.AssetGroupID)
	assert.NotZero(t, profile.InsertTS)
	assert.NotZero(t, profile.ModifyTS)

	t.Logf("Verified profile details match creation request")

	// Update Assessment Profile
	updatedProfileName := fmt.Sprintf("%s-updated", profileName)
	updatedDescription := fmt.Sprintf("%s (Updated)", profileDescription)

	updateReq := types.UpdateAssessmentProfileRequest{
		ID:          profileID,
		ProfileName: updatedProfileName,
		Description: updatedDescription,
		Enabled:     "yes",
	}

	updateSuccess, err := client.UpdateAssessmentProfile(ctx, updateReq)
	require.NoError(t, err, "failed to update assessment profile")
	require.True(t, updateSuccess, "assessment profile update unsuccessful")

	t.Logf("Updated assessment profile: %s", profileID)

	// Verify update
	updatedProfile, err := client.GetAssessmentProfile(ctx, getReq)
	require.NoError(t, err, "failed to get updated assessment profile")
	require.NotNil(t, updatedProfile, "updated profile is nil")

	assert.Equal(t, profileID, updatedProfile.ID)
	assert.Equal(t, updatedProfileName, updatedProfile.Name)
	assert.Equal(t, updatedDescription, updatedProfile.Description)
	assert.True(t, updatedProfile.Enabled)

	t.Logf("Verified updated profile details")

	// Test List with filters
	listWithFilterReq := types.ListAssessmentProfilesRequest{
		Filters: []types.Filter{
			{
				Field:    "name",
				Operator: "contains",
				Value:    updatedProfileName,
			},
		},
		SearchFrom: util.ToPointer(0),
		SearchTo:   util.ToPointer(10),
	}

	filteredListResp, err := client.ListAssessmentProfiles(ctx, listWithFilterReq)
	require.NoError(t, err, "failed to list assessment profiles with filter")
	require.NotNil(t, filteredListResp, "filtered list response is nil")
	require.Greater(t, len(filteredListResp.AssessmentProfiles), 0, "no profiles found with filter")

	foundProfile := false
	for _, p := range filteredListResp.AssessmentProfiles {
		if p.ID == profileID {
			foundProfile = true
			assert.Equal(t, updatedProfileName, p.Name)
			break
		}
	}
	assert.True(t, foundProfile, "updated profile not found in filtered list")

	t.Logf("Successfully completed assessment profile lifecycle test")
}

func TestAccAssessmentProfileList(t *testing.T) {
	client := setupAcceptanceTest(t)
	ctx := context.Background()

	// Test basic list without filters
	listReq := types.ListAssessmentProfilesRequest{
		SearchFrom: util.ToPointer(0),
		SearchTo:   util.ToPointer(5),
	}

	listResp, err := client.ListAssessmentProfiles(ctx, listReq)
	require.NoError(t, err, "failed to list assessment profiles")
	require.NotNil(t, listResp, "list response is nil")

	t.Logf("Found %d total assessment profiles, returned %d", listResp.TotalCount, listResp.ResultCount)

	// Verify response structure
	assert.GreaterOrEqual(t, listResp.TotalCount, 0)
	assert.GreaterOrEqual(t, listResp.ResultCount, 0)
	assert.LessOrEqual(t, listResp.ResultCount, 5)

	// If there are profiles, verify their structure
	if len(listResp.AssessmentProfiles) > 0 {
		profile := listResp.AssessmentProfiles[0]
		assert.NotEmpty(t, profile.ID, "profile ID is empty")
		assert.NotEmpty(t, profile.Name, "profile name is empty")
		assert.NotZero(t, profile.InsertTS, "insert timestamp is zero")
		t.Logf("Sample profile: ID=%s, Name=%s", profile.ID, profile.Name)
	}
}

func TestAccAssessmentProfileSorting(t *testing.T) {
	client := setupAcceptanceTest(t)
	ctx := context.Background()

	// Test sorting by creation time descending
	listReq := types.ListAssessmentProfilesRequest{
		Sort: &types.SortFilter{
			Field:   "creation_time",
			Keyword: "desc",
		},
		SearchFrom: util.ToPointer(0),
		SearchTo:   util.ToPointer(10),
	}

	listResp, err := client.ListAssessmentProfiles(ctx, listReq)
	require.NoError(t, err, "failed to list assessment profiles with sorting")
	require.NotNil(t, listResp, "list response is nil")

	t.Logf("Retrieved %d profiles sorted by creation_time desc", listResp.ResultCount)

	// Verify sorting if we have multiple profiles
	if len(listResp.AssessmentProfiles) > 1 {
		for i := 0; i < len(listResp.AssessmentProfiles)-1; i++ {
			current := listResp.AssessmentProfiles[i]
			next := listResp.AssessmentProfiles[i+1]
			assert.GreaterOrEqual(t, current.InsertTS, next.InsertTS,
				"profiles not sorted correctly by creation_time desc")
		}
		t.Logf("Verified sorting order is correct")
	}
}
