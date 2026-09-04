// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

//go:build acceptance

package cwp

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"testing"
	"time"

	types "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/types/cwp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Environment variable names
const (
	envTestCortexAPIURL     = "TEST_CORTEX_API_URL"
	envTestCortexAPIKey     = "TEST_CORTEX_API_KEY"
	envTestCortexAPIKeyID   = "TEST_CORTEX_API_KEY_ID"
	envTestCortexAPIKeyType = "TEST_CORTEX_API_KEY_TYPE"
)

// Default values
const (
	defaultAPIKeyType = "standard"
	defaultLogLevel   = "debug"
)

// Test policy configuration
const (
	testPolicyType            = "COMPLIANCE"
	testPolicyDescription     = "SDK acceptance test CWP policy"
	testPolicyEvaluationStage = "RUNTIME"
	testRemediationGuidance   = "Test remediation guidance"
	testRuleID                = "00000000-0000-0000-0000-000000300419"
	testRuleName              = "test-rule-1"
	testRuleAction            = "ISSUE"
	testRuleSeverity          = "MEDIUM"
	testAssetGroupID          = 26
)

// Test policy update configuration
const (
	updatedRuleAction          = "PREVENT"
	updatedRuleSeverity        = "HIGH"
	updatedRemediationGuidance = "Updated remediation guidance"
	updatedPolicyDescription   = "Updated SDK acceptance test CWP policy"
	updatedNameSuffix          = "-Updated"
)

// Test configuration variables
var (
	testPolicyDisabled      = false
	testRuleUserGuidance    = ""
	testAssetGroupIDs       = []int{testAssetGroupID}
	updatedPolicyDisabled   = true
	testPolicyTypes         = []string{testPolicyType}
	testMultiplePolicyTypes = []string{testPolicyType, "MALWARE"}
	testPolicyNameTemplate  = "SDK-Test-CWP-Policy-%d"
)

// Skip messages
const (
	skipMessageEnvVars = "Skipping acceptance test: TEST_CORTEX_API_URL, TEST_CORTEX_API_KEY, and TEST_CORTEX_API_KEY_ID must be set"
	errorMessageKeyID  = "TEST_CORTEX_API_KEY_ID must be a valid integer"
)

// TestAccPolicy_FullLifecycle tests the complete CRUD lifecycle of a CWP policy.
//
// This test requires valid API credentials set in environment variables with TEST_ prefix:
// - TEST_CORTEX_API_URL
// - TEST_CORTEX_API_KEY
// - TEST_CORTEX_API_KEY_ID
// - TEST_CORTEX_API_KEY_TYPE (optional, defaults to "standard")
func TestAccPolicy_FullLifecycle(t *testing.T) {
	// Check for required environment variables
	apiURL := os.Getenv(envTestCortexAPIURL)
	apiKey := os.Getenv(envTestCortexAPIKey)
	apiKeyIDStr := os.Getenv(envTestCortexAPIKeyID)

	if apiURL == "" || apiKey == "" || apiKeyIDStr == "" {
		t.Skip(skipMessageEnvVars)
	}

	// Convert API key ID to int
	apiKeyID, err := strconv.Atoi(apiKeyIDStr)
	require.NoError(t, err, errorMessageKeyID)

	// Get API key type (default to standard if not set)
	apiKeyType := os.Getenv(envTestCortexAPIKeyType)
	if apiKeyType == "" {
		apiKeyType = defaultAPIKeyType
	}

	// Create client
	client, err := NewClient(
		WithCortexAPIURL(apiURL),
		WithCortexAPIKey(apiKey),
		WithCortexAPIKeyID(apiKeyID),
		WithCortexAPIKeyType(apiKeyType),
		WithLogLevel(defaultLogLevel),
	)
	require.NoError(t, err)
	require.NotNil(t, client)

	ctx := context.Background()
	timestamp := time.Now().Unix()
	policyName := fmt.Sprintf(testPolicyNameTemplate, timestamp)

	var policyID string

	// Step 1: Create Policy
	t.Run("Create", func(t *testing.T) {
		createReq := types.CreateOrUpdatePolicyRequest{
			Type:            testPolicyType,
			Name:            policyName,
			Description:     testPolicyDescription,
			Disabled:        testPolicyDisabled,
			EvaluationStage: testPolicyEvaluationStage,
			PolicyRules: []types.PolicyRule{
				{
					RuleID:   testRuleID,
					Action:   testRuleAction,
					Severity: testRuleSeverity,
				},
			},
			AssetGroupIDs:       testAssetGroupIDs,
			RemediationGuidance: testRemediationGuidance,
		}

		resp, err := client.CreatePolicy(ctx, createReq)
		require.NoError(t, err)
		require.NotNil(t, resp)
		assert.NotEmpty(t, resp.PolicyID)

		policyID = resp.PolicyID
		t.Logf("Created policy with ID: %s", policyID)
	})

	// Step 2: Get Policy
	t.Run("Get", func(t *testing.T) {
		require.NotEmpty(t, policyID, "Policy ID must be set from Create step")

		policy, err := client.GetPolicyByID(ctx, policyID)
		require.NoError(t, err)
		require.NotNil(t, policy)

		assert.Equal(t, policyID, policy.ID)
		assert.Equal(t, policyName, policy.Name)
		assert.Equal(t, testPolicyDescription, policy.Description)
		assert.Equal(t, testPolicyType, policy.Type)
		assert.Equal(t, testPolicyEvaluationStage, policy.EvaluationStage)
		assert.Equal(t, testRuleAction, policy.PolicyAction)
		assert.Equal(t, testRuleSeverity, policy.PolicySeverity)
		assert.False(t, policy.Disabled)
		assert.NotEmpty(t, policy.PolicyRules)
		assert.NotEmpty(t, policy.AssetGroupIDs)

		t.Logf("Retrieved policy: %s", policy.Name)
	})

	// Step 3: List All Policies
	t.Run("List_All", func(t *testing.T) {
		policies, err := client.ListPolicies(ctx, nil)
		require.NoError(t, err)
		require.NotEmpty(t, policies)

		// Verify our policy is in the list
		found := false
		for _, p := range policies {
			if p.ID == policyID {
				found = true
				assert.Equal(t, policyName, p.Name)
				break
			}
		}
		assert.True(t, found, "Created policy should be in the list")

		t.Logf("Listed %d total policies", len(policies))
	})

	// Step 4: List Filtered Policies
	t.Run("List_Filtered", func(t *testing.T) {
		// List only COMPLIANCE policies
		policies, err := client.ListPolicies(ctx, testPolicyTypes)
		require.NoError(t, err)
		require.NotEmpty(t, policies)

		// All returned policies should be COMPLIANCE type
		for _, p := range policies {
			assert.Equal(t, testPolicyType, p.Type)
		}

		t.Logf("Listed %d %s policies", len(policies), testPolicyType)
	})

	// Step 5: Update Policy
	t.Run("Update", func(t *testing.T) {
		require.NotEmpty(t, policyID, "Policy ID must be set from Create step")

		// Fetch the previously-created policy
		currentPolicy, err := client.GetPolicyByID(ctx, policyID)
		require.NoError(t, err)

		updateReq := currentPolicy.ToCreateOrUpdateRequest(true)

		// Update appropriate fields
		updatedName := fmt.Sprintf("%s%s", policyName, updatedNameSuffix)

		updateReq.Name = updatedName
		updateReq.Description = updatedPolicyDescription
		updateReq.Disabled = updatedPolicyDisabled
		updateReq.RemediationGuidance = updatedRemediationGuidance

		updateReq.PolicyRules[0].Action = updatedRuleAction
		updateReq.PolicyRules[0].Severity = updatedRuleSeverity

		err = client.UpdatePolicy(ctx, policyID, updateReq)
		require.NoError(t, err)

		// Verify the update
		policy, err := client.GetPolicyByID(ctx, policyID)
		require.NoError(t, err)
		assert.Equal(t, updatedName, policy.Name)
		assert.Equal(t, updatedPolicyDescription, policy.Description)
		assert.Equal(t, updatedRuleAction, policy.PolicyAction)
		assert.Equal(t, updatedRuleSeverity, policy.PolicySeverity)
		assert.Equal(t, updatedRemediationGuidance, policy.RemediationGuidance)

		t.Logf("Updated policy: %s (action=%s, severity=%s)", policy.Name, policy.PolicyAction, policy.PolicySeverity)
	})

	// Step 6: Delete Policy
	t.Run("Delete", func(t *testing.T) {
		require.NotEmpty(t, policyID, "Policy ID must be set from Create step")

		err := client.DeletePolicy(ctx, policyID, false)
		require.NoError(t, err)

		t.Logf("Deleted policy with ID: %s", policyID)

		// Verify deletion - GetPolicy should fail
		_, err = client.GetPolicyByID(ctx, policyID)
		assert.Error(t, err, "Getting deleted policy should return an error")
	})
}

// TestAccPolicy_ListByType tests listing policies filtered by type.
func TestAccPolicy_ListByType(t *testing.T) {
	apiURL := os.Getenv(envTestCortexAPIURL)
	apiKey := os.Getenv(envTestCortexAPIKey)
	apiKeyIDStr := os.Getenv(envTestCortexAPIKeyID)

	if apiURL == "" || apiKey == "" || apiKeyIDStr == "" {
		t.Skip(skipMessageEnvVars)
	}

	apiKeyID, err := strconv.Atoi(apiKeyIDStr)
	require.NoError(t, err)

	apiKeyType := os.Getenv(envTestCortexAPIKeyType)
	if apiKeyType == "" {
		apiKeyType = defaultAPIKeyType
	}

	client, err := NewClient(
		WithCortexAPIURL(apiURL),
		WithCortexAPIKey(apiKey),
		WithCortexAPIKeyID(apiKeyID),
		WithCortexAPIKeyType(apiKeyType),
	)
	require.NoError(t, err)

	ctx := context.Background()

	t.Run("List COMPLIANCE policies", func(t *testing.T) {
		policies, err := client.ListPolicies(ctx, testPolicyTypes)
		require.NoError(t, err)

		// Verify all returned policies are COMPLIANCE type
		for _, p := range policies {
			assert.Equal(t, testPolicyType, p.Type)
		}

		t.Logf("Found %d %s policies", len(policies), testPolicyType)
	})

	t.Run("List multiple types", func(t *testing.T) {
		policies, err := client.ListPolicies(ctx, testMultiplePolicyTypes)
		require.NoError(t, err)

		// Verify all returned policies are either COMPLIANCE or MALWARE
		for _, p := range policies {
			assert.Contains(t, testMultiplePolicyTypes, p.Type)
		}

		t.Logf("Found %d COMPLIANCE/MALWARE policies", len(policies))
	})
}

// TestAccPolicy_DisabledFieldMismatch tests that setting disabled=true in Create/Update
// results in disabled=false when fetching the policy.
func TestAccPolicy_DisabledFieldMismatch(t *testing.T) {
	apiURL := os.Getenv(envTestCortexAPIURL)
	apiKey := os.Getenv(envTestCortexAPIKey)
	apiKeyIDStr := os.Getenv(envTestCortexAPIKeyID)

	if apiURL == "" || apiKey == "" || apiKeyIDStr == "" {
		t.Skip(skipMessageEnvVars)
	}

	apiKeyID, err := strconv.Atoi(apiKeyIDStr)
	require.NoError(t, err, errorMessageKeyID)

	apiKeyType := os.Getenv(envTestCortexAPIKeyType)
	if apiKeyType == "" {
		apiKeyType = defaultAPIKeyType
	}

	client, err := NewClient(
		WithCortexAPIURL(apiURL),
		WithCortexAPIKey(apiKey),
		WithCortexAPIKeyID(apiKeyID),
		WithCortexAPIKeyType(apiKeyType),
		WithLogLevel(defaultLogLevel),
	)
	require.NoError(t, err)

	ctx := context.Background()
	timestamp := time.Now().Unix()
	policyName := fmt.Sprintf("SDK-Test-CWP-Disabled-Mismatch-%d", timestamp)

	var policyID string

	t.Run("Create with disabled=true", func(t *testing.T) {
		createReq := types.CreateOrUpdatePolicyRequest{
			Type:            testPolicyType,
			Name:            policyName,
			Description:     testPolicyDescription,
			Disabled:        true,
			EvaluationStage: testPolicyEvaluationStage,
			PolicyRules: []types.PolicyRule{
				{
					RuleID:   testRuleID,
					Action:   testRuleAction,
					Severity: testRuleSeverity,
				},
			},
			AssetGroupIDs:       testAssetGroupIDs,
			RemediationGuidance: testRemediationGuidance,
		}

		resp, err := client.CreatePolicy(ctx, createReq)
		require.NoError(t, err)
		require.NotNil(t, resp)
		policyID = resp.PolicyID

		policy, err := client.GetPolicyByID(ctx, policyID)
		require.NoError(t, err)
		assert.False(t, policy.Disabled, "Expected disabled to be false even though it was set to true in Create. Re-assess the upstream API to see if this field is now user-configurable, and remove this test if it is.")
	})

	t.Run("Update with disabled=true", func(t *testing.T) {
		require.NotEmpty(t, policyID)

		currentPolicy, err := client.GetPolicyByID(ctx, policyID)
		require.NoError(t, err)

		updateReq := currentPolicy.ToCreateOrUpdateRequest(true)
		updateReq.Disabled = true

		err = client.UpdatePolicy(ctx, policyID, updateReq)
		require.NoError(t, err)

		policy, err := client.GetPolicyByID(ctx, policyID)
		require.NoError(t, err)
		assert.False(t, policy.Disabled, "Expected disabled to be false even though it was set to true in Update. Re-assess the upstream API to see if this field is now user-configurable, and remove this test if it is.")
	})

	t.Run("Cleanup", func(t *testing.T) {
		if policyID != "" {
			err := client.DeletePolicy(ctx, policyID, false)
			require.NoError(t, err)
		}
	})
}
