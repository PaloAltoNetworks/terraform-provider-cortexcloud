// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

//go:build acceptance

package cloudsec

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/enums"
	types "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/types/cloudsec"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

const (
	testAPIURLEnvVar     string = "CORTEXCLOUD_API_URL_TEST"
	testAPIKeyEnvVar     string = "CORTEXCLOUD_API_KEY_TEST"
	testAPIKeyIDEnvVar   string = "CORTEXCLOUD_API_KEY_ID_TEST"
	testAPIKeyTypeEnvVar string = "CORTEXCLOUD_API_KEY_TYPE_TEST"
)

func TestAccPolicy_CRUD(t *testing.T) {
	skipIfNotAcceptance(t)

	ctx := context.Background()
	client := setupAcceptanceTest(t)

	// Generate unique policy name
	policyName := fmt.Sprintf("test-policy-%d", time.Now().Unix())

	// Test Create
	t.Run("Create", func(t *testing.T) {
		enabled := true
		createReq := types.PolicyCreateRequest{
			Name:              policyName,
			Description:       "Test policy created by acceptance test",
			Labels:            []string{"test", "acceptance"},
			RuleMatchingType:  enums.RuleMatchingTypeAllRules.String(),
			AssetMatchingType: enums.AssetMatchingTypeAllAssets.String(),
			Enabled:           &enabled,
		}

		policy, err := client.CreatePolicy(ctx, createReq)
		if err != nil {
			t.Fatalf("Create failed: %v", err)
		}

		if policy.ID == "" {
			t.Error("Created policy has no ID")
		}
		if policy.Name != policyName {
			t.Errorf("Created policy name = %v, want %v", policy.Name, policyName)
		}
		if policy.RuleMatchingType != enums.RuleMatchingTypeAllRules.String() {
			t.Errorf("Created policy rule_matching_type = %v, want %v", policy.RuleMatchingType, enums.RuleMatchingTypeAllRules.String())
		}
		if policy.AssetMatchingType != enums.AssetMatchingTypeAllAssets.String() {
			t.Errorf("Created policy asset_matching_type = %v, want %v", policy.AssetMatchingType, enums.AssetMatchingTypeAllAssets.String())
		}
		if !policy.Enabled {
			t.Error("Created policy should be enabled")
		}

		// Store ID for subsequent tests
		policyID := policy.ID

		// Test Get
		t.Run("Get", func(t *testing.T) {
			retrieved, err := client.GetPolicy(ctx, policyID)
			if err != nil {
				t.Fatalf("Get failed: %v", err)
			}

			if retrieved.ID != policyID {
				t.Errorf("Retrieved policy ID = %v, want %v", retrieved.ID, policyID)
			}
			if retrieved.Name != policyName {
				t.Errorf("Retrieved policy name = %v, want %v", retrieved.Name, policyName)
			}
		})

		// Test Search
		t.Run("Search", func(t *testing.T) {
			searchReq := types.SearchPoliciesRequest{
				Filter: &types.FilterCriteria{
					AND: []types.FilterCriteria{
						{
							SearchField: "id",
							SearchType:  enums.SearchTypeEqualTo.String(),
							SearchValue: policyID,
						},
					},
				},
				SearchFrom: 0,
				SearchTo:   10,
			}

			results, err := client.SearchPolicies(ctx, searchReq)
			if err != nil {
				t.Fatalf("Search failed: %v", err)
			}

			if results.Metadata.FilterCount == 0 {
				t.Error("Search returned no results")
			}

			found := false
			for _, policy := range results.Data {
				if policy.ID == policyID {
					found = true
					break
				}
			}
			if !found {
				t.Error("Created policy not found in search results")
			}
		})

		// Test Update
		t.Run("Update", func(t *testing.T) {
			updateReq := types.PolicyUpdateRequest{
				ID:          policyID,
				Description: "Updated policy description",
				Labels:      []string{"test", "acceptance", "updated"},
			}

			updated, err := client.UpdatePolicy(ctx, updateReq)
			if err != nil {
				t.Fatalf("Update failed: %v", err)
			}

			if updated.Description != "Updated policy description" {
				t.Errorf("Updated policy description = %v, want %v", updated.Description, "Updated policy description")
			}
			if len(updated.Labels) != 3 {
				t.Errorf("Updated policy has %d labels, want 3", len(updated.Labels))
			}
		})

		// Test Delete
		t.Run("Delete", func(t *testing.T) {
			err := client.DeletePolicy(ctx, policyID)
			if err != nil {
				t.Fatalf("Delete failed: %v", err)
			}

			// Verify deletion by attempting to get the policy
			_, err = client.GetPolicy(ctx, policyID)
			if err == nil {
				t.Error("Expected error when getting deleted policy, got nil")
			}
		})
	})
}

func TestAccPolicy_CreateWithRuleFilter(t *testing.T) {
	skipIfNotAcceptance(t)

	ctx := context.Background()
	client := setupAcceptanceTest(t)

	policyName := fmt.Sprintf("test-policy-filter-%d", time.Now().Unix())
	enabled := true

	createReq := types.PolicyCreateRequest{
		Name:             policyName,
		Description:      "Test policy with rule filter",
		RuleMatchingType: enums.RuleMatchingTypeRuleFilter.String(),
		AssociatedRuleFilter: &types.FilterCriteria{
			AND: []types.FilterCriteria{
				{
					SearchField: "severity",
					SearchType:  enums.SearchTypeEqualTo.String(),
					SearchValue: enums.CloudSecSeverityHigh.String(),
				},
			},
		},
		AssetMatchingType: enums.AssetMatchingTypeAllAssets.String(),
		Enabled:           &enabled,
	}

	policy, err := client.CreatePolicy(ctx, createReq)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	defer func() {
		// Cleanup
		_ = client.DeletePolicy(ctx, policy.ID)
	}()

	if policy.RuleMatchingType != enums.RuleMatchingTypeRuleFilter.String() {
		t.Errorf("Policy rule_matching_type = %v, want %v", policy.RuleMatchingType, enums.RuleMatchingTypeRuleFilter.String())
	}
	if policy.AssociatedRuleFilter == nil {
		t.Error("Policy should have associated_rule_filter")
	}
}

func TestAccPolicy_CreateWithSpecificRules(t *testing.T) {
	skipIfNotAcceptance(t)

	ctx := context.Background()
	client := setupAcceptanceTest(t)

	// First, create a test rule to associate with the policy
	ruleName := fmt.Sprintf("test-rule-for-policy-%d", time.Now().Unix())
	ruleEnabled := true
	createRuleReq := types.CreateRuleRequest{
		Name:        ruleName,
		Description: "Test rule for policy association",
		Class:       enums.RuleClassConfig.String(),
		Type:        "DETECTION",
		AssetTypes:  []string{"S3_BUCKET"},
		Severity:    enums.CloudSecSeverityMedium.String(),
		Query: types.QueryRequest{
			XQL: "dataset = asset_inventory | filter xdm.asset.type.id = \"S3_BUCKET\" and xdm.asset.name = \"test-data\" | fields xdm.asset.id as asset_id, xdm.asset.name as asset_name, xdm.asset.type.id as asset_type_id",
		},
		Enabled: &ruleEnabled,
	}

	rule, err := client.Create(ctx, createRuleReq)
	if err != nil {
		t.Fatalf("Failed to create test rule: %v", err)
	}

	defer func() {
		// Cleanup rule
		_ = client.Delete(ctx, rule.ID)
	}()

	// Now create policy with specific rule
	policyName := fmt.Sprintf("test-policy-rules-%d", time.Now().Unix())
	policyEnabled := true

	createReq := types.PolicyCreateRequest{
		Name:              policyName,
		Description:       "Test policy with specific rules",
		RuleMatchingType:  enums.RuleMatchingTypeRules.String(),
		AssociatedRuleIDs: []string{rule.ID},
		AssetMatchingType: enums.AssetMatchingTypeAllAssets.String(),
		Enabled:           &policyEnabled,
	}

	policy, err := client.CreatePolicy(ctx, createReq)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	defer func() {
		// Cleanup policy
		_ = client.DeletePolicy(ctx, policy.ID)
	}()

	if policy.RuleMatchingType != enums.RuleMatchingTypeRules.String() {
		t.Errorf("Policy rule_matching_type = %v, want %v", policy.RuleMatchingType, enums.RuleMatchingTypeRules.String())
	}
	if len(policy.AssociatedRuleIDs) != 1 {
		t.Errorf("Policy has %d associated rules, want 1", len(policy.AssociatedRuleIDs))
	}
	if len(policy.AssociatedRuleIDs) > 0 && policy.AssociatedRuleIDs[0] != rule.ID {
		t.Errorf("Policy associated_rule_ids[0] = %v, want %v", policy.AssociatedRuleIDs[0], rule.ID)
	}
}

func TestAccPolicy_Search_Filters(t *testing.T) {
	skipIfNotAcceptance(t)

	ctx := context.Background()
	client := setupAcceptanceTest(t)

	t.Run("SearchWithORFilter", func(t *testing.T) {
		searchReq := types.SearchPoliciesRequest{
			Filter: &types.FilterCriteria{
				OR: []types.FilterCriteria{
					{
						SearchField: "rule_matching_type",
						SearchType:  enums.SearchTypeEqualTo.String(),
						SearchValue: enums.RuleMatchingTypeAllRules.String(),
					},
					{
						SearchField: "rule_matching_type",
						SearchType:  enums.SearchTypeEqualTo.String(),
						SearchValue: enums.RuleMatchingTypeRuleFilter.String(),
					},
				},
			},
			SearchFrom: 0,
			SearchTo:   50,
			Sort: []types.SortCriteria{
				{Field: "name", Order: enums.SortOrderASC.String()},
			},
		}

		results, err := client.SearchPolicies(ctx, searchReq)
		if err != nil {
			t.Fatalf("Search with OR filter failed: %v", err)
		}

		if results.Metadata.FilterCount == 0 {
			t.Log("No policies found with ALL_RULES or RULE_FILTER matching type (this may be expected)")
		}
	})

	t.Run("SearchWithANDFilter", func(t *testing.T) {
		searchReq := types.SearchPoliciesRequest{
			Filter: &types.FilterCriteria{
				AND: []types.FilterCriteria{
					{
						SearchField: "enabled",
						SearchType:  enums.SearchTypeEqualTo.String(),
						SearchValue: true,
					},
					{
						SearchField: "mode",
						SearchType:  enums.SearchTypeEqualTo.String(),
						SearchValue: enums.PolicyModeCustom.String(),
					},
				},
			},
			SearchFrom: 0,
			SearchTo:   50,
		}

		results, err := client.SearchPolicies(ctx, searchReq)
		if err != nil {
			t.Fatalf("Search with AND filter failed: %v", err)
		}

		t.Logf("Found %d custom enabled policies", results.Metadata.FilterCount)
	})

	t.Run("SearchByName", func(t *testing.T) {
		searchReq := types.SearchPoliciesRequest{
			Filter: &types.FilterCriteria{
				AND: []types.FilterCriteria{
					{
						SearchField: "name",
						SearchType:  enums.SearchTypeContains.String(),
						SearchValue: "test",
					},
				},
			},
			SearchFrom: 0,
			SearchTo:   50,
			Sort: []types.SortCriteria{
				{Field: "creation_time", Order: enums.SortOrderDESC.String()},
			},
		}

		results, err := client.SearchPolicies(ctx, searchReq)
		if err != nil {
			t.Fatalf("Search by name failed: %v", err)
		}

		t.Logf("Found %d policies with 'test' in name", results.Metadata.FilterCount)
	})

	t.Run("SearchEnabledPolicies", func(t *testing.T) {
		searchReq := types.SearchPoliciesRequest{
			Filter: &types.FilterCriteria{
				AND: []types.FilterCriteria{
					{
						SearchField: "enabled",
						SearchType:  enums.SearchTypeEqualTo.String(),
						SearchValue: true,
					},
				},
			},
			SearchFrom: 0,
			SearchTo:   100,
		}

		results, err := client.SearchPolicies(ctx, searchReq)
		if err != nil {
			t.Fatalf("Search enabled policies failed: %v", err)
		}

		t.Logf("Found %d enabled policies", results.Metadata.FilterCount)

		// Verify all returned policies are enabled
		for _, policy := range results.Data {
			if !policy.Enabled {
				t.Errorf("Policy %s is not enabled but was returned in enabled filter", policy.ID)
			}
		}
	})
}

func TestAccPolicy_UpdateRuleMatching(t *testing.T) {
	skipIfNotAcceptance(t)

	ctx := context.Background()
	client := setupAcceptanceTest(t)

	// Create initial policy with ALL_RULES
	policyName := fmt.Sprintf("test-policy-update-%d", time.Now().Unix())
	enabled := true

	createReq := types.PolicyCreateRequest{
		Name:              policyName,
		Description:       "Test policy for update",
		RuleMatchingType:  enums.RuleMatchingTypeAllRules.String(),
		AssetMatchingType: enums.AssetMatchingTypeAllAssets.String(),
		Enabled:           &enabled,
	}

	policy, err := client.CreatePolicy(ctx, createReq)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	defer func() {
		// Cleanup
		_ = client.DeletePolicy(ctx, policy.ID)
	}()

	// Update to use rule filter
	updateReq := types.PolicyUpdateRequest{
		ID:               policy.ID,
		RuleMatchingType: enums.RuleMatchingTypeRuleFilter.String(),
		AssociatedRuleFilter: &types.FilterCriteria{
			AND: []types.FilterCriteria{
				{
					SearchField: "severity",
					SearchType:  enums.SearchTypeEqualTo.String(),
					SearchValue: enums.CloudSecSeverityCritical.String(),
				},
			},
		},
	}

	updated, err := client.UpdatePolicy(ctx, updateReq)
	if err != nil {
		t.Fatalf("Update failed: %v", err)
	}

	if updated.RuleMatchingType != enums.RuleMatchingTypeRuleFilter.String() {
		t.Errorf("Updated policy rule_matching_type = %v, want %v", updated.RuleMatchingType, enums.RuleMatchingTypeRuleFilter.String())
	}
	if updated.AssociatedRuleFilter == nil {
		t.Error("Updated policy should have associated_rule_filter")
	}
}

func TestAccPolicy_Pagination(t *testing.T) {
	skipIfNotAcceptance(t)

	ctx := context.Background()
	client := setupAcceptanceTest(t)

	// Test pagination with different page sizes
	t.Run("SmallPageSize", func(t *testing.T) {
		searchReq := types.SearchPoliciesRequest{
			SearchFrom: 0,
			SearchTo:   5,
			Sort: []types.SortCriteria{
				{Field: "name", Order: enums.SortOrderASC.String()},
			},
		}

		results, err := client.SearchPolicies(ctx, searchReq)
		if err != nil {
			t.Fatalf("Search failed: %v", err)
		}

		if len(results.Data) > 5 {
			t.Errorf("Expected at most 5 results, got %d", len(results.Data))
		}

		t.Logf("Page 1: Retrieved %d policies out of %d total", len(results.Data), results.Metadata.TotalCount)
	})

	t.Run("SecondPage", func(t *testing.T) {
		searchReq := types.SearchPoliciesRequest{
			SearchFrom: 5,
			SearchTo:   10,
			Sort: []types.SortCriteria{
				{Field: "name", Order: enums.SortOrderASC.String()},
			},
		}

		results, err := client.SearchPolicies(ctx, searchReq)
		if err != nil {
			t.Fatalf("Search failed: %v", err)
		}

		t.Logf("Page 2: Retrieved %d policies", len(results.Data))
	})
}

// TestAccPolicy_CreateDisabledBugDetection tests for the known bug where
// the enabled field is ignored during policy creation. This test should FAIL when
// the bug is fixed and the workaround in the Create() function of the
// Terraform resource is no longer needed.
func TestAccPolicy_CreateDisabledBugDetection(t *testing.T) {
	skipIfNotAcceptance(t)

	ctx := context.Background()
	client := setupAcceptanceTest(t)

	// Create initial policy with ALL_RULES
	policyName := fmt.Sprintf("test-policy-create-disabled-bug-%d", time.Now().Unix())
	enabled := false

	createReq := types.PolicyCreateRequest{
		Name:              policyName,
		Description:       "Test policy for the enabled field bug",
		RuleMatchingType:  enums.RuleMatchingTypeAllRules.String(),
		AssetMatchingType: enums.AssetMatchingTypeAllAssets.String(),
		Enabled:           &enabled,
	}

	createdPolicy, err := client.CreatePolicy(ctx, createReq)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	defer func() {
		err := client.DeletePolicy(ctx, createdPolicy.ID)
		if err != nil {
			t.Fatalf("Delete callback failed: %v", err)
		}
	}()

	policy, err := client.GetPolicy(ctx, createdPolicy.ID)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	require.True(t, policy.Enabled, "policy should be created in the enabled state -- check if the upstream API bug has been fixed!")
}
