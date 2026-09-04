// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package cloudsec

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/enums"
	types "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/types/cloudsec"
)

func TestPolicyCreateRequest_Validation(t *testing.T) {
	tests := []struct {
		name    string
		request types.PolicyCreateRequest
		wantErr bool
	}{
		{
			name: "valid request with ALL_RULES and ALL_ASSETS",
			request: types.PolicyCreateRequest{
				Name:              "Test Policy",
				Description:       "Test policy description",
				RuleMatchingType:  enums.RuleMatchingTypeAllRules.String(),
				AssetMatchingType: enums.AssetMatchingTypeAllAssets.String(),
			},
			wantErr: false,
		},
		{
			name: "valid request with RULES matching type",
			request: types.PolicyCreateRequest{
				Name:              "Test Policy with Rules",
				RuleMatchingType:  enums.RuleMatchingTypeRules.String(),
				AssociatedRuleIDs: []string{"rule-id-1", "rule-id-2"},
				AssetMatchingType: enums.AssetMatchingTypeAllAssets.String(),
			},
			wantErr: false,
		},
		{
			name: "valid request with RULE_FILTER matching type",
			request: types.PolicyCreateRequest{
				Name:             "Test Policy with Filter",
				RuleMatchingType: enums.RuleMatchingTypeRuleFilter.String(),
				AssociatedRuleFilter: &types.FilterCriteria{
					SearchField: "severity",
					SearchType:  enums.SearchTypeEqualTo.String(),
					SearchValue: enums.CloudSecSeverityHigh.String(),
				},
				AssetMatchingType: enums.AssetMatchingTypeAllAssets.String(),
			},
			wantErr: false,
		},
		{
			name: "valid request with ASSET_GROUPS matching type",
			request: types.PolicyCreateRequest{
				Name:                    "Test Policy with Asset Groups",
				RuleMatchingType:        enums.RuleMatchingTypeAllRules.String(),
				AssetMatchingType:       enums.AssetMatchingTypeAssetGroups.String(),
				AssociatedAssetGroupIDs: []int32{1, 2, 3},
			},
			wantErr: false,
		},
		{
			name: "valid request with CLOUD_ACCOUNTS matching type",
			request: types.PolicyCreateRequest{
				Name:                      "Test Policy with Cloud Accounts",
				RuleMatchingType:          enums.RuleMatchingTypeAllRules.String(),
				AssetMatchingType:         enums.AssetMatchingTypeCloudAccounts.String(),
				AssociatedCloudAccountIDs: []string{"account-1", "account-2"},
			},
			wantErr: false,
		},
		{
			name: "request with labels and enabled flag",
			request: types.PolicyCreateRequest{
				Name:              "Test Policy with Metadata",
				Description:       "Policy with additional metadata",
				Labels:            []string{"production", "critical"},
				RuleMatchingType:  enums.RuleMatchingTypeAllRules.String(),
				AssetMatchingType: enums.AssetMatchingTypeAllAssets.String(),
				Enabled:           boolPtr(true),
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Basic validation checks
			if tt.request.Name == "" && !tt.wantErr {
				t.Error("Expected name to be set")
			}
			if tt.request.RuleMatchingType == "" && !tt.wantErr {
				t.Error("Expected rule_matching_type to be set")
			}
			if tt.request.AssetMatchingType == "" && !tt.wantErr {
				t.Error("Expected asset_matching_type to be set")
			}

			// Validate conditional requirements
			if tt.request.RuleMatchingType == enums.RuleMatchingTypeRules.String() {
				if len(tt.request.AssociatedRuleIDs) == 0 && !tt.wantErr {
					t.Error("Expected associated_rule_ids when rule_matching_type is RULES")
				}
			}
			if tt.request.RuleMatchingType == enums.RuleMatchingTypeRuleFilter.String() {
				if tt.request.AssociatedRuleFilter == nil && !tt.wantErr {
					t.Error("Expected associated_rule_filter when rule_matching_type is RULE_FILTER")
				}
			}
			if tt.request.AssetMatchingType == enums.AssetMatchingTypeAssetGroups.String() {
				if len(tt.request.AssociatedAssetGroupIDs) == 0 && !tt.wantErr {
					t.Error("Expected associated_asset_group_ids when asset_matching_type is ASSET_GROUPS")
				}
			}
			if tt.request.AssetMatchingType == enums.AssetMatchingTypeCloudAccounts.String() {
				if len(tt.request.AssociatedCloudAccountIDs) == 0 && !tt.wantErr {
					t.Error("Expected associated_cloud_account_ids when asset_matching_type is CLOUD_ACCOUNTS")
				}
			}
		})
	}
}

func TestPolicyUpdateRequest_Structure(t *testing.T) {
	tests := []struct {
		name    string
		request types.PolicyUpdateRequest
	}{
		{
			name: "update with ID and description",
			request: types.PolicyUpdateRequest{
				ID:          "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
				Description: "Updated description",
			},
		},
		{
			name: "update name and description",
			request: types.PolicyUpdateRequest{
				Name:        "Updated Policy Name",
				Description: "Updated description",
			},
		},
		{
			name: "update labels",
			request: types.PolicyUpdateRequest{
				Labels: []string{"updated", "test"},
			},
		},
		{
			name: "update rule matching to specific rules",
			request: types.PolicyUpdateRequest{
				RuleMatchingType:  enums.RuleMatchingTypeRules.String(),
				AssociatedRuleIDs: []string{"new-rule-1", "new-rule-2"},
			},
		},
		{
			name: "update asset matching to asset groups",
			request: types.PolicyUpdateRequest{
				AssetMatchingType:       enums.AssetMatchingTypeAssetGroups.String(),
				AssociatedAssetGroupIDs: []int32{10, 20},
			},
		},
		{
			name: "update enabled status",
			request: types.PolicyUpdateRequest{
				Enabled: boolPtr(false),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Verify that at least one field is set for update
			hasUpdate := tt.request.ID != "" ||
				tt.request.Name != "" ||
				tt.request.Description != "" ||
				len(tt.request.Labels) > 0 ||
				tt.request.RuleMatchingType != "" ||
				tt.request.AssetMatchingType != "" ||
				tt.request.Enabled != nil

			if !hasUpdate {
				t.Error("Update request should have at least one field set")
			}
		})
	}
}

func TestPolicyUpdateRequest_IDExcludedFromJSON(t *testing.T) {
	req := types.PolicyUpdateRequest{
		ID:          "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
		Description: "Updated description",
		Labels:      []string{"test"},
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Failed to marshal PolicyUpdateRequest: %v", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("Failed to unmarshal JSON: %v", err)
	}

	// ID should NOT be present in JSON output (json:"-" tag)
	if _, exists := raw["id"]; exists {
		t.Error("ID field should be excluded from JSON serialization (json:\"-\" tag)")
	}

	// Other fields should be present
	if _, exists := raw["description"]; !exists {
		t.Error("Description field should be present in JSON output")
	}
	if _, exists := raw["labels"]; !exists {
		t.Error("Labels field should be present in JSON output")
	}
}

func TestUpdatePolicy_EmptyIDReturnsError(t *testing.T) {
	client, server := setupTest(t, func(w http.ResponseWriter, r *http.Request) {
		// This handler should never be reached — validation should fail first
		t.Error("HTTP request should not be made when ID is empty")
		w.WriteHeader(http.StatusOK)
	})
	defer server.Close()

	req := types.PolicyUpdateRequest{
		// ID intentionally left empty
		Description: "Updated description",
	}

	_, err := client.UpdatePolicy(context.Background(), req)
	if err == nil {
		t.Fatal("Expected error when calling UpdatePolicy with empty ID, got nil")
	}

	expectedMsg := "policy ID is required for update"
	if err.Error() != expectedMsg {
		t.Errorf("Error message = %q, want %q", err.Error(), expectedMsg)
	}
}

func TestSearchPoliciesRequest_Filters(t *testing.T) {
	tests := []struct {
		name   string
		filter types.FilterCriteria
	}{
		{
			name: "simple EQ filter on name",
			filter: types.FilterCriteria{
				SearchField: "name",
				SearchType:  enums.SearchTypeEqualTo.String(),
				SearchValue: "My Policy",
			},
		},
		{
			name: "CONTAINS filter on description",
			filter: types.FilterCriteria{
				SearchField: "description",
				SearchType:  enums.SearchTypeContains.String(),
				SearchValue: "security",
			},
		},
		{
			name: "OR filter for enabled policies",
			filter: types.FilterCriteria{
				OR: []types.FilterCriteria{
					{
						SearchField: "enabled",
						SearchType:  enums.SearchTypeEqualTo.String(),
						SearchValue: true,
					},
					{
						SearchField: "mode",
						SearchType:  enums.SearchTypeEqualTo.String(),
						SearchValue: enums.PolicyModeDefault.String(),
					},
				},
			},
		},
		{
			name: "AND filter for custom enabled policies",
			filter: types.FilterCriteria{
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
		},
		{
			name: "complex nested filter",
			filter: types.FilterCriteria{
				AND: []types.FilterCriteria{
					{
						SearchField: "enabled",
						SearchType:  enums.SearchTypeEqualTo.String(),
						SearchValue: true,
					},
					{
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
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Verify filter structure is valid
			if tt.filter.SearchField == "" && len(tt.filter.AND) == 0 && len(tt.filter.OR) == 0 {
				t.Error("Filter must have either SearchField or AND/OR criteria")
			}
		})
	}
}

func TestSearchPoliciesRequest_Pagination(t *testing.T) {
	request := types.SearchPoliciesRequest{
		SearchFrom: 0,
		SearchTo:   50,
		Sort: []types.SortCriteria{
			{Field: "name", Order: enums.SortOrderASC.String()},
		},
	}

	if request.SearchFrom < 0 {
		t.Error("SearchFrom should not be negative")
	}
	if request.SearchTo <= request.SearchFrom {
		t.Error("SearchTo should be greater than SearchFrom")
	}
	if len(request.Sort) > 0 && request.Sort[0].Field == "" {
		t.Error("Sort field should not be empty")
	}
}

func TestSearchPoliciesRequest_Sorting(t *testing.T) {
	tests := []struct {
		name string
		sort []types.SortCriteria
	}{
		{
			name: "sort by name ascending",
			sort: []types.SortCriteria{
				{Field: "name", Order: enums.SortOrderASC.String()},
			},
		},
		{
			name: "sort by creation_time descending",
			sort: []types.SortCriteria{
				{Field: "creation_time", Order: enums.SortOrderDESC.String()},
			},
		},
		{
			name: "multiple sort criteria",
			sort: []types.SortCriteria{
				{Field: "enabled", Order: enums.SortOrderDESC.String()},
				{Field: "name", Order: enums.SortOrderASC.String()},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, sortCriteria := range tt.sort {
				if sortCriteria.Field == "" {
					t.Error("Sort field should not be empty")
				}
				if sortCriteria.Order == "" {
					t.Error("Sort order should not be empty")
				}
			}
		})
	}
}

// Helper function to create a bool pointer
func boolPtr(b bool) *bool {
	return &b
}
