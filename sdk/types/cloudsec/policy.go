// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package cloudsec

// PolicyCreateRequest represents the request body for creating a policy.
type PolicyCreateRequest struct {
	Name                      string          `json:"name"`
	Description               string          `json:"description,omitempty"`
	Labels                    []string        `json:"labels,omitempty"`
	RuleMatchingType          string          `json:"rule_matching_type"`
	AssociatedRuleFilter      *FilterCriteria `json:"associated_rule_filter,omitempty"`
	AssociatedRuleIDs         []string        `json:"associated_rule_ids,omitempty"`
	AssetMatchingType         string          `json:"asset_matching_type"`
	AssociatedAssetGroupIDs   []int32         `json:"associated_asset_group_ids,omitempty"`
	AssociatedCloudAccountIDs []string        `json:"associated_cloud_account_ids,omitempty"`
	Enabled                   *bool           `json:"enabled,omitempty"`
}

// PolicyUpdateRequest represents the request body for updating a policy.
// All fields are optional for partial updates.
type PolicyUpdateRequest struct {
	ID                        string          `json:"-"`
	Name                      string          `json:"name,omitempty"`
	Description               string          `json:"description,omitempty"`
	Labels                    []string        `json:"labels,omitempty"`
	RuleMatchingType          string          `json:"rule_matching_type,omitempty"`
	AssociatedRuleFilter      *FilterCriteria `json:"associated_rule_filter,omitempty"`
	AssociatedRuleIDs         []string        `json:"associated_rule_ids,omitempty"`
	AssetMatchingType         string          `json:"asset_matching_type,omitempty"`
	AssociatedAssetGroupIDs   []int32         `json:"associated_asset_group_ids,omitempty"`
	AssociatedCloudAccountIDs []string        `json:"associated_cloud_account_ids,omitempty"`
	Enabled                   *bool           `json:"enabled,omitempty"`
}

// PolicyResponse represents the response for policy operations.
// Response fields do not use omitempty as they are always present in API responses.
type PolicyResponse struct {
	ID                        string          `json:"id"`
	Name                      string          `json:"name"`
	Description               string          `json:"description"`
	Labels                    []string        `json:"labels"`
	RuleMatchingType          string          `json:"rule_matching_type"`
	AssociatedRuleFilter      *FilterCriteria `json:"associated_rule_filter"`
	AssociatedRuleIDs         []string        `json:"associated_rule_ids"`
	AssetMatchingType         string          `json:"asset_matching_type"`
	AssociatedAssetGroupIDs   []int32         `json:"associated_asset_group_ids"`
	AssociatedCloudAccountIDs []string        `json:"associated_cloud_account_ids"`
	Enabled                   bool            `json:"enabled"`
	Mode                      string          `json:"mode"`
	CreationTime              int64           `json:"creation_time"`
	CreatedBy                 string          `json:"created_by"`
	ModificationTime          int64           `json:"modification_time"`
	ModifiedBy                string          `json:"modified_by"`
}

// SearchPoliciesRequest represents the request body for searching policies.
type SearchPoliciesRequest struct {
	Filter     *FilterCriteria `json:"filter,omitempty"`
	SearchFrom int32           `json:"search_from,omitempty"`
	SearchTo   int32           `json:"search_to,omitempty"`
	Sort       []SortCriteria  `json:"sort,omitempty"`
}

// SearchPoliciesResponse represents the response for searching policies.
type SearchPoliciesResponse struct {
	Data     []PolicyResponse `json:"data"`
	Metadata SearchMetadata   `json:"metadata"`
}
