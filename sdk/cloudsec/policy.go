// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package cloudsec

import (
	"context"
	"fmt"
	"net/http"

	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/internal/client"
	types "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/types/cloudsec"
)

// ---------------------------
// Policy Request functions
// ---------------------------

// CreatePolicy creates a new policy.
//
// This operation creates a new CloudSec policy with the provided configuration.
// The policy must have a unique name, and all required fields must be provided.
//
// Required fields:
//   - Name: Unique policy name
//   - RuleMatchingType: One of: ALL_RULES, RULES, RULE_FILTER
//   - AssetMatchingType: One of: ALL_ASSETS, ASSET_GROUPS, CLOUD_ACCOUNTS
//
// Conditional requirements:
//   - If RuleMatchingType is RULE_FILTER: AssociatedRuleFilter is required
//   - If RuleMatchingType is RULES: AssociatedRuleIDs is required
//   - If AssetMatchingType is ASSET_GROUPS: AssociatedAssetGroupIDs is required
//   - If AssetMatchingType is CLOUD_ACCOUNTS: AssociatedCloudAccountIDs is required
//
// Example:
//
//	policy, err := client.CreatePolicy(ctx, types.PolicyCreateRequest{
//	    Name:              "My Security Policy",
//	    Description:       "Policy for critical security rules",
//	    RuleMatchingType:  "RULES",
//	    AssociatedRuleIDs: []string{"rule-id-1", "rule-id-2"},
//	    AssetMatchingType: "ALL_ASSETS",
//	})
func (c *Client) CreatePolicy(ctx context.Context, input types.PolicyCreateRequest) (types.PolicyResponse, error) {
	var ans types.PolicyResponse
	_, err := c.internalClient.Do(ctx, http.MethodPost, CreatePolicyEndpoint, nil, nil, input, &ans, &client.DoOptions{})

	return ans, err
}

// GetPolicy retrieves the details of a policy by its ID.
//
// Example:
//
//	policy, err := client.GetPolicy(ctx, "a1b2c3d4-e5f6-7890-abcd-ef1234567890")
func (c *Client) GetPolicy(ctx context.Context, id string) (types.PolicyResponse, error) {
	var ans types.PolicyResponse
	_, err := c.internalClient.Do(ctx, http.MethodGet, GetPolicyEndpoint, &[]string{id}, nil, nil, &ans, &client.DoOptions{})

	return ans, err
}

// SearchPolicies retrieves policies that match the provided filter criteria.
//
// This operation supports complex filtering with AND/OR logic, pagination, and sorting.
// If no filter is provided, all policies will be returned (subject to pagination limits).
//
// Example with filter:
//
//	resp, err := client.SearchPolicies(ctx, types.SearchPoliciesRequest{
//	    Filter: &types.FilterCriteria{
//	        AND: []types.FilterCriteria{
//	            {
//	                SearchField: "name",
//	                SearchType:  "CONTAINS",
//	                SearchValue: "Security",
//	            },
//	            {
//	                SearchField: "enabled",
//	                SearchType:  "EQ",
//	                SearchValue: true,
//	            },
//	        },
//	    },
//	    SearchFrom: 0,
//	    SearchTo:   50,
//	    Sort: []types.SortCriteria{
//	        {Field: "name", Order: "ASC"},
//	    },
//	})
func (c *Client) SearchPolicies(ctx context.Context, input types.SearchPoliciesRequest) (types.SearchPoliciesResponse, error) {
	var ans types.SearchPoliciesResponse
	_, err := c.internalClient.Do(ctx, http.MethodPost, SearchPoliciesEndpoint, nil, nil, input, &ans, &client.DoOptions{})

	return ans, err
}

// UpdatePolicy modifies an existing policy.
//
// All fields in the PolicyUpdateRequest are optional, allowing for partial updates.
// Only the fields that are provided will be updated.
// The ID field must be set to identify which policy to update.
//
// For system default policies, only certain fields (like labels) can be modified.
// For custom policies, all fields can be modified.
//
// Example:
//
//	policy, err := client.UpdatePolicy(ctx, types.PolicyUpdateRequest{
//	    ID:          "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
//	    Description: "Updated policy description",
//	    Labels:      []string{"Updated", "Production"},
//	})
func (c *Client) UpdatePolicy(ctx context.Context, input types.PolicyUpdateRequest) (types.PolicyResponse, error) {
	if input.ID == "" {
		return types.PolicyResponse{}, fmt.Errorf("policy ID is required for update")
	}

	var ans types.PolicyResponse
	_, err := c.internalClient.Do(ctx, http.MethodPatch, UpdatePolicyEndpoint, &[]string{input.ID}, nil, input, &ans, &client.DoOptions{})

	return ans, err
}

// DeletePolicy removes a policy by its ID.
//
// This operation permanently deletes the specified policy. System default policies
// cannot be deleted.
//
// Example:
//
//	err := client.DeletePolicy(ctx, "a1b2c3d4-e5f6-7890-abcd-ef1234567890")
func (c *Client) DeletePolicy(ctx context.Context, id string) error {
	_, err := c.internalClient.Do(ctx, http.MethodDelete, DeletePolicyEndpoint, &[]string{id}, nil, nil, nil, &client.DoOptions{})

	return err
}
