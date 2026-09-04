// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package cloudsec

import (
	"context"
	"net/http"

	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/internal/client"
	types "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/types/cloudsec"
)

// ---------------------------
// Request functions
// ---------------------------

// Create creates a new detection rule.
//
// This operation creates a new CSPM detection rule with the provided configuration.
// The rule must have a unique name, and all required fields must be provided.
//
// Required fields:
//   - Name: Unique rule name (max 255 chars)
//   - Class: Must be 'config' for CSPM rules
//   - AssetTypes: Array with exactly one asset type identifier
//   - Severity: One of: low, medium, high, critical, informational
//   - Query: XQL query definition
//
// Example:
//
//	rule, err := client.Create(ctx, types.CreateRuleRequest{
//	    Name:       "AWS S3 Bucket with Public Access",
//	    Class:      "config",
//	    AssetTypes: []string{"aws-s3-bucket"},
//	    Severity:   "high",
//	    Query: types.QueryRequest{
//	        XQL: "config from cloud.resource where cloud.type = 'aws' AND api.name = 'aws-s3api-get-bucket-acl'",
//	    },
//	})
func (c *Client) Create(ctx context.Context, input types.CreateRuleRequest) (types.RuleResponse, error) {
	var ans types.RuleResponse
	_, err := c.internalClient.Do(ctx, http.MethodPost, CreateRuleEndpoint, nil, nil, input, &ans, nil)

	return ans, err
}

// Get retrieves the details of a detection rule by its ID.
//
// Example:
//
//	rule, err := client.Get(ctx, "a1b2c3d4-e5f6-7890-abcd-ef1234567890")
func (c *Client) Get(ctx context.Context, id string) (types.RuleResponse, error) {
	var ans types.RuleResponse
	_, err := c.internalClient.Do(ctx, http.MethodGet, GetRuleEndpoint, &[]string{id}, nil, nil, &ans, nil)

	return ans, err
}

// Search retrieves detection rules that match the provided filter criteria.
//
// This operation supports complex filtering with AND/OR logic, pagination, and sorting.
// If no filter is provided, all rules will be returned (subject to pagination limits).
//
// Example with filter:
//
//	resp, err := client.Search(ctx, types.SearchRulesRequest{
//	    Filter: &types.FilterCriteria{
//	        OR: []types.FilterCriteria{
//	            {
//	                SearchField: "id",
//	                SearchType:  "EQ",
//	                SearchValue: "4f900112-eb70-490e-a867-63a31769a786",
//	            },
//	            {
//	                SearchField: "severity",
//	                SearchType:  "EQ",
//	                SearchValue: "critical",
//	            },
//	        },
//	    },
//	    SearchFrom: 0,
//	    SearchTo:   50,
//	    Sort: []types.SortCriteria{
//	        {Field: "name", Order: "ASC"},
//	    },
//	})
func (c *Client) Search(ctx context.Context, input types.SearchRulesRequest) (types.SearchRulesResponse, error) {
	var ans types.SearchRulesResponse
	_, err := c.internalClient.Do(ctx, http.MethodPost, SearchRulesEndpoint, nil, nil, input, &ans, nil)

	return ans, err
}

// Update modifies an existing detection rule.
//
// All fields in the UpdateRuleRequest are optional, allowing for partial updates.
// Only the fields that are provided will be updated.
//
// For system default rules, only certain fields (like labels) can be modified.
// For custom rules, all fields can be modified.
//
// Example:
//
//	rule, err := client.Update(ctx, "a1b2c3d4-e5f6-7890-abcd-ef1234567890", types.UpdateRuleRequest{
//	    Severity: "critical",
//	    Labels:   []string{"Updated", "Critical"},
//	})
func (c *Client) Update(ctx context.Context, id string, input types.UpdateRuleRequest) (types.RuleResponse, error) {
	var ans types.RuleResponse
	_, err := c.internalClient.Do(ctx, http.MethodPatch, UpdateRuleEndpoint, &[]string{id}, nil, input, &ans, nil)

	return ans, err
}

// Delete removes a detection rule by its ID.
//
// This operation permanently deletes the specified rule. System default rules
// cannot be deleted.
//
// Example:
//
//	err := client.Delete(ctx, "a1b2c3d4-e5f6-7890-abcd-ef1234567890")
func (c *Client) Delete(ctx context.Context, id string) error {
	_, err := c.internalClient.Do(ctx, http.MethodDelete, DeleteRuleEndpoint, &[]string{id}, nil, nil, nil, &client.DoOptions{})

	return err
}
