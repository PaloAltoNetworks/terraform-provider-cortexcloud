// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package cwp

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"

	types "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/types/cwp"
	convert "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/types/util"
)

// CreatePolicy creates a new CWP policy.
//
// Cloud Workload Policies help prevent and manage security violations in cloud runtime instances.
// They enable you to apply detection logic to specific asset groups at desired SDLC stages.
//
// Required fields in the request:
//   - Type: Policy type (COMPLIANCE, MALWARE, SECRET)
//   - Name: Policy name
//   - EvaluationStage: SDLC stage (CI, RUNTIME, DEPLOY)
//   - PolicyAction: Action to take (ISSUE, PREVENT)
//   - PolicySeverity: Severity level (LOW, MEDIUM, HIGH, CRITICAL)
//   - AssetGroupIDs: Asset groups to apply policy to
//
// For non-compliance policies, RulesIDs and Condition are also required.
func (c *Client) CreatePolicy(ctx context.Context, input types.CreateOrUpdatePolicyRequest) (*types.CreateOrUpdatePolicyResponse, error) {
	var resp types.CreateOrUpdatePolicyResponse
	_, err := c.internalClient.Do(ctx, http.MethodPost, PoliciesV2Endpoint, nil, nil, input, &resp, nil)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// GetPolicyByID retrieves a specific CWP policy by ID.
func (c *Client) GetPolicyByID(ctx context.Context, policyId string) (*types.Policy, error) {
	var resp types.Policy
	_, err := c.internalClient.Do(ctx, http.MethodGet, PoliciesV2Endpoint, &[]string{policyId}, nil, nil, &resp, nil)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// ListPolicies retrieves all CWP policies with optional type filtering.
//
// If policyTypes is nil or empty, all policies will be returned.
// Valid policy types: COMPLIANCE, MALWARE, SECRET
func (c *Client) ListPolicies(ctx context.Context, policyTypes []string) ([]types.Policy, error) {
	var queryParams *url.Values
	if len(policyTypes) > 0 {
		params := convert.StringSliceToQuery("types", policyTypes)
		queryParams = &params
	}

	var resp []types.Policy
	_, err := c.internalClient.Do(ctx, http.MethodGet, PoliciesV2Endpoint, nil, queryParams, nil, &resp, nil)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// UpdatePolicy updates an existing CWP policy.
//
// The request should contain the full policy object with all required fields.
// This is a full replacement operation.
func (c *Client) UpdatePolicy(ctx context.Context, policyID string, input types.CreateOrUpdatePolicyRequest) error {
	_, err := c.internalClient.Do(ctx, http.MethodPut, PoliciesV2Endpoint, &[]string{policyID}, nil, input, nil, nil)
	return err
}

// DeletePolicy deletes a CWP policy by ID.
//
// If closeIssues is true, all issues opened by this policy will be closed.
func (c *Client) DeletePolicy(ctx context.Context, policyID string, closeIssues bool) error {
	queryVals := convert.StringToQuery("closeIssues", strconv.FormatBool(closeIssues))
	_, err := c.internalClient.Do(ctx, http.MethodDelete, PoliciesV1Endpoint, &[]string{policyID}, &queryVals, nil, nil, nil)
	return err
}

// ValidateCreatePolicyRequest performs validation on a CreatePolicyRequest.
//
// This helps catch common errors before making API calls.
func ValidateCreatePolicyRequest(req types.CreateOrUpdatePolicyRequest) error {
	if req.Type == "" {
		return fmt.Errorf("Policy type is required (COMPLIANCE, MALWARE, or SECRET)")
	}
	if req.Name == "" {
		return fmt.Errorf("Policy name is required")
	}
	if req.EvaluationStage == "" {
		return fmt.Errorf("evaluation stage is required (CI, RUNTIME, or DEPLOY)")
	}
	if len(req.AssetGroupIDs) == 0 {
		return fmt.Errorf("at least one asset group ID must be defined")
	}
	if len(req.PolicyRules) == 0 {
		return fmt.Errorf("at least one policy rule must be defined")
	}

	return nil
}

// ValidateUpdatePolicyRequest performs validation on an UpdatePolicyRequest.
//
// This helps catch common errors before making API calls.
func ValidateUpdatePolicyRequest(req types.CreateOrUpdatePolicyRequest) error {
	if req.ID == "" {
		return fmt.Errorf("Policy ID is required")
	}

	return ValidateCreatePolicyRequest(req)
}
