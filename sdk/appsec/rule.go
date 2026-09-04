// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package appsec

import (
	"context"
	"net/http"

	types "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/types/appsec"
)

// ---------------------------
// Request functions
// ---------------------------

// Validate validates the Application Security rule definition and relevant
// properties to ensure that they align with what is expected by the Cortex
// Cloud API.
//
// This operation occurs within the Cortex Cloud platform as a prerequisite
// step during the rule creation/cloning operation. The purpose of this function
// is to allow for validation of the rule logic prior to executing the
// create/clone request, if users would like to handle any rule logic errors
// separately from any errors that may be raised for the other input values.
//
// The private version of this endpoint is called from the UI by clicking the
// "Validate Code" button in the rule definition creation screen.
func (c *Client) Validate(ctx context.Context, input []types.ValidateRequest) (types.ValidateResponse, error) {
	var ans types.ValidateResponse
	_, err := c.internalClient.Do(ctx, http.MethodPost, RulesValidationEndpoint, nil, nil, input, &ans, nil)

	return ans, err
}

// CreateOrClone creates a new or clones an existing Application Security rule.
//
// If a rule with the specified name already exists, that rule will be cloned
// and altered according to the remaining input values.
//
// Otherwise, a new rule will be created with the provided input values.
func (c *Client) CreateOrClone(ctx context.Context, input types.CreateOrCloneRequest) (types.Rule, error) {
	var ans types.Rule
	_, err := c.internalClient.Do(ctx, http.MethodPost, RulesEndpoint, nil, nil, input, &ans, nil)

	return ans, err
}

// Get returns the details of the Application Security rule with the provided
// ID value.
func (c *Client) Get(ctx context.Context, id string) (types.Rule, error) {
	var ans types.Rule
	_, err := c.internalClient.Do(ctx, http.MethodGet, RulesEndpoint, &[]string{id}, nil, nil, &ans, nil)

	return ans, err
}

// GetLabels retrieves all available Application Security rule labels.
func (c *Client) GetLabels(ctx context.Context) (types.GetLabelsResponse, error) {
	var ans types.GetLabelsResponse
	_, err := c.internalClient.Do(ctx, http.MethodGet, RulesLabelsEndpoint, nil, nil, nil, &ans, nil)

	return ans, err
}

// List retrieves a list of all Application Security rules that match the
// provided filter values.
//
// If no filter values are provided, all rules will be returned.
func (c *Client) List(ctx context.Context, input types.ListRequest) (types.ListResponse, error) {
	queryValues := input.ToQueryValues()

	var ans types.ListResponse
	_, err := c.internalClient.Do(ctx, http.MethodGet, RulesEndpoint, nil, &queryValues, nil, &ans, nil)

	return ans, err
}

// Update modifies an existing Application Security rule.
//
// If the target rule is an out-of-the-box rule, only the labels can be
// modified. For custom rules, all fields can be modified.
//
// To customize an out-of-the-box rule, first clone it using `CreateOrClone`,
// then use `Update` to set the desired configuration.
//
// The caller is responsible for populating all required fields in the
// UpdateRequest. The PATCH endpoint accepts only the fields defined in
// UpdateRequest; excess properties will be rejected by the API.
func (c *Client) Update(ctx context.Context, ruleId string, input types.UpdateRequest) (types.UpdateResponse, error) {
	var ans types.UpdateResponse

	_, err := c.internalClient.Do(ctx, http.MethodPatch, RulesEndpoint, &[]string{ruleId}, nil, input, &ans, nil)

	return ans, err
}

// Delete deletes the specified Application Security rule.
func (c *Client) Delete(ctx context.Context, id string) error {
	_, err := c.internalClient.Do(ctx, http.MethodDelete, RulesEndpoint, &[]string{id}, nil, nil, nil, nil)

	return err
}
