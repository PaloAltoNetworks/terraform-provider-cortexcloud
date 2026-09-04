// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package compliance

import (
	"context"
	"fmt"
	"net/http"

	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/internal/client"
	commontypes "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/types"
	types "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/types/compliance"
)

// CreateStandard creates a new compliance standard.
func (c *Client) CreateStandard(ctx context.Context, req types.CreateStandardRequest) (bool, error) {
	var resp commontypes.SuccessResponse
	_, err := c.internalClient.Do(ctx, http.MethodPost, CreateStandardEndpoint, nil, nil, req, &resp, &client.DoOptions{
		RequestWrapperKeys:  []string{"request_data"},
		ResponseWrapperKeys: []string{"reply"},
	})
	return resp.Success, err
}

// GetStandard retrieves a specific standard by ID.
func (c *Client) GetStandard(ctx context.Context, req types.GetStandardRequest) (*types.Standard, error) {
	var resp types.GetStandardResponse
	_, err := c.internalClient.Do(ctx, http.MethodPost, GetStandardEndpoint, nil, nil, req, &resp, &client.DoOptions{
		RequestWrapperKeys:  []string{"request_data"},
		ResponseWrapperKeys: []string{"reply"},
	})
	if err != nil {
		return nil, err
	}
	if len(resp.Standards) == 0 {
		return nil, fmt.Errorf("standard not found")
	}
	return &resp.Standards[0], nil
}

// UpdateStandard updates an existing compliance standard.
func (c *Client) UpdateStandard(ctx context.Context, req types.UpdateStandardRequest) (bool, error) {
	// First, fetch the existing standard to ensure all required fields are present
	existingStandard, err := c.GetStandard(ctx, types.GetStandardRequest{
		ID: req.ID,
	})
	if err != nil {
		return false, err
	}

	// Create a new update request with all fields from the existing standard
	mergedReq := types.UpdateStandardRequest{
		ID:           req.ID,
		StandardName: existingStandard.Name,
		Description:  existingStandard.Description,
		Labels:       existingStandard.Labels,
		ControlsIDs:  existingStandard.ControlsIDs,
	}

	// Ensure Labels and ControlsIDs are never nil (API requires empty arrays, not null)
	if mergedReq.Labels == nil {
		mergedReq.Labels = []string{}
	}
	if mergedReq.ControlsIDs == nil {
		mergedReq.ControlsIDs = []string{}
	}

	// Overwrite with any new values provided in the update request
	if req.StandardName != "" {
		mergedReq.StandardName = req.StandardName
	}
	if req.Description != "" {
		mergedReq.Description = req.Description
	}
	if req.Labels != nil {
		mergedReq.Labels = req.Labels
	}
	if req.ControlsIDs != nil {
		mergedReq.ControlsIDs = req.ControlsIDs
	}

	var resp commontypes.SuccessResponse
	_, err = c.internalClient.Do(ctx, http.MethodPost, UpdateStandardEndpoint, nil, nil, mergedReq, &resp, &client.DoOptions{
		RequestWrapperKeys:  []string{"request_data"},
		ResponseWrapperKeys: []string{"reply"},
	})
	return resp.Success, err
}

// DeleteStandard deletes a standard.
func (c *Client) DeleteStandard(ctx context.Context, req types.DeleteStandardRequest) (bool, error) {
	var resp commontypes.SuccessResponse
	_, err := c.internalClient.Do(ctx, http.MethodPost, DeleteStandardEndpoint, nil, nil, req, &resp, &client.DoOptions{
		RequestWrapperKeys:  []string{"request_data"},
		ResponseWrapperKeys: []string{"reply"},
	})
	return resp.Success, err
}

// ListStandards retrieves all standards with optional filtering, sorting, and pagination.
func (c *Client) ListStandards(ctx context.Context, req types.ListStandardsRequest) (*types.ListStandardsResponse, error) {
	var resp types.ListStandardsResponse
	_, err := c.internalClient.Do(ctx, http.MethodPost, ListStandardsEndpoint, nil, nil, req, &resp, &client.DoOptions{
		RequestWrapperKeys:  []string{"request_data"},
		ResponseWrapperKeys: []string{"reply"},
	})
	if err != nil {
		return nil, err
	}
	return &resp, nil
}
