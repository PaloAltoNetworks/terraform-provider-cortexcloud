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

// CreateControl creates a new compliance control.
// Returns the created control's ID and success status.
func (c *Client) CreateControl(ctx context.Context, req types.CreateControlRequest) (*types.CreateControlResponse, error) {
	var resp types.CreateControlResponse
	_, err := c.internalClient.Do(ctx, http.MethodPost, CreateControlEndpoint, nil, nil, req, &resp, &client.DoOptions{
		RequestWrapperKeys:  []string{"request_data"},
		ResponseWrapperKeys: []string{"reply"},
	})
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// GetControl retrieves a specific control by ID.
// Note: The API returns the control wrapped in an array, so we extract the first element.
func (c *Client) GetControl(ctx context.Context, req types.GetControlRequest) (*types.Control, error) {
	var resp types.GetControlResponse
	_, err := c.internalClient.Do(ctx, http.MethodPost, GetControlEndpoint, nil, nil, req, &resp, &client.DoOptions{
		RequestWrapperKeys:  []string{"request_data"},
		ResponseWrapperKeys: []string{"reply"},
	})
	if err != nil {
		return nil, err
	}
	if len(resp.Control) == 0 {
		return nil, fmt.Errorf("control not found")
	}
	return &resp.Control[0], nil
}

// UpdateControl updates an existing compliance control.
func (c *Client) UpdateControl(ctx context.Context, req types.UpdateControlRequest) (bool, error) {
	var resp commontypes.SuccessResponse
	_, err := c.internalClient.Do(ctx, http.MethodPost, UpdateControlEndpoint, nil, nil, req, &resp, &client.DoOptions{
		RequestWrapperKeys:  []string{"request_data"},
		ResponseWrapperKeys: []string{"reply"},
	})
	return resp.Success, err
}

// DeleteControl deletes a control.
func (c *Client) DeleteControl(ctx context.Context, req types.DeleteControlRequest) (bool, error) {
	var resp commontypes.SuccessResponse
	_, err := c.internalClient.Do(ctx, http.MethodPost, DeleteControlEndpoint, nil, nil, req, &resp, &client.DoOptions{
		RequestWrapperKeys:  []string{"request_data"},
		ResponseWrapperKeys: []string{"reply"},
	})
	return resp.Success, err
}

// ListControls retrieves all controls with optional filtering, sorting, and pagination.
func (c *Client) ListControls(ctx context.Context, req types.ListControlsRequest) (*types.ListControlsResponse, error) {
	var resp types.ListControlsResponse
	_, err := c.internalClient.Do(ctx, http.MethodPost, ListControlsEndpoint, nil, nil, req, &resp, &client.DoOptions{
		RequestWrapperKeys:  []string{"request_data"},
		ResponseWrapperKeys: []string{"reply"},
	})
	if err != nil {
		return nil, err
	}
	return &resp, nil
}
