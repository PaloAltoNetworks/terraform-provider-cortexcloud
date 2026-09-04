// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package cloudonboarding

import (
	"context"
	"net/http"

	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/internal/client"
	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/types/cloudonboarding"
)

// CreateOutpostTemplate creates a new Cloud Onboarding Outpost Template.
func (c *Client) CreateOutpostTemplate(ctx context.Context, input *types.CreateOutpostTemplateRequest) (*types.CreateTemplateOrEditIntegrationInstanceResponse, error) {
	var ans types.CreateTemplateOrEditIntegrationInstanceResponse
	_, err := c.internalClient.Do(ctx, http.MethodPost, CreateOutpostTemplateEndpoint, nil, nil, input, &ans, &client.DoOptions{
		RequestWrapperKeys:  []string{"request_data"},
		ResponseWrapperKeys: []string{"reply"},
	})
	if err != nil {
		return nil, err
	}
	return &ans, nil
}

// UpdateOutpost updates an existing Outpost.
func (c *Client) UpdateOutpost(ctx context.Context, input *types.UpdateOutpostRequest) error {
	_, err := c.internalClient.Do(ctx, http.MethodPost, UpdateOutpostEndpoint, nil, nil, input, nil, &client.DoOptions{
		RequestWrapperKeys: []string{"request_data"},
	})
	return err
}

// ListOutposts returns a list of outposts.
func (c *Client) ListOutposts(ctx context.Context, input *types.ListOutpostsRequest) (*types.ListOutpostsResponse, error) {
	var ans types.ListOutpostsResponse
	_, err := c.internalClient.Do(ctx, http.MethodPost, ListOutpostsEndpoint, nil, nil, input, &ans, &client.DoOptions{
		RequestWrapperKeys:  []string{"request_data"},
		ResponseWrapperKeys: []string{"reply"},
	})
	if err != nil {
		return nil, err
	}
	return &ans, nil
}
