// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package platform

import (
	"context"
	"net/http"

	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/internal/client"
	types "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/types/platform"
)

// CreateSyslogIntegration creates a new syslog integration and returns its name and ID.
func (c *Client) CreateSyslogIntegration(ctx context.Context, input types.CreateSyslogIntegrationRequest) (types.CreateSyslogIntegrationResponse, error) {
	var resp types.CreateSyslogIntegrationResponse
	_, err := c.internalClient.Do(ctx, http.MethodPost, CreateSyslogIntegrationEndpoint, nil, nil, input, &resp, &client.DoOptions{
		RequestWrapperKeys: []string{"request_data"},
	})
	return resp, mapError(err)
}

// ListSyslogIntegrations retrieves a filtered list of all syslog integrations.
func (c *Client) ListSyslogIntegrations(ctx context.Context, input types.ListSyslogIntegrationsRequest) (types.ListSyslogIntegrationsResponse, error) {
	var resp types.ListSyslogIntegrationsResponse
	_, err := c.internalClient.Do(ctx, http.MethodPost, ListSyslogIntegrationsEndpoint, nil, nil, input, &resp, &client.DoOptions{
		RequestWrapperKeys: []string{"request_data"},
	})
	return resp, mapError(err)
}
