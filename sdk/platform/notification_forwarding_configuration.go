// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package platform

import (
	"context"
	"fmt"
	"net/http"

	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/internal/client"
	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/types/platform"
)

// CreateNotificationForwardingConfiguration creates a new notification forwarding configuration.
func (c *Client) CreateNotificationForwardingConfiguration(ctx context.Context, req types.CreateOrUpdateNotificationForwardingConfigurationRequest) (types.NotificationForwardingConfiguration, error) {
	var resp types.CreateOrUpdateNotificationForwardingConfigurationResponse
	if _, err := c.internalClient.Do(ctx, http.MethodPost, NotificationForwardingConfigurationsEndpoint, nil, nil, req, &resp, &client.DoOptions{
		RequestWrapperKeys: []string{"request_data"},
	}); err != nil {
		return types.NotificationForwardingConfiguration{}, mapError(err)
	} else {
		return resp.Data.ToSDK(), mapError(err)
	}
}

// UpdateNotificationForwardingConfiguration updates an existing notification forwarding configuration.
func (c *Client) UpdateNotificationForwardingConfiguration(ctx context.Context, id string, req types.CreateOrUpdateNotificationForwardingConfigurationRequest) (types.NotificationForwardingConfiguration, error) {
	var resp types.CreateOrUpdateNotificationForwardingConfigurationResponse
	if _, err := c.internalClient.Do(ctx, http.MethodPut, fmt.Sprintf("%s/%s", NotificationForwardingConfigurationsEndpoint, id), nil, nil, req, &resp, &client.DoOptions{
		RequestWrapperKeys: []string{"request_data"},
	}); err != nil {
		return types.NotificationForwardingConfiguration{}, mapError(err)
	} else {
		return resp.Data.ToSDK(), mapError(err)
	}
}

// toggleNotificationForwardingConfiguration enables or disables a notification forwarding configuration.
func (c *Client) toggleNotificationForwardingConfiguration(ctx context.Context, id string, status string) error {
	req := types.ToggleNotificationForwardingConfigurationRequest{
		Status: status,
	}
	_, err := c.internalClient.Do(ctx, http.MethodPatch, fmt.Sprintf("%s/%s", ToggleNotificationForwardingConfigurationEndpoint, id), nil, nil, req, nil, &client.DoOptions{
		RequestWrapperKeys: []string{"request_data"},
	})
	return mapError(err)
}

// EnableNotificationForwardingConfiguration enables a notification forwarding configuration.
func (c *Client) EnableNotificationForwardingConfiguration(ctx context.Context, id string) error {
	return c.toggleNotificationForwardingConfiguration(ctx, id, "enable")
}

// DisableNotificationForwardingConfiguration disables a notification forwarding configuration.
func (c *Client) DisableNotificationForwardingConfiguration(ctx context.Context, id string) error {
	return c.toggleNotificationForwardingConfiguration(ctx, id, "disable")
}

// DeleteNotificationForwardingConfiguration deletes a notification forwarding configuration.
func (c *Client) DeleteNotificationForwardingConfiguration(ctx context.Context, id string) error {
	_, err := c.internalClient.Do(ctx, http.MethodDelete, fmt.Sprintf("%s/%s", NotificationForwardingConfigurationsEndpoint, id), nil, nil, nil, nil, nil)
	return mapError(err)
}

// GetNotificationForwardingConfiguration retrieves the notification forwarding configuration with the specified ID value.
func (c *Client) GetNotificationForwardingConfiguration(ctx context.Context, id string) (types.NotificationForwardingConfiguration, error) {
	var resp types.CreateOrUpdateNotificationForwardingConfigurationResponse
	if _, err := c.internalClient.Do(ctx, http.MethodGet, fmt.Sprintf("%s/%s", NotificationForwardingConfigurationsEndpoint, id), nil, nil, nil, &resp, nil); err != nil {
		return types.NotificationForwardingConfiguration{}, mapError(err)
	} else {
		return resp.Data.ToSDK(), mapError(err)
	}
}

// ListNotificationForwardingConfigurations retrieves a filtered list of all notification forwarding configurations.
func (c *Client) ListNotificationForwardingConfigurations(ctx context.Context) (data []types.NotificationForwardingConfiguration, totalCount int, error error) {
	var resp types.ListNotificationForwardingConfigurationsResponse
	if _, err := c.internalClient.Do(ctx, http.MethodGet, ListNotificationForwardingConfigurationsEndpoint, nil, nil, nil, &resp, nil); err != nil {
		return []types.NotificationForwardingConfiguration{}, 0, mapError(err)
	} else {
		for _, datum := range resp.Data {
			data = append(data, datum.ToSDK())
		}
		return data, resp.Metadata.TotalCount, mapError(err)
	}
}
