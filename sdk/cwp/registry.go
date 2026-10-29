// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package cwp

import (
	"context"
	stderrors "errors"
	"fmt"
	"net/http"
	"strings"

	sdkerrors "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/errors"
	types "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/types/cwp"
)

// IsNotFound reports whether err is the API's "not found" response for a
// registry connector.
//
// The internal client does not retain the HTTP status on API errors, so this
// inspects the parsed body instead. The registry onboarding API answers a
// missing connector with
//
//	404 {"err_msg": "Connector ID not found", "metadata": {"code": "NOT_FOUND"}}
//
// and a 404 whose body is not recognised is surfaced with Code "HTTP_404".
func IsNotFound(err error) bool {
	if err == nil {
		return false
	}
	var apiErr *sdkerrors.CortexCloudAPIError
	if !stderrors.As(err, &apiErr) || apiErr == nil {
		return false
	}
	if apiErr.Code != nil && *apiErr.Code == "HTTP_404" {
		return true
	}
	if apiErr.ErrMsg != nil && strings.Contains(strings.ToLower(*apiErr.ErrMsg), "not found") {
		return true
	}
	return false
}

// CreateRegistryConnector onboards a third-party container registry connector
// and returns the ID assigned by the platform.
func (c *Client) CreateRegistryConnector(ctx context.Context, input types.RegistryConnector) (string, error) {
	var resp types.CreateRegistryConnectorResponse
	if _, err := c.internalClient.Do(ctx, http.MethodPost, RegistryOnboardingInstancesEndpoint, nil, nil, input, &resp, nil); err != nil {
		return "", err
	}
	if resp.ConnectorID == "" {
		return "", fmt.Errorf("registry connector create succeeded but the response did not include a connector_id")
	}
	return resp.ConnectorID, nil
}

// GetRegistryConnector retrieves a registry connector by ID.
func (c *Client) GetRegistryConnector(ctx context.Context, connectorID string) (*types.RegistryConnector, error) {
	var resp types.RegistryConnector
	if _, err := c.internalClient.Do(ctx, http.MethodGet, RegistryOnboardingInstancesEndpoint, &[]string{connectorID}, nil, nil, &resp, nil); err != nil {
		return nil, err
	}
	return &resp, nil
}

// UpdateRegistryConnector replaces a registry connector.
//
// This is a full replacement: every field of input is written, so callers must
// send the complete connector, including credentials.
func (c *Client) UpdateRegistryConnector(ctx context.Context, connectorID string, input types.RegistryConnector) error {
	input.ConnectorID = connectorID
	_, err := c.internalClient.Do(ctx, http.MethodPut, RegistryOnboardingInstancesEndpoint, &[]string{connectorID}, nil, input, nil, nil)
	return err
}

// DeleteRegistryConnector deletes a registry connector by ID.
func (c *Client) DeleteRegistryConnector(ctx context.Context, connectorID string) error {
	_, err := c.internalClient.Do(ctx, http.MethodDelete, RegistryOnboardingInstancesEndpoint, &[]string{connectorID}, nil, nil, nil, nil)
	return err
}
