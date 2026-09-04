// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package platform

import (
	"context"
	"net/http"

	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/internal/client"
	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/types/platform"
)

// ListIDPMetadata returns the metadata for all IDPs.
//
// This endpoint requires Instance Administrator permissions.
func (c *Client) ListIDPMetadata(ctx context.Context) (types.ListIDPMetadataResponse, error) {
	var resp types.ListIDPMetadataResponse
	_, err := c.internalClient.Do(ctx, http.MethodPost, ListIDPMetadataEndpoint, nil, nil, types.ListIDPMetadataRequest{}, &resp, &client.DoOptions{
		RequestWrapperKeys: []string{"request_data"},
	})
	return resp, err
}

// ListAuthSettings returns the authentication settings for all configured
// domains in the tenant.
//
// This endpoint requires Instance Administrator permissions.
func (c *Client) ListAuthSettings(ctx context.Context) ([]types.AuthSettings, error) {
	var ans []types.AuthSettings
	_, err := c.internalClient.Do(ctx, http.MethodPost, ListAuthSettingsEndpoint, nil, nil, types.ListAuthSettingsRequest{}, &ans, &client.DoOptions{
		RequestWrapperKeys:  []string{"request_data"},
		ResponseWrapperKeys: []string{"reply"},
	})
	return ans, err
}

// CreateAuthSettings creates authentication settings for the specified domain
// using the provided IDP SSO or metadata URL.
//
// To configure IDP SSO, the `idp_sso_url`, `idp_issuer` and `idp_certificate`
// fields are required. To configure via metadata URL, the `metadata_url` is
// the only required field.
//
// This endpoint requires Instance Administrator permissions.
func (c *Client) CreateAuthSettings(ctx context.Context, req types.CreateAuthSettingsRequest) (bool, error) {
	var resp bool
	_, err := c.internalClient.Do(ctx, http.MethodPost, CreateAuthSettingsEndpoint, nil, nil, req, &resp, &client.DoOptions{
		RequestWrapperKeys:  []string{"request_data"},
		ResponseWrapperKeys: []string{"reply"},
	})
	return resp, err
}

// UpdateAuthSettings updates the existing authentication settings for the
// specified domain.
//
// To update the default domain, provide empty strings for the
// `current_domain_value` and `new_domain_value` fields.
//
// This endpoint requires Instance Administrator permissions.
func (c *Client) UpdateAuthSettings(ctx context.Context, req types.UpdateAuthSettingsRequest) (bool, error) {
	var resp bool
	_, err := c.internalClient.Do(ctx, http.MethodPost, UpdateAuthSettingsEndpoint, nil, nil, req, &resp, &client.DoOptions{
		RequestWrapperKeys:  []string{"request_data"},
		ResponseWrapperKeys: []string{"reply"},
	})
	return resp, err
}

// DeleteAuthSettings deletes all authentication settings for the specified
// domain.
//
// This endpoint requires Instance Administrator permissions.
func (c *Client) DeleteAuthSettings(ctx context.Context, domain string) (bool, error) {
	var resp bool
	_, err := c.internalClient.Do(ctx, http.MethodPost, DeleteAuthSettingsEndpoint, nil, nil, types.DeleteAuthSettingsRequest{Domain: domain}, &resp, &client.DoOptions{
		RequestWrapperKeys:  []string{"request_data"},
		ResponseWrapperKeys: []string{"reply"},
	})
	return resp, err
}
