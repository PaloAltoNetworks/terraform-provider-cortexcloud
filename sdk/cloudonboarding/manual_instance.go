// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package cloudonboarding

import (
	"context"
	"net/http"

	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/internal/client"
	types "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/types/cloudonboarding"
)

// CreateManualInstance creates a manually onboarded cloud connector instance
// and returns the identifier assigned to it.
//
// This is the manual onboarding flow and is distinct from
// CreateIntegrationTemplate, which drives the automated template flow against a
// different endpoint and an incompatible schema.
func (c *Client) CreateManualInstance(ctx context.Context, input *types.CreateManualInstanceRequest) (types.CreateManualInstanceResponse, error) {
	var ans types.CreateManualInstanceResponse
	_, err := c.internalClient.Do(ctx, http.MethodPost, CreateManualInstanceEndpoint, nil, nil, input, &ans, &client.DoOptions{
		RequestWrapperKeys:  []string{"request_data"},
		ResponseWrapperKeys: []string{"reply"},
	})
	return ans, err
}

// EditManualInstance updates a manually onboarded cloud connector instance.
//
// The update is partial: optional fields that are omitted retain their existing
// server-side values, so callers should supply the complete desired state. The
// endpoint returns an empty reply on success.
//
// This is distinct from EditIntegrationInstance, which targets the automated
// flow and rejects the fields this endpoint requires.
func (c *Client) EditManualInstance(ctx context.Context, input *types.EditManualInstanceRequest) error {
	_, err := c.internalClient.Do(ctx, http.MethodPost, EditManualInstanceEndpoint, nil, nil, input, nil, &client.DoOptions{
		RequestWrapperKeys: []string{"request_data"},
	})
	return err
}

// GetEditInstanceDetails reads the editable configuration of a cloud connector
// instance.
//
// A successful call does not prove the requested instance exists: the endpoint
// has been observed returning identical payloads for different identifiers, so
// callers must not use it as an existence check. Inspect the returned fields
// instead.
//
// The reply is not the write shape. It carries keys the write endpoints reject
// and omits keys they accept, so the result cannot be fed back into
// EditManualInstance unmodified.
func (c *Client) GetEditInstanceDetails(ctx context.Context, input *types.GetEditInstanceDetailsRequest) (types.GetEditInstanceDetailsResponse, error) {
	var ans types.GetEditInstanceDetailsResponse
	_, err := c.internalClient.Do(ctx, http.MethodPost, GetEditInstanceDetailsEndpoint, nil, nil, input, &ans, &client.DoOptions{
		RequestWrapperKeys:  []string{"request_data"},
		ResponseWrapperKeys: []string{"reply"},
	})
	return ans, err
}

// DeleteInstanceTemplate deletes a cloud connector instance template.
//
// The endpoint returns success for a template that does not exist. That is the
// documented server behaviour, so this method reports no error in that case and
// deliberately performs no client-side existence check. Deletion is therefore
// idempotent from the caller's point of view but is not a confirmation that a
// template was ever present.
func (c *Client) DeleteInstanceTemplate(ctx context.Context, input *types.DeleteInstanceTemplateRequest) error {
	_, err := c.internalClient.Do(ctx, http.MethodPost, DeleteInstanceTemplateEndpoint, nil, nil, input, nil, &client.DoOptions{
		RequestWrapperKeys: []string{"request_data"},
	})
	return err
}
