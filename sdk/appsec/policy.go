// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package appsec

import (
	"context"
	stderrors "errors"
	"net/http"
	"strings"

	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/errors"
	types "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/types/appsec"
)

// ---------------------------
// Request functions
// ---------------------------

// CreatePolicy creates a new Application Security policy.
//
// Policies define conditions for when findings should trigger actions.
// Scope and AssetGroupIds are mutually exclusive - use one or the other.
//
// On some legacy stacks the API rejects the new
// "ciImage" and "imageRegistry" trigger keys as excess properties with
// HTTP 422 ValidateError. When this specific error is detected, the call
// is silently retried with the legacy 3-trigger payload (periodic / pr /
// cicd only). The retry is invisible to SDK consumers; only the standard
// CreatePolicy(input) signature is exposed.
func (c *Client) CreatePolicy(ctx context.Context, input types.CreatePolicyRequest) (types.Policy, error) {
	pol, err := c.createPolicyOnce(ctx, input, false /* legacyMode */)
	if err != nil && isLegacyTriggerExcessPropertyError(err) {
		c.internalClient.Logger().Debug(ctx,
			"AppSec Policy CREATE rejected new trigger keys (ciImage/imageRegistry); "+
				"retrying with legacy 3-trigger payload")
		return c.createPolicyOnce(ctx, input, true /* legacyMode */)
	}
	return pol, err
}

// createPolicyOnce performs a single CreatePolicy HTTP call. When legacyMode
// is true, the request body uses the 3-trigger shape (no ciImage / no
// imageRegistry). Otherwise, the standard 5-trigger shape is used.
func (c *Client) createPolicyOnce(ctx context.Context, input types.CreatePolicyRequest, legacyMode bool) (types.Policy, error) {
	body, err := buildCreatePolicyBody(input, legacyMode)
	if err != nil {
		return types.Policy{}, err
	}
	var ans types.Policy
	_, err = c.internalClient.Do(ctx, http.MethodPost, PoliciesEndpoint, nil, nil, body, &ans, nil)
	return ans, err
}

// GetPolicy retrieves a policy by ID.
func (c *Client) GetPolicy(ctx context.Context, policyID string) (types.Policy, error) {
	var ans types.Policy
	_, err := c.internalClient.Do(ctx, http.MethodGet, PoliciesEndpoint, &[]string{policyID}, nil, nil, &ans, nil)
	return ans, err
}

// ListPolicies retrieves all policies with optional filters.
//
// If no filters are provided, all policies will be returned.
func (c *Client) ListPolicies(ctx context.Context, input types.ListPoliciesRequest) ([]types.Policy, error) {
	queryValues := input.ToQueryValues()

	var ans []types.Policy
	_, err := c.internalClient.Do(ctx, http.MethodGet, PoliciesEndpoint, nil, &queryValues, nil, &ans, nil)
	return ans, err
}

// UpdatePolicy updates an existing Application Security policy.
//
// All fields in the request are optional. Only provided fields will be updated.
//
// On some legacy stacks the API rejects the new
// "ciImage" and "imageRegistry" trigger keys as excess properties with
// HTTP 422 ValidateError. When this specific error is detected and the
// request actually included a triggers payload, the call is silently
// retried with the legacy 3-trigger payload (periodic / pr / cicd only).
func (c *Client) UpdatePolicy(ctx context.Context, policyID string, input types.UpdatePolicyRequest) (types.Policy, error) {
	pol, err := c.updatePolicyOnce(ctx, policyID, input, false /* legacyMode */)
	if err != nil && input.Triggers != nil && isLegacyTriggerExcessPropertyError(err) {
		c.internalClient.Logger().Debug(ctx,
			"AppSec Policy UPDATE rejected new trigger keys (ciImage/imageRegistry); "+
				"retrying with legacy 3-trigger payload")
		return c.updatePolicyOnce(ctx, policyID, input, true /* legacyMode */)
	}
	return pol, err
}

// updatePolicyOnce performs a single UpdatePolicy HTTP call. When legacyMode
// is true, the request body uses the 3-trigger shape (no ciImage / no
// imageRegistry). Otherwise, the standard 5-trigger shape is used.
func (c *Client) updatePolicyOnce(ctx context.Context, policyID string, input types.UpdatePolicyRequest, legacyMode bool) (types.Policy, error) {
	body, err := buildUpdatePolicyBody(input, legacyMode)
	if err != nil {
		return types.Policy{}, err
	}
	var ans types.Policy
	_, err = c.internalClient.Do(ctx, http.MethodPut, PoliciesEndpoint, &[]string{policyID}, nil, body, &ans, nil)
	return ans, err
}

// DeletePolicy deletes the specified Application Security policy.
func (c *Client) DeletePolicy(ctx context.Context, policyID string) error {
	var ans types.DeletePolicyResponse
	_, err := c.internalClient.Do(ctx, http.MethodDelete, PoliciesEndpoint, &[]string{policyID}, nil, nil, &ans, nil)
	return err
}

// ---------------------------
// Internal helpers
// ---------------------------

// buildCreatePolicyBody returns a value that, when handed to the internal
// client's Do() function (which json.Marshals it), produces either the
// standard 5-trigger payload or the legacy 3-trigger payload.
//
// In legacy mode, the body is pre-marshaled and returned as json.RawMessage
// so that the internal client's json.Marshal call emits it verbatim.
// Otherwise, the input struct is returned as-is to preserve the existing
// behaviour.
func buildCreatePolicyBody(input types.CreatePolicyRequest, legacyMode bool) (any, error) {
	if !legacyMode {
		return input, nil
	}
	raw, err := types.MarshalCreatePolicyRequestLegacy(input)
	if err != nil {
		return nil, err
	}
	return rawJSONMessage(raw), nil
}

// buildUpdatePolicyBody is the UpdatePolicy counterpart to
// buildCreatePolicyBody. Same contract.
func buildUpdatePolicyBody(input types.UpdatePolicyRequest, legacyMode bool) (any, error) {
	if !legacyMode {
		return input, nil
	}
	raw, err := types.MarshalUpdatePolicyRequestLegacy(input)
	if err != nil {
		return nil, err
	}
	return rawJSONMessage(raw), nil
}

// rawJSONMessage adapts pre-marshaled bytes into a value that re-serializes
// to itself via encoding/json. The internal HTTP client always calls
// json.Marshal on its input; json.RawMessage's MarshalJSON returns its
// underlying bytes verbatim, so we get the exact body we constructed.
func rawJSONMessage(b []byte) any {
	// Defined here so the appsec package isn't forced to import encoding/json
	// purely for the type alias. See callers above.
	return jsonRawMessage(b)
}

// jsonRawMessage is a tiny local alias for encoding/json.RawMessage to
// document the intent without leaking the import to other helpers.
type jsonRawMessage []byte

func (m jsonRawMessage) MarshalJSON() ([]byte, error) {
	if len(m) == 0 {
		return []byte("null"), nil
	}
	return m, nil
}

// isLegacyTriggerExcessPropertyError returns true iff err is a
// *errors.CortexCloudAPIError whose Details.Fields map contains a key
// referencing the new "ciImage" or "imageRegistry" trigger keys with a
// message indicating an excess-property rejection.
//
// Examples of legacy-stack rejections:
//
//	"policy.triggers.ciImage":       { "message": "'ciImage' is not a valid property" }
//	"policy.triggers.imageRegistry": { "message": "extra fields not permitted" }
func isLegacyTriggerExcessPropertyError(err error) bool {
	if err == nil {
		return false
	}

	var apiErr *errors.CortexCloudAPIError
	if !stderrors.As(err, &apiErr) {
		return false
	}
	if apiErr == nil || apiErr.Details == nil || len(apiErr.Details.Fields) == 0 {
		return false
	}

	for fieldPath, params := range apiErr.Details.Fields {
		lowerPath := strings.ToLower(fieldPath)
		if !strings.Contains(lowerPath, "ciimage") && !strings.Contains(lowerPath, "imageregistry") {
			continue
		}
		// Field path mentions ciImage or imageRegistry. Confirm the message
		// looks like an excess-property / not-permitted rejection so we
		// don't accidentally treat a "value out of range" error on the new
		// keys as a legacy-stack signal.
		lowerMsg := strings.ToLower(params.Message)
		if strings.Contains(lowerMsg, "excess") ||
			strings.Contains(lowerMsg, "not permitted") ||
			strings.Contains(lowerMsg, "not allowed") ||
			strings.Contains(lowerMsg, "not a valid property") ||
			strings.Contains(lowerMsg, "unknown property") ||
			strings.Contains(lowerMsg, "unknown field") ||
			strings.Contains(lowerMsg, "extra field") ||
			strings.Contains(lowerMsg, "additional propert") ||
			strings.Contains(lowerMsg, "unexpected property") {
			return true
		}
	}
	return false
}
