// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package types

// SuccessResponse represents a generic API response containing only a success boolean.
// This type is used across multiple modules/endpoints that return a simple success indicator.
type SuccessResponse struct {
	Success bool `json:"success"`
}
