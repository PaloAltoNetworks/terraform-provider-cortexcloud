// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package models

import (
	//"github.com/hashicorp/terraform-plugin-framework/types"
)

type scopeModificationRegions struct {
	Enabled bool     `json:"enabled" tfsdk:"enabled"`
	Type    *string   `json:"type,omitempty" tfsdk:"type"`
	Regions *[]string `json:"regions,omitempty" tfsdk:"regions"`
}
