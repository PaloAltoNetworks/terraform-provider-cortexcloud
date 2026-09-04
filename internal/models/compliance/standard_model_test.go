// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package models

import (
	"context"
	"testing"

	complianceTypes "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/types/compliance"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestStandardModel_RefreshFromRemote_EmptyDescriptionIsNull verifies that an
// empty description echoed by the API is normalized to null so an omitted
// (null) `description` in configuration does not perpetually drift.
func TestStandardModel_RefreshFromRemote_EmptyDescriptionIsNull(t *testing.T) {
	ctx := context.Background()
	diags := diag.Diagnostics{}

	model := &StandardModel{}
	remote := &complianceTypes.Standard{
		ID:          "std-123",
		Name:        "Test Standard",
		Description: "",
	}

	model.RefreshFromRemote(ctx, &diags, remote)

	require.False(t, diags.HasError(), "unexpected diagnostics: %v", diags)
	assert.True(t, model.Description.IsNull(),
		"empty remote description should be normalized to null")
}

// TestStandardModel_RefreshFromRemote_NonEmptyDescriptionPreserved verifies a
// non-empty description is preserved as-is.
func TestStandardModel_RefreshFromRemote_NonEmptyDescriptionPreserved(t *testing.T) {
	ctx := context.Background()
	diags := diag.Diagnostics{}

	model := &StandardModel{}
	remote := &complianceTypes.Standard{
		ID:          "std-123",
		Name:        "Test Standard",
		Description: "A meaningful description",
	}

	model.RefreshFromRemote(ctx, &diags, remote)

	require.False(t, diags.HasError(), "unexpected diagnostics: %v", diags)
	assert.False(t, model.Description.IsNull(),
		"non-empty remote description should not be null")
	assert.Equal(t, types.StringValue("A meaningful description"), model.Description)
}
