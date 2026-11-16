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

// TestControlModel_RefreshFromRemote_EmptySubcategoryIsEmptyString verifies an
// empty remote subcategory is stored as "" (not null) when configured as "",
// so a configured `subcategory = ""` matches state after apply.
func TestControlModel_RefreshFromRemote_EmptySubcategoryIsEmptyString(t *testing.T) {
	ctx := context.Background()
	diags := diag.Diagnostics{}

	model := &ControlModel{Subcategory: types.StringValue("")}
	remote := &complianceTypes.Control{
		ID:          "control-id-123",
		Name:        "Custom Access Control Policy",
		Category:    "01.0 - Access Control",
		Subcategory: "",
	}

	model.RefreshFromRemote(ctx, &diags, remote)

	require.False(t, diags.HasError(), "unexpected diagnostics: %v", diags)
	assert.False(t, model.Subcategory.IsNull(), "empty remote subcategory must not be null")
	assert.Equal(t, types.StringValue(""), model.Subcategory)
}

// TestControlModel_RefreshFromRemote_SubcategoryPreserved verifies a populated
// remote subcategory is stored unchanged.
func TestControlModel_RefreshFromRemote_SubcategoryPreserved(t *testing.T) {
	ctx := context.Background()
	diags := diag.Diagnostics{}

	model := &ControlModel{}
	remote := &complianceTypes.Control{
		ID:          "control-id-123",
		Name:        "Custom Access Control Policy",
		Category:    "01.0 - Access Control",
		Subcategory: "01.01 Business Requirement For Access Control",
	}

	model.RefreshFromRemote(ctx, &diags, remote)

	require.False(t, diags.HasError(), "unexpected diagnostics: %v", diags)
	assert.Equal(t, types.StringValue("01.01 Business Requirement For Access Control"), model.Subcategory)
}

// TestControlModel_RefreshFromRemote_EmptyDescriptionIsEmptyString verifies an
// empty remote description is stored as "" (not null) when configured as "",
// so a configured `description = ""` matches state after apply.
func TestControlModel_RefreshFromRemote_EmptyDescriptionIsEmptyString(t *testing.T) {
	ctx := context.Background()
	diags := diag.Diagnostics{}

	model := &ControlModel{Description: types.StringValue("")}
	remote := &complianceTypes.Control{
		ID:          "control-id-123",
		Name:        "Custom Access Control Policy",
		Category:    "01.0 - Access Control",
		Description: "",
	}

	model.RefreshFromRemote(ctx, &diags, remote)

	require.False(t, diags.HasError(), "unexpected diagnostics: %v", diags)
	assert.False(t, model.Description.IsNull(), "empty remote description must not be null")
	assert.Equal(t, types.StringValue(""), model.Description)
}

// TestControlModel_RefreshFromRemote_DescriptionPreserved verifies a populated
// remote description is stored unchanged.
func TestControlModel_RefreshFromRemote_DescriptionPreserved(t *testing.T) {
	ctx := context.Background()
	diags := diag.Diagnostics{}

	model := &ControlModel{}
	remote := &complianceTypes.Control{
		ID:          "control-id-123",
		Name:        "Custom Access Control Policy",
		Category:    "01.0 - Access Control",
		Description: "Enforce access control policies and procedures",
	}

	model.RefreshFromRemote(ctx, &diags, remote)

	require.False(t, diags.HasError(), "unexpected diagnostics: %v", diags)
	assert.Equal(t, types.StringValue("Enforce access control policies and procedures"), model.Description)
}

// TestControlModel_RefreshFromRemote_NilRemoteAddsError verifies a nil remote
// produces a diagnostic error rather than a panic.
func TestControlModel_RefreshFromRemote_NilRemoteAddsError(t *testing.T) {
	ctx := context.Background()
	diags := diag.Diagnostics{}

	model := &ControlModel{}
	model.RefreshFromRemote(ctx, &diags, nil)

	assert.True(t, diags.HasError(), "expected an error diagnostic for nil remote")
}

// TestControlModel_ToUpdateRequest_EmptySubcategoryPassedThrough verifies a
// planned `subcategory = ""` reaches the update request as "".
func TestControlModel_ToUpdateRequest_EmptySubcategoryPassedThrough(t *testing.T) {
	ctx := context.Background()
	diags := diag.Diagnostics{}

	model := &ControlModel{
		ID:          types.StringValue("control-id-123"),
		Name:        types.StringValue("Custom Access Control Policy"),
		Description: types.StringValue("Enforce access control policies and procedures"),
		Category:    types.StringValue("01.0 - Access Control"),
		Subcategory: types.StringValue(""),
	}

	req := model.ToUpdateRequest(ctx, &diags)

	require.False(t, diags.HasError(), "unexpected diagnostics: %v", diags)
	assert.Equal(t, "control-id-123", req.ID)
	assert.Equal(t, "Custom Access Control Policy", req.ControlName)
	assert.Equal(t, "01.0 - Access Control", req.Category)
	assert.Equal(t, "", req.Subcategory)
	assert.Equal(t, "Enforce access control policies and procedures", req.Description)
}

// TestControlModel_ToUpdateRequest_PopulatedFieldsMapped verifies all
// configurable fields are mapped into the update request.
func TestControlModel_ToUpdateRequest_PopulatedFieldsMapped(t *testing.T) {
	ctx := context.Background()
	diags := diag.Diagnostics{}

	model := &ControlModel{
		ID:          types.StringValue("control-id-123"),
		Name:        types.StringValue("Custom Access Control Policy"),
		Description: types.StringValue("Enforce access control policies and procedures"),
		Category:    types.StringValue("01.0 - Access Control"),
		Subcategory: types.StringValue("01.01 Business Requirement For Access Control"),
	}

	req := model.ToUpdateRequest(ctx, &diags)

	require.False(t, diags.HasError(), "unexpected diagnostics: %v", diags)
	assert.Equal(t, complianceTypes.UpdateControlRequest{
		ID:          "control-id-123",
		ControlName: "Custom Access Control Policy",
		Description: "Enforce access control policies and procedures",
		Category:    "01.0 - Access Control",
		Subcategory: "01.01 Business Requirement For Access Control",
	}, req)
}

// TestControlModel_ToUpdateRequest_UnknownDescriptionAddsError verifies an
// unknown description is rejected instead of being silently sent as "".
func TestControlModel_ToUpdateRequest_UnknownDescriptionAddsError(t *testing.T) {
	ctx := context.Background()
	diags := diag.Diagnostics{}

	model := &ControlModel{
		ID:          types.StringValue("control-id-123"),
		Name:        types.StringValue("Custom Access Control Policy"),
		Description: types.StringUnknown(),
		Category:    types.StringValue("01.0 - Access Control"),
		Subcategory: types.StringValue("01.01 Business Requirement For Access Control"),
	}

	model.ToUpdateRequest(ctx, &diags)

	assert.True(t, diags.HasError(), "expected an error diagnostic for unknown description")
}

// TestControlModel_ToUpdateRequest_UnknownSubcategoryAddsError verifies an
// unknown subcategory is rejected instead of being sent as "".
func TestControlModel_ToUpdateRequest_UnknownSubcategoryAddsError(t *testing.T) {
	ctx := context.Background()
	diags := diag.Diagnostics{}

	model := &ControlModel{
		ID:          types.StringValue("control-id-123"),
		Name:        types.StringValue("Custom Access Control Policy"),
		Description: types.StringValue("Enforce access control policies and procedures"),
		Category:    types.StringValue("01.0 - Access Control"),
		Subcategory: types.StringUnknown(),
	}

	model.ToUpdateRequest(ctx, &diags)

	assert.True(t, diags.HasError(), "expected an error diagnostic for unknown subcategory")
}

// TestControlModel_RefreshFromRemote_NullKeptWhenRemoteEmpty verifies that an
// attribute omitted from configuration (null in plan/state) stays null when
// the backend returns "". description and subcategory are Optional-only, so
// turning null into "" would make Terraform report an inconsistent result.
func TestControlModel_RefreshFromRemote_NullKeptWhenRemoteEmpty(t *testing.T) {
	ctx := context.Background()
	diags := diag.Diagnostics{}

	model := &ControlModel{
		Description: types.StringNull(),
		Subcategory: types.StringNull(),
	}
	remote := &complianceTypes.Control{
		ID:       "control-id-123",
		Name:     "Custom Access Control Policy",
		Category: "01.0 - Access Control",
	}

	model.RefreshFromRemote(ctx, &diags, remote)

	require.False(t, diags.HasError(), "unexpected diagnostics: %v", diags)
	assert.True(t, model.Description.IsNull(), "omitted description must stay null")
	assert.True(t, model.Subcategory.IsNull(), "omitted subcategory must stay null")
}

// TestControlModel_RefreshFromRemote_RemoteValueOverridesNull verifies drift
// detection: if the backend has a value the configuration does not, state
// records it so the next plan clears it.
func TestControlModel_RefreshFromRemote_RemoteValueOverridesNull(t *testing.T) {
	ctx := context.Background()
	diags := diag.Diagnostics{}

	model := &ControlModel{
		Description: types.StringNull(),
		Subcategory: types.StringNull(),
	}
	remote := &complianceTypes.Control{
		ID:          "control-id-123",
		Name:        "Custom Access Control Policy",
		Category:    "01.0 - Access Control",
		Description: "Enforce access control policies and procedures",
		Subcategory: "01.01 Business Requirement For Access Control",
	}

	model.RefreshFromRemote(ctx, &diags, remote)

	require.False(t, diags.HasError(), "unexpected diagnostics: %v", diags)
	assert.Equal(t, types.StringValue("Enforce access control policies and procedures"), model.Description)
	assert.Equal(t, types.StringValue("01.01 Business Requirement For Access Control"), model.Subcategory)
}

// TestControlModel_ToUpdateRequest_NullClearsFields verifies that removing
// description and subcategory from configuration (null in plan) sends both as
// "" so the edit API clears them on the backend.
func TestControlModel_ToUpdateRequest_NullClearsFields(t *testing.T) {
	ctx := context.Background()
	diags := diag.Diagnostics{}

	model := &ControlModel{
		ID:          types.StringValue("control-id-123"),
		Name:        types.StringValue("Custom Access Control Policy"),
		Category:    types.StringValue("01.0 - Access Control"),
		Description: types.StringNull(),
		Subcategory: types.StringNull(),
	}

	req := model.ToUpdateRequest(ctx, &diags)

	require.False(t, diags.HasError(), "unexpected diagnostics: %v", diags)
	assert.Equal(t, "", req.Description)
	assert.Equal(t, "", req.Subcategory)
}

// TestControlModel_RefreshFromRemote_NormalizedLabelsKeepConfiguredCasing
// verifies that the API's Title Case normalization of category and
// subcategory does not overwrite the configured casing, which would make
// Terraform report an inconsistent result after apply.
func TestControlModel_RefreshFromRemote_NormalizedLabelsKeepConfiguredCasing(t *testing.T) {
	ctx := context.Background()
	diags := diag.Diagnostics{}

	model := &ControlModel{
		Category:    types.StringValue("my custom category"),
		Subcategory: types.StringValue("  my custom subcategory"),
	}
	remote := &complianceTypes.Control{
		ID:          "control-id-123",
		Name:        "Custom Access Control Policy",
		Category:    "My Custom Category",
		Subcategory: "My Custom Subcategory",
	}

	model.RefreshFromRemote(ctx, &diags, remote)

	require.False(t, diags.HasError(), "unexpected diagnostics: %v", diags)
	assert.Equal(t, types.StringValue("my custom category"), model.Category)
	assert.Equal(t, types.StringValue("  my custom subcategory"), model.Subcategory)
}

// TestControlModel_RefreshFromRemote_DifferentLabelsTakeRemote verifies that a
// remote category or subcategory that differs from the current value beyond
// normalization (out-of-band drift) replaces it.
func TestControlModel_RefreshFromRemote_DifferentLabelsTakeRemote(t *testing.T) {
	ctx := context.Background()
	diags := diag.Diagnostics{}

	model := &ControlModel{
		Category:    types.StringValue("my custom category"),
		Subcategory: types.StringValue("my custom subcategory"),
	}
	remote := &complianceTypes.Control{
		ID:          "control-id-123",
		Name:        "Custom Access Control Policy",
		Category:    "Changed Elsewhere",
		Subcategory: "Also Changed",
	}

	model.RefreshFromRemote(ctx, &diags, remote)

	require.False(t, diags.HasError(), "unexpected diagnostics: %v", diags)
	assert.Equal(t, types.StringValue("Changed Elsewhere"), model.Category)
	assert.Equal(t, types.StringValue("Also Changed"), model.Subcategory)
}

// TestControlModel_RefreshFromRemote_NullLabelsTakeRemote verifies that null
// current values (import, where there is no prior configuration) take the
// remote value as stored.
func TestControlModel_RefreshFromRemote_NullLabelsTakeRemote(t *testing.T) {
	ctx := context.Background()
	diags := diag.Diagnostics{}

	model := &ControlModel{
		Category:    types.StringNull(),
		Subcategory: types.StringNull(),
	}
	remote := &complianceTypes.Control{
		ID:          "control-id-123",
		Name:        "Custom Access Control Policy",
		Category:    "My Custom Category",
		Subcategory: "My Custom Subcategory",
	}

	model.RefreshFromRemote(ctx, &diags, remote)

	require.False(t, diags.HasError(), "unexpected diagnostics: %v", diags)
	assert.Equal(t, types.StringValue("My Custom Category"), model.Category)
	assert.Equal(t, types.StringValue("My Custom Subcategory"), model.Subcategory)
}

// TestControlModel_RefreshFromRemote_OmittedSubcategoryStaysNull verifies the
// normalization handling does not change the omitted-subcategory behavior.
func TestControlModel_RefreshFromRemote_OmittedSubcategoryStaysNull(t *testing.T) {
	ctx := context.Background()
	diags := diag.Diagnostics{}

	model := &ControlModel{
		Category:    types.StringValue("my custom category"),
		Subcategory: types.StringNull(),
	}
	remote := &complianceTypes.Control{
		ID:       "control-id-123",
		Name:     "Custom Access Control Policy",
		Category: "My Custom Category",
	}

	model.RefreshFromRemote(ctx, &diags, remote)

	require.False(t, diags.HasError(), "unexpected diagnostics: %v", diags)
	assert.True(t, model.Subcategory.IsNull(), "omitted subcategory must stay null")
	assert.Equal(t, types.StringValue("my custom category"), model.Category)
}

// TestControlModel_ToRequests_SendRawLabelCasing verifies the configured
// category and subcategory reach the API unchanged; normalization is the
// API's responsibility.
func TestControlModel_ToRequests_SendRawLabelCasing(t *testing.T) {
	ctx := context.Background()
	diags := diag.Diagnostics{}

	model := &ControlModel{
		ID:          types.StringValue("control-id-123"),
		Name:        types.StringValue("Custom Access Control Policy"),
		Category:    types.StringValue("my custom category"),
		Subcategory: types.StringValue("my custom subcategory"),
	}

	createReq := model.ToCreateRequest(ctx, &diags)
	updateReq := model.ToUpdateRequest(ctx, &diags)

	require.False(t, diags.HasError(), "unexpected diagnostics: %v", diags)
	assert.Equal(t, "my custom category", createReq.Category)
	assert.Equal(t, "my custom subcategory", createReq.Subcategory)
	assert.Equal(t, "my custom category", updateReq.Category)
	assert.Equal(t, "my custom subcategory", updateReq.Subcategory)
}

// TestControlModel_ToCreateRequest_EmptySubcategoryPassedThrough verifies create
// maps an empty subcategory to "".
func TestControlModel_ToCreateRequest_EmptySubcategoryPassedThrough(t *testing.T) {
	ctx := context.Background()
	diags := diag.Diagnostics{}

	model := &ControlModel{
		Name:        types.StringValue("Custom Access Control Policy"),
		Category:    types.StringValue("01.0 - Access Control"),
		Subcategory: types.StringValue(""),
	}

	req := model.ToCreateRequest(ctx, &diags)

	require.False(t, diags.HasError(), "unexpected diagnostics: %v", diags)
	assert.Equal(t, "Custom Access Control Policy", req.ControlName)
	assert.Equal(t, "01.0 - Access Control", req.Category)
	assert.Equal(t, "", req.Subcategory)
}
