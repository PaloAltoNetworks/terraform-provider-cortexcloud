// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package models

import (
	"context"
	"testing"

	complianceTypes "github.com/PaloAltoNetworks/cortex-cloud-go/types/compliance"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAssessmentProfileModel_ToUpdateRequest_EnabledTrue(t *testing.T) {
	ctx := context.Background()
	diags := diag.Diagnostics{}

	model := AssessmentProfileModel{
		ID:           types.StringValue("test-id"),
		Name:         types.StringValue("Test Profile"),
		StandardID:   types.StringValue("std-123"),
		AssetGroupID: types.Int64Value(1),
		Description:  types.StringValue("Test description"),
		ReportType:   types.StringValue("NONE"),
		Enabled:      types.BoolValue(true),
	}

	req := model.ToUpdateRequest(ctx, &diags)

	require.False(t, diags.HasError(), "unexpected diagnostics: %v", diags)
	assert.Equal(t, "yes", req.Enabled, "enabled=true should map to 'yes'")
	assert.Equal(t, "test-id", req.ID)
	assert.Equal(t, "Test Profile", req.ProfileName)
}

func TestAssessmentProfileModel_ToUpdateRequest_EnabledFalse(t *testing.T) {
	ctx := context.Background()
	diags := diag.Diagnostics{}

	model := AssessmentProfileModel{
		ID:           types.StringValue("test-id"),
		Name:         types.StringValue("Test Profile"),
		StandardID:   types.StringValue("std-123"),
		AssetGroupID: types.Int64Value(1),
		Description:  types.StringValue("Test description"),
		ReportType:   types.StringValue("NONE"),
		Enabled:      types.BoolValue(false),
	}

	req := model.ToUpdateRequest(ctx, &diags)

	require.False(t, diags.HasError(), "unexpected diagnostics: %v", diags)
	assert.Equal(t, "no", req.Enabled, "enabled=false should map to 'no'")
}

func TestAssessmentProfileModel_ToCreateRequest_DoesNotIncludeEnabled(t *testing.T) {
	ctx := context.Background()
	diags := diag.Diagnostics{}

	model := AssessmentProfileModel{
		Name:         types.StringValue("Test Profile"),
		StandardID:   types.StringValue("std-123"),
		AssetGroupID: types.Int64Value(1),
		Description:  types.StringValue("Test description"),
		ReportType:   types.StringValue("NONE"),
		Enabled:      types.BoolValue(false),
	}

	req := model.ToCreateRequest(ctx, &diags)

	require.False(t, diags.HasError(), "unexpected diagnostics: %v", diags)
	// CreateAssessmentProfileRequest does not have an Enabled field,
	// so this test verifies the create request is built without error
	// even when the model has enabled=false.
	assert.Equal(t, "Test Profile", req.ProfileName)
	assert.Equal(t, "1", req.AssetGroupID)
	assert.Equal(t, "std-123", req.StandardID)
}

func TestAssessmentProfileModel_RefreshFromRemote_EnabledTrue(t *testing.T) {
	ctx := context.Background()
	diags := diag.Diagnostics{}

	model := AssessmentProfileModel{}
	remote := &complianceTypes.AssessmentProfile{
		ID:           "test-id",
		Name:         "Test Profile",
		StandardID:   "std-123",
		AssetGroupID: 1,
		Enabled:      true,
		ReportType:   "NONE",
	}

	model.RefreshFromRemote(ctx, &diags, remote)

	require.False(t, diags.HasError(), "unexpected diagnostics: %v", diags)
	assert.True(t, model.Enabled.ValueBool(), "enabled should be true")
}

func TestAssessmentProfileModel_RefreshFromRemote_EnabledFalse(t *testing.T) {
	ctx := context.Background()
	diags := diag.Diagnostics{}

	model := AssessmentProfileModel{}
	remote := &complianceTypes.AssessmentProfile{
		ID:           "test-id",
		Name:         "Test Profile",
		StandardID:   "std-123",
		AssetGroupID: 1,
		Enabled:      false,
		ReportType:   "NONE",
	}

	model.RefreshFromRemote(ctx, &diags, remote)

	require.False(t, diags.HasError(), "unexpected diagnostics: %v", diags)
	assert.False(t, model.Enabled.ValueBool(), "enabled should be false")
}
