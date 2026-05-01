// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package models

import (
	"context"
	"strconv"
	"strings"

	complianceTypes "github.com/PaloAltoNetworks/cortex-cloud-go/types/compliance"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// AssessmentProfileModel is the Terraform model for a compliance assessment profile.
type AssessmentProfileModel struct {
	ID              types.String `tfsdk:"id"`
	Name            types.String `tfsdk:"name"`
	StandardID      types.String `tfsdk:"standard_id"`
	StandardName    types.String `tfsdk:"standard_name"`
	AssetGroupID    types.Int64  `tfsdk:"asset_group_id"`
	AssetGroupName  types.String `tfsdk:"asset_group_name"`
	Description     types.String `tfsdk:"description"`
	ReportFrequency types.String `tfsdk:"report_frequency"`
	ReportTargets   types.List   `tfsdk:"report_targets"`
	ReportType      types.String `tfsdk:"report_type"`
	Enabled         types.Bool   `tfsdk:"enabled"`
	InsertTS        types.Int64  `tfsdk:"insert_ts"`
	ModifyTS        types.Int64  `tfsdk:"modify_ts"`
	CreatedBy       types.String `tfsdk:"created_by"`
	ModifiedBy      types.String `tfsdk:"modified_by"`
}

// RefreshFromRemote updates the Terraform model from the SDK response.
func (m *AssessmentProfileModel) RefreshFromRemote(ctx context.Context, diags *diag.Diagnostics, remote *complianceTypes.AssessmentProfile) {
	tflog.Debug(ctx, "Refreshing compliance assessment profile model from remote")

	if remote == nil {
		diags.AddError("Compliance Assessment Profile Not Found", "The requested compliance assessment profile does not exist.")
		return
	}

	// Set simple fields
	m.ID = types.StringValue(remote.ID)
	m.Name = types.StringValue(remote.Name)
	m.StandardID = types.StringValue(remote.StandardID)
	m.StandardName = types.StringValue(remote.StandardName)
	m.AssetGroupID = types.Int64Value(int64(remote.AssetGroupID))
	m.AssetGroupName = types.StringValue(remote.AssetGroupName)
	m.Description = types.StringValue(remote.Description)
	// Normalize report_type to uppercase to avoid case mismatch between
	// user config (e.g., "ALL") and API response (e.g., "All").
	// The API normalizes report_type to title case, but Terraform expects
	// the value to match what the user configured (uppercase).
	m.ReportType = types.StringValue(strings.ToUpper(remote.ReportType))
	m.Enabled = types.BoolValue(remote.Enabled)
	m.InsertTS = types.Int64Value(remote.InsertTS)
	m.ModifyTS = types.Int64Value(remote.ModifyTS)
	m.CreatedBy = types.StringValue(remote.CreatedBy)
	m.ModifiedBy = types.StringValue(remote.ModifiedBy)

	// Handle optional ReportFrequency
	if remote.ReportFrequency != nil {
		m.ReportFrequency = types.StringValue(*remote.ReportFrequency)
	} else {
		m.ReportFrequency = types.StringNull()
	}

	// Convert report_targets list
	// Note: API may return empty array even when targets were set
	// Preserve the existing value if API returns empty but we have a value
	if len(remote.ReportTargets) == 0 {
		// Only set to null if we don't already have a value
		if m.ReportTargets.IsNull() || m.ReportTargets.IsUnknown() {
			m.ReportTargets = types.ListNull(types.StringType)
		}
		// Otherwise keep the existing value (API bug workaround)
	} else {
		elements := make([]attr.Value, len(remote.ReportTargets))
		for i, target := range remote.ReportTargets {
			elements[i] = types.StringValue(target)
		}
		listValue, listDiags := types.ListValue(types.StringType, elements)
		diags.Append(listDiags...)
		if diags.HasError() {
			return
		}
		m.ReportTargets = listValue
	}
}

// ToCreateRequest converts the Terraform model to an SDK create request.
func (m *AssessmentProfileModel) ToCreateRequest(ctx context.Context, diags *diag.Diagnostics) complianceTypes.CreateAssessmentProfileRequest {
	tflog.Debug(ctx, "Converting assessment profile model to create request")

	req := complianceTypes.CreateAssessmentProfileRequest{
		ProfileName:  m.Name.ValueString(),
		StandardID:   m.StandardID.ValueString(),
		AssetGroupID: strconv.FormatInt(m.AssetGroupID.ValueInt64(), 10),
		Description:  m.Description.ValueString(),
		ReportType:   m.ReportType.ValueString(),
	}

	// Only set evaluation_frequency and report_targets if report_type is not "NONE"
	if m.ReportType.ValueString() != "NONE" {
		if !m.ReportFrequency.IsNull() && !m.ReportFrequency.IsUnknown() {
			req.EvaluationFrequency = m.ReportFrequency.ValueString()
		}

		if !m.ReportTargets.IsNull() && !m.ReportTargets.IsUnknown() {
			var targets []string
			diags.Append(m.ReportTargets.ElementsAs(ctx, &targets, false)...)
			if diags.HasError() {
				return req
			}
			req.ReportTargets = targets
		}
	}

	return req
}

// ToUpdateRequest converts the Terraform model to an SDK update request.
func (m *AssessmentProfileModel) ToUpdateRequest(ctx context.Context, diags *diag.Diagnostics) complianceTypes.UpdateAssessmentProfileRequest {
	tflog.Debug(ctx, "Converting assessment profile model to update request")

	req := complianceTypes.UpdateAssessmentProfileRequest{
		ID:           m.ID.ValueString(),
		ProfileName:  m.Name.ValueString(),
		StandardID:   m.StandardID.ValueString(),
		AssetGroupID: strconv.FormatInt(m.AssetGroupID.ValueInt64(), 10),
		Description:  m.Description.ValueString(),
		ReportType:   m.ReportType.ValueString(),
	}

	// Set enabled status
	if m.Enabled.ValueBool() {
		req.Enabled = "yes"
	} else {
		req.Enabled = "no"
	}

	// Only set evaluation_frequency and report_targets if report_type is not "NONE"
	if m.ReportType.ValueString() != "NONE" {
		if !m.ReportFrequency.IsNull() && !m.ReportFrequency.IsUnknown() {
			req.EvaluationFrequency = m.ReportFrequency.ValueString()
		}

		if !m.ReportTargets.IsNull() && !m.ReportTargets.IsUnknown() {
			var targets []string
			diags.Append(m.ReportTargets.ElementsAs(ctx, &targets, false)...)
			if diags.HasError() {
				return req
			}
			req.ReportTargets = targets
		}
	}

	return req
}
