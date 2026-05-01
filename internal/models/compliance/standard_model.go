// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package models

import (
	"context"

	complianceTypes "github.com/PaloAltoNetworks/cortex-cloud-go/types/compliance"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// StandardModel is the Terraform model for a compliance standard.
type StandardModel struct {
	ID                       types.String `tfsdk:"id"`
	Name                     types.String `tfsdk:"name"`
	Description              types.String `tfsdk:"description"`
	Version                  types.String `tfsdk:"version"`
	AssessmentsProfilesCount types.Int64  `tfsdk:"assessments_profiles_count"`
	ControlsIDs              types.Set    `tfsdk:"controls_ids"`
	Labels                   types.Set    `tfsdk:"labels"`
	Revision                 types.Int64  `tfsdk:"revision"`
	Publisher                types.String `tfsdk:"publisher"`
	ReleaseDate              types.String `tfsdk:"release_date"`
	CreatedDate              types.String `tfsdk:"created_date"`
	CreatedBy                types.String `tfsdk:"created_by"`
	InsertTS                 types.Int64  `tfsdk:"insert_ts"`
	ModifyTS                 types.Int64  `tfsdk:"modify_ts"`
	IsCustom                 types.Bool   `tfsdk:"is_custom"`
}

// RefreshFromRemote updates the Terraform model from the SDK response.
func (m *StandardModel) RefreshFromRemote(ctx context.Context, diags *diag.Diagnostics, remote *complianceTypes.Standard) {
	tflog.Debug(ctx, "Refreshing compliance standard model from remote")

	if remote == nil {
		diags.AddError("Compliance Standard Not Found", "The requested compliance standard does not exist.")
		return
	}

	// Set simple fields
	m.ID = types.StringValue(remote.ID)
	m.Name = types.StringValue(remote.Name)
	m.Description = types.StringValue(remote.Description)
	m.Version = types.StringValue(remote.Version)
	m.AssessmentsProfilesCount = types.Int64Value(int64(remote.AssessmentsProfilesCount))
	m.Revision = types.Int64Value(remote.Revision)
	m.Publisher = types.StringValue(remote.Publisher)
	m.ReleaseDate = types.StringValue(remote.ReleaseDate)
	m.CreatedDate = types.StringValue(remote.CreatedDate)
	m.CreatedBy = types.StringValue(remote.CreatedBy)
	m.InsertTS = types.Int64Value(remote.InsertTS)
	m.ModifyTS = types.Int64Value(remote.ModifyTS)
	m.IsCustom = types.BoolValue(remote.IsCustom)

	// Convert controls_ids to a Set (unordered) to avoid order mismatch with API response
	if len(remote.ControlsIDs) == 0 {
		m.ControlsIDs = types.SetNull(types.StringType)
	} else {
		elements := make([]attr.Value, len(remote.ControlsIDs))
		for i, id := range remote.ControlsIDs {
			elements[i] = types.StringValue(id)
		}
		setValue, setDiags := types.SetValue(types.StringType, elements)
		diags.Append(setDiags...)
		if diags.HasError() {
			return
		}
		m.ControlsIDs = setValue
	}

	// Convert labels to a Set (unordered) to avoid order mismatch with API response
	if len(remote.Labels) == 0 {
		m.Labels = types.SetNull(types.StringType)
	} else {
		elements := make([]attr.Value, len(remote.Labels))
		for i, label := range remote.Labels {
			elements[i] = types.StringValue(label)
		}
		setValue, setDiags := types.SetValue(types.StringType, elements)
		diags.Append(setDiags...)
		if diags.HasError() {
			return
		}
		m.Labels = setValue
	}
}

// ToCreateRequest converts the Terraform model to an SDK create request.
func (m *StandardModel) ToCreateRequest(ctx context.Context, diags *diag.Diagnostics) complianceTypes.CreateStandardRequest {
	tflog.Debug(ctx, "Converting standard model to create request")

	req := complianceTypes.CreateStandardRequest{
		StandardName: m.Name.ValueString(),
		Description:  m.Description.ValueString(),
	}

	// Convert controls_ids
	if !m.ControlsIDs.IsNull() && !m.ControlsIDs.IsUnknown() {
		var controlsIDs []string
		diags.Append(m.ControlsIDs.ElementsAs(ctx, &controlsIDs, false)...)
		if diags.HasError() {
			return req
		}
		req.ControlsIDs = controlsIDs
	}

	// Convert labels
	if !m.Labels.IsNull() && !m.Labels.IsUnknown() {
		var labels []string
		diags.Append(m.Labels.ElementsAs(ctx, &labels, false)...)
		if diags.HasError() {
			return req
		}
		req.Labels = labels
	}

	return req
}

// ToUpdateRequest converts the Terraform model to an SDK update request.
// Note: API requires labels and controls_ids to always be present as lists.
func (m *StandardModel) ToUpdateRequest(ctx context.Context, diags *diag.Diagnostics) complianceTypes.UpdateStandardRequest {
	tflog.Debug(ctx, "Converting standard model to update request")

	req := complianceTypes.UpdateStandardRequest{
		ID:           m.ID.ValueString(),
		StandardName: m.Name.ValueString(),
		Description:  m.Description.ValueString(),
		Labels:       []string{}, // Initialize as empty list
		ControlsIDs:  []string{}, // Initialize as empty list
	}

	// Convert controls_ids (required field, must be present)
	if !m.ControlsIDs.IsNull() && !m.ControlsIDs.IsUnknown() {
		var controlsIDs []string
		diags.Append(m.ControlsIDs.ElementsAs(ctx, &controlsIDs, false)...)
		if diags.HasError() {
			return req
		}
		req.ControlsIDs = controlsIDs
	}

	// Convert labels (required field, must be present)
	if !m.Labels.IsNull() && !m.Labels.IsUnknown() {
		var labels []string
		diags.Append(m.Labels.ElementsAs(ctx, &labels, false)...)
		if diags.HasError() {
			return req
		}
		req.Labels = labels
	}

	return req
}
