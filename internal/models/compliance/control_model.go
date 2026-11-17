// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package models

import (
	"context"

	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/util"
	complianceTypes "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/types/compliance"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// ControlModel is the Terraform model for a compliance control.
type ControlModel struct {
	ID                     types.String `tfsdk:"id"`
	Name                   types.String `tfsdk:"name"`
	Description            types.String `tfsdk:"description"`
	Category               types.String `tfsdk:"category"`
	CategoryDescription    types.String `tfsdk:"category_description"`
	Subcategory            types.String `tfsdk:"subcategory"`
	SubcategoryDescription types.String `tfsdk:"subcategory_description"`
	Standards              types.List   `tfsdk:"standards"`
	Severity               types.String `tfsdk:"severity"`
	Supported              types.Bool   `tfsdk:"supported"`
	InsertionTime          types.Int64  `tfsdk:"insertion_time"`
	ModificationTime       types.Int64  `tfsdk:"modification_time"`
	ModifiedBy             types.String `tfsdk:"modified_by"`
	CreatedBy              types.String `tfsdk:"created_by"`
	Enabled                types.Bool   `tfsdk:"enabled"`
	IsCustom               types.Bool   `tfsdk:"is_custom"`
}

// RefreshFromRemote updates the Terraform model from the SDK response.
func (m *ControlModel) RefreshFromRemote(ctx context.Context, diags *diag.Diagnostics, remote *complianceTypes.Control) {
	tflog.Debug(ctx, "Refreshing compliance control model from remote")

	if remote == nil {
		diags.AddError("Compliance Control Not Found", "The requested compliance control does not exist.")
		return
	}

	// Set simple fields
	m.ID = types.StringValue(remote.ID)
	m.Name = types.StringValue(remote.Name)

	// description and subcategory are Optional-only. An omitted attribute is
	// null in plan/state and the backend returns "" for it, so keep null in
	// that case to avoid an inconsistent-result error and a perpetual diff.
	m.Description = optionalStringFromRemote(m.Description, remote.Description)

	// category and subcategory are normalized by the API (trimmed, Title
	// Cased), so the stored value can differ in casing from the configured one.
	// Keep the configured value when both are equal under normalization to
	// avoid an inconsistent-result error and a perpetual diff.
	m.Category = labelFromRemote(m.Category, remote.Category)

	if remote.CategoryDescription == "" {
		m.CategoryDescription = types.StringNull()
	} else {
		m.CategoryDescription = types.StringValue(remote.CategoryDescription)
	}

	m.Subcategory = optionalLabelFromRemote(m.Subcategory, remote.Subcategory)

	if remote.SubcategoryDescription == "" {
		m.SubcategoryDescription = types.StringNull()
	} else {
		m.SubcategoryDescription = types.StringValue(remote.SubcategoryDescription)
	}

	if remote.Severity == "" {
		m.Severity = types.StringNull()
	} else {
		m.Severity = types.StringValue(remote.Severity)
	}

	m.Supported = types.BoolValue(remote.Supported.Bool())
	m.InsertionTime = types.Int64Value(remote.InsertionTime)
	m.ModificationTime = types.Int64Value(remote.ModificationTime)
	m.CreatedBy = types.StringValue(remote.CreatedBy)
	m.Enabled = types.BoolValue(remote.Enabled.Bool())
	m.IsCustom = types.BoolValue(remote.IsCustom.Bool())

	// Handle optional ModifiedBy field
	if remote.ModifiedBy != nil {
		m.ModifiedBy = types.StringValue(*remote.ModifiedBy)
	} else {
		m.ModifiedBy = types.StringNull()
	}

	// Convert standards list
	if len(remote.Standards) == 0 {
		m.Standards = types.ListNull(types.StringType)
	} else {
		elements := make([]attr.Value, len(remote.Standards))
		for i, standard := range remote.Standards {
			elements[i] = types.StringValue(standard)
		}
		listValue, listDiags := types.ListValue(types.StringType, elements)
		diags.Append(listDiags...)
		if diags.HasError() {
			return
		}
		m.Standards = listValue
	}
}

// labelFromRemote maps a remote category or subcategory onto a string
// attribute. The API stores these normalized (see util.NormalizeControlLabel),
// so a known, non-null current value is kept when it is equal to the remote
// value under normalization. Otherwise the remote value wins, which keeps
// real drift visible and populates the value on import.
func labelFromRemote(current types.String, remote string) types.String {
	if !current.IsNull() && !current.IsUnknown() && util.EqualControlLabel(current.ValueString(), remote) {
		return current
	}
	return types.StringValue(remote)
}

// optionalLabelFromRemote is labelFromRemote for an Optional-only attribute:
// an empty remote value keeps a null current value null (attribute omitted
// from configuration).
func optionalLabelFromRemote(current types.String, remote string) types.String {
	if remote == "" && current.IsNull() {
		return types.StringNull()
	}
	return labelFromRemote(current, remote)
}

// optionalStringFromRemote maps a remote value onto an Optional-only string
// attribute. An empty remote value keeps the current value when it is null
// (attribute omitted from configuration); otherwise the remote value wins, so
// out-of-band changes still surface as drift.
func optionalStringFromRemote(current types.String, remote string) types.String {
	if remote == "" && current.IsNull() {
		return types.StringNull()
	}
	return types.StringValue(remote)
}

// ToCreateRequest converts the Terraform model to an SDK create request.
func (m *ControlModel) ToCreateRequest(ctx context.Context, diags *diag.Diagnostics) complianceTypes.CreateControlRequest {
	tflog.Debug(ctx, "Converting control model to create request")

	req := complianceTypes.CreateControlRequest{
		ControlName: m.Name.ValueString(),
		Description: m.Description.ValueString(),
		Category:    m.Category.ValueString(),
		Subcategory: m.Subcategory.ValueString(),
	}

	return req
}

// ToUpdateRequest converts the Terraform model to an SDK update request.
//
// Description and Subcategory are always sent (no omitempty). A null value,
// meaning the attribute was removed from configuration, is sent as "" so the
// edit API clears it on the backend. An unknown value is rejected rather than
// silently sent as "", since both attributes are Optional-only and should
// always be known at apply time.
func (m *ControlModel) ToUpdateRequest(ctx context.Context, diags *diag.Diagnostics) complianceTypes.UpdateControlRequest {
	tflog.Debug(ctx, "Converting control model to update request")

	for name, value := range map[string]types.String{
		"description": m.Description,
		"subcategory": m.Subcategory,
	} {
		if value.IsUnknown() {
			diags.AddError(
				"Unknown Compliance Control "+name,
				"The "+name+" is unknown at apply time. Sending it would clear the value on the backend, so the update was not sent. This is a provider bug; please report it.",
			)
		}
	}

	req := complianceTypes.UpdateControlRequest{
		ID:          m.ID.ValueString(),
		ControlName: m.Name.ValueString(),
		Description: m.Description.ValueString(),
		Category:    m.Category.ValueString(),
		Subcategory: m.Subcategory.ValueString(),
	}

	return req
}
