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

	// Handle optional string fields - use null for empty strings
	if remote.Description == "" {
		m.Description = types.StringNull()
	} else {
		m.Description = types.StringValue(remote.Description)
	}

	m.Category = types.StringValue(remote.Category)

	if remote.CategoryDescription == "" {
		m.CategoryDescription = types.StringNull()
	} else {
		m.CategoryDescription = types.StringValue(remote.CategoryDescription)
	}

	// Always store subcategory as a string value (never null) since the schema
	// uses Default: stringdefault.StaticString(""). Converting "" to null would
	// cause state drift on every plan.
	m.Subcategory = types.StringValue(remote.Subcategory)

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

	m.Supported = types.BoolValue(remote.Supported)
	m.InsertionTime = types.Int64Value(remote.InsertionTime)
	m.ModificationTime = types.Int64Value(remote.ModificationTime)
	m.CreatedBy = types.StringValue(remote.CreatedBy)
	m.Enabled = types.BoolValue(remote.Enabled)
	m.IsCustom = types.BoolValue(remote.IsCustom)

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
func (m *ControlModel) ToUpdateRequest(ctx context.Context, diags *diag.Diagnostics) complianceTypes.UpdateControlRequest {
	tflog.Debug(ctx, "Converting control model to update request")

	req := complianceTypes.UpdateControlRequest{
		ID:          m.ID.ValueString(),
		ControlName: m.Name.ValueString(),
		Description: m.Description.ValueString(),
		Category:    m.Category.ValueString(),
		Subcategory: m.Subcategory.ValueString(),
	}

	return req
}
