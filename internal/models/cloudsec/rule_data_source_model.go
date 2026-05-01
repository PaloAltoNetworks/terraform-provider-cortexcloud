// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package models

import (
	"context"
	"strings"

	cloudsecTypes "github.com/PaloAltoNetworks/cortex-cloud-go/types/cloudsec"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// GetRuleDataSourceAttrTypes returns the attribute types for CloudSecRuleDataSourceModel.
// This is used when creating types.List values containing rule objects.
func GetRuleDataSourceAttrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"id":                   types.StringType,
		"name":                 types.StringType,
		"description":          types.StringType,
		"class":                types.StringType,
		"type":                 types.StringType,
		"asset_types":          types.ListType{ElemType: types.StringType},
		"severity":             types.StringType,
		"enabled":              types.BoolType,
		"system_default":       types.BoolType,
		"providers":            types.ListType{ElemType: types.StringType},
		"compliance_metadata":  types.ListType{ElemType: types.ObjectType{AttrTypes: GetComplianceMetadataAttrTypes()}},
		"compliance_standards": types.ListType{ElemType: types.StringType},
		"labels":               types.ListType{ElemType: types.StringType},
		"created_by":           types.StringType,
		"created_on":           types.Int64Type,
		"last_modified_by":     types.StringType,
		"last_modified_on":     types.Int64Type,
		"module":               types.StringType,
	}
}

// CloudSecRuleDataSourceModel represents the Terraform model for a CloudSec rule data source.
// This is a read-only model used for data source queries.
type CloudSecRuleDataSourceModel struct {
	ID                  types.String `tfsdk:"id"`
	Name                types.String `tfsdk:"name"`
	Description         types.String `tfsdk:"description"`
	Class               types.String `tfsdk:"class"`
	Type                types.String `tfsdk:"type"`
	AssetTypes          types.List   `tfsdk:"asset_types"`
	Severity            types.String `tfsdk:"severity"`
	Enabled             types.Bool   `tfsdk:"enabled"`
	SystemDefault       types.Bool   `tfsdk:"system_default"`
	Providers           types.List   `tfsdk:"providers"`
	ComplianceMetadata  types.List   `tfsdk:"compliance_metadata"`
	ComplianceStandards types.List   `tfsdk:"compliance_standards"`
	Labels              types.List   `tfsdk:"labels"`
	CreatedBy           types.String `tfsdk:"created_by"`
	CreatedOn           types.Int64  `tfsdk:"created_on"`
	LastModifiedBy      types.String `tfsdk:"last_modified_by"`
	LastModifiedOn      types.Int64  `tfsdk:"last_modified_on"`
	Module              types.String `tfsdk:"module"`
}

// FromSDKRuleData populates the data source model from SDK RuleData.
// This is used when reading rule data from search/list operations.
func (m *CloudSecRuleDataSourceModel) FromSDKRuleData(ctx context.Context, diags *diag.Diagnostics, remote *cloudsecTypes.RuleData) {
	if remote == nil {
		diags.AddError("Rule not found", "The requested rule does not exist.")
		return
	}

	m.ID = types.StringValue(remote.ID)
	m.Name = types.StringValue(remote.Name)
	m.Description = types.StringValue(remote.Description)
	m.Class = types.StringValue(remote.Class)
	m.Type = types.StringValue(remote.Type)
	m.Severity = types.StringValue(remote.Severity)
	m.Enabled = types.BoolValue(remote.Enabled)
	m.SystemDefault = types.BoolValue(remote.SystemDefault)
	m.CreatedBy = types.StringValue(remote.CreatedBy)
	m.CreatedOn = types.Int64Value(remote.CreatedOn)
	m.LastModifiedBy = types.StringValue(remote.LastModifiedBy)
	m.LastModifiedOn = types.Int64Value(remote.LastModifiedOn)
	m.Module = types.StringValue(remote.Module)

	// Asset Types
	if len(remote.AssetTypes) > 0 {
		assetTypesList, d := types.ListValueFrom(ctx, types.StringType, remote.AssetTypes)
		diags.Append(d...)
		m.AssetTypes = assetTypesList
	} else {
		m.AssetTypes = types.ListNull(types.StringType)
	}

	// Providers
	if len(remote.Providers) > 0 {
		providersList, d := types.ListValueFrom(ctx, types.StringType, remote.Providers)
		diags.Append(d...)
		m.Providers = providersList
	} else {
		m.Providers = types.ListNull(types.StringType)
	}

	// Compliance Standards
	if len(remote.ComplianceStandards) > 0 {
		standardsList, d := types.ListValueFrom(ctx, types.StringType, remote.ComplianceStandards)
		diags.Append(d...)
		m.ComplianceStandards = standardsList
	} else {
		m.ComplianceStandards = types.ListNull(types.StringType)
	}

	// Labels
	if len(remote.Labels) > 0 {
		labelsList, d := types.ListValueFrom(ctx, types.StringType, remote.Labels)
		diags.Append(d...)
		m.Labels = labelsList
	} else {
		m.Labels = types.ListNull(types.StringType)
	}

	// Compliance Metadata
	if len(remote.ComplianceMetadata) > 0 {
		// Reuse the compliance metadata conversion from rule_model.go
		complianceElems := make([]attr.Value, 0, len(remote.ComplianceMetadata))
		for _, cm := range remote.ComplianceMetadata {
			cmObj, d := types.ObjectValue(
				GetComplianceMetadataAttrTypes(),
				map[string]attr.Value{
					"control_id":    types.StringValue(cm.ControlID),
					"standard_id":   types.StringValue(cm.StandardID),
					"standard_name": types.StringValue(cm.StandardName),
					"control_name":  types.StringValue(cm.ControlName),
				},
			)
			diags.Append(d...)
			complianceElems = append(complianceElems, cmObj)
		}

		complianceList, d := types.ListValue(
			types.ObjectType{AttrTypes: GetComplianceMetadataAttrTypes()},
			complianceElems,
		)
		diags.Append(d...)
		m.ComplianceMetadata = complianceList
	} else {
		m.ComplianceMetadata = types.ListNull(types.ObjectType{AttrTypes: GetComplianceMetadataAttrTypes()})
	}
}

// FromSDKRuleResponse populates the data source model from SDK RuleResponse.
// This is used when reading a specific rule by ID.
func (m *CloudSecRuleDataSourceModel) FromSDKRuleResponse(ctx context.Context, diags *diag.Diagnostics, remote *cloudsecTypes.RuleResponse) {
	if remote == nil {
		diags.AddError("Rule not found", "The requested rule does not exist.")
		return
	}

	m.ID = types.StringValue(remote.ID)
	m.Name = types.StringValue(remote.Name)
	m.Description = types.StringValue(remote.Description)
	m.Class = types.StringValue(remote.Class)
	m.Type = types.StringValue(remote.Type)
	m.Severity = types.StringValue(strings.ToLower(remote.Severity))
	m.Enabled = types.BoolValue(remote.Enabled)
	m.SystemDefault = types.BoolValue(remote.SystemDefault)
	m.CreatedBy = types.StringValue(remote.CreatedBy)
	m.CreatedOn = types.Int64Value(remote.CreatedOn)
	m.LastModifiedBy = types.StringValue(remote.LastModifiedBy)
	m.LastModifiedOn = types.Int64Value(remote.LastModifiedOn)

	// Module is not in RuleResponse, set to null
	m.Module = types.StringNull()

	// Asset Types
	if len(remote.AssetTypes) > 0 {
		assetTypesList, d := types.ListValueFrom(ctx, types.StringType, remote.AssetTypes)
		diags.Append(d...)
		m.AssetTypes = assetTypesList
	} else {
		m.AssetTypes = types.ListNull(types.StringType)
	}

	// Providers
	if len(remote.Providers) > 0 {
		providersList, d := types.ListValueFrom(ctx, types.StringType, remote.Providers)
		diags.Append(d...)
		m.Providers = providersList
	} else {
		m.Providers = types.ListNull(types.StringType)
	}

	// Compliance Standards - not in RuleResponse, set to null
	m.ComplianceStandards = types.ListNull(types.StringType)

	// Labels
	if len(remote.Labels) > 0 {
		labelsList, d := types.ListValueFrom(ctx, types.StringType, remote.Labels)
		diags.Append(d...)
		m.Labels = labelsList
	} else {
		m.Labels = types.ListNull(types.StringType)
	}

	// Compliance Metadata
	if len(remote.ComplianceMetadata) > 0 {
		complianceElems := make([]attr.Value, 0, len(remote.ComplianceMetadata))
		for _, cm := range remote.ComplianceMetadata {
			cmObj, d := types.ObjectValue(
				GetComplianceMetadataAttrTypes(),
				map[string]attr.Value{
					"control_id":    types.StringValue(cm.ControlID),
					"standard_id":   types.StringValue(cm.StandardID),
					"standard_name": types.StringValue(cm.StandardName),
					"control_name":  types.StringValue(cm.ControlName),
				},
			)
			diags.Append(d...)
			complianceElems = append(complianceElems, cmObj)
		}

		complianceList, d := types.ListValue(
			types.ObjectType{AttrTypes: GetComplianceMetadataAttrTypes()},
			complianceElems,
		)
		diags.Append(d...)
		m.ComplianceMetadata = complianceList
	} else {
		m.ComplianceMetadata = types.ListNull(types.ObjectType{AttrTypes: GetComplianceMetadataAttrTypes()})
	}
}
