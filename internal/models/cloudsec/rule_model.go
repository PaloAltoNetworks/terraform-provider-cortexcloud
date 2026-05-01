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
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
)

// CloudSecRuleResourceModel represents the Terraform model for a CloudSec rule resource.
type CloudSecRuleResourceModel struct {
	ID                 types.String `tfsdk:"id"`
	Name               types.String `tfsdk:"name"`
	Description        types.String `tfsdk:"description"`
	Class              types.String `tfsdk:"class"`
	Type               types.String `tfsdk:"type"`
	AssetTypes         types.List   `tfsdk:"asset_types"`
	Severity           types.String `tfsdk:"severity"`
	Query              types.Object `tfsdk:"query"`
	Metadata           types.Object `tfsdk:"metadata"`
	ComplianceMetadata types.List   `tfsdk:"compliance_metadata"`
	Labels             types.Set    `tfsdk:"labels"`
	Enabled            types.Bool   `tfsdk:"enabled"`
	Providers          types.List   `tfsdk:"providers"`
	SystemDefault      types.Bool   `tfsdk:"system_default"`
	CreatedBy          types.String `tfsdk:"created_by"`
	CreatedOn          types.Int64  `tfsdk:"created_on"`
	LastModifiedBy     types.String `tfsdk:"last_modified_by"`
	LastModifiedOn     types.Int64  `tfsdk:"last_modified_on"`
	Deleted            types.Bool   `tfsdk:"deleted"`
	DeletedAt          types.Int64  `tfsdk:"deleted_at"`
	DeletedBy          types.String `tfsdk:"deleted_by"`
}

// RuleQueryModel represents the query block in a rule.
type RuleQueryModel struct {
	XQL types.String `tfsdk:"xql"`
}

// RuleMetadataModel represents the metadata block in a rule.
type RuleMetadataModel struct {
	Issue types.Object `tfsdk:"issue"`
}

// IssueModel represents the issue/recommendation block in metadata.
type IssueModel struct {
	Recommendation types.String `tfsdk:"recommendation"`
}

// ComplianceMetadataModel represents a compliance metadata item.
type ComplianceMetadataModel struct {
	ControlID    types.String `tfsdk:"control_id"`
	StandardID   types.String `tfsdk:"standard_id"`
	StandardName types.String `tfsdk:"standard_name"`
	ControlName  types.String `tfsdk:"control_name"`
}

// GetQueryAttrTypes returns the attribute types for the query object.
func GetQueryAttrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"xql": types.StringType,
	}
}

// GetIssueAttrTypes returns the attribute types for the issue object.
func GetIssueAttrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"recommendation": types.StringType,
	}
}

// GetMetadataAttrTypes returns the attribute types for the metadata object.
func GetMetadataAttrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"issue": types.ObjectType{AttrTypes: GetIssueAttrTypes()},
	}
}

// GetComplianceMetadataAttrTypes returns the attribute types for compliance metadata.
func GetComplianceMetadataAttrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"control_id":    types.StringType,
		"standard_id":   types.StringType,
		"standard_name": types.StringType,
		"control_name":  types.StringType,
	}
}

// ToSDKCreateRequest converts the Terraform model to an SDK CreateRuleRequest.
func (m *CloudSecRuleResourceModel) ToSDKCreateRequest(ctx context.Context, diags *diag.Diagnostics) cloudsecTypes.CreateRuleRequest {
	req := cloudsecTypes.CreateRuleRequest{
		Name:     m.Name.ValueString(),
		Class:    m.Class.ValueString(),
		Severity: m.Severity.ValueString(),
	}

	// Description (optional)
	if !m.Description.IsNull() && !m.Description.IsUnknown() {
		req.Description = m.Description.ValueString()
	}

	// Type (optional)
	if !m.Type.IsNull() && !m.Type.IsUnknown() {
		req.Type = m.Type.ValueString()
	}

	// Asset Types (required)
	if !m.AssetTypes.IsNull() && !m.AssetTypes.IsUnknown() {
		var assetTypes []string
		diags.Append(m.AssetTypes.ElementsAs(ctx, &assetTypes, false)...)
		req.AssetTypes = assetTypes
	}

	// Query (required)
	if !m.Query.IsNull() && !m.Query.IsUnknown() {
		var queryModel RuleQueryModel
		diags.Append(m.Query.As(ctx, &queryModel, basetypes.ObjectAsOptions{})...)
		if !diags.HasError() {
			req.Query = cloudsecTypes.QueryRequest{
				XQL: queryModel.XQL.ValueString(),
			}
		}
	}

	// Metadata (optional)
	if !m.Metadata.IsNull() && !m.Metadata.IsUnknown() {
		var metadataModel RuleMetadataModel
		diags.Append(m.Metadata.As(ctx, &metadataModel, basetypes.ObjectAsOptions{})...)
		if !diags.HasError() && !metadataModel.Issue.IsNull() {
			var issueModel IssueModel
			diags.Append(metadataModel.Issue.As(ctx, &issueModel, basetypes.ObjectAsOptions{})...)
			if !diags.HasError() {
				req.Metadata = &cloudsecTypes.MetadataRequest{
					Issue: &cloudsecTypes.IssueRequest{
						Recommendation: issueModel.Recommendation.ValueString(),
					},
				}
			}
		}
	}

	// Compliance Metadata → ComplianceMetadataInput (the API accepts compliance_metadata
	// as an array of objects with control_id)
	if !m.ComplianceMetadata.IsNull() && !m.ComplianceMetadata.IsUnknown() {
		var complianceList []ComplianceMetadataModel
		diags.Append(m.ComplianceMetadata.ElementsAs(ctx, &complianceList, false)...)
		if !diags.HasError() {
			cmInputs := make([]cloudsecTypes.ComplianceMetadataInput, len(complianceList))
			for i, cm := range complianceList {
				cmInputs[i] = cloudsecTypes.ComplianceMetadataInput{
					ControlID: cm.ControlID.ValueString(),
				}
			}
			req.ComplianceMetadata = cmInputs
		}
	}

	// Labels (optional)
	if !m.Labels.IsNull() && !m.Labels.IsUnknown() {
		var labels []string
		diags.Append(m.Labels.ElementsAs(ctx, &labels, false)...)
		req.Labels = labels
	}

	// Enabled (optional)
	if !m.Enabled.IsNull() && !m.Enabled.IsUnknown() {
		enabled := m.Enabled.ValueBool()
		req.Enabled = &enabled
	}

	return req
}

// ToSDKUpdateRequest converts the Terraform model to an SDK UpdateRuleRequest,
// including only fields that changed between the prior state and the new plan.
// The rule_class field is always included because the API requires it on every PATCH.
func (m *CloudSecRuleResourceModel) ToSDKUpdateRequest(ctx context.Context, diags *diag.Diagnostics, prior *CloudSecRuleResourceModel) cloudsecTypes.UpdateRuleRequest {
	req := cloudsecTypes.UpdateRuleRequest{}

	// rule_class is ALWAYS included — the API requires it in every PATCH call.
	req.Class = m.Class.ValueString()

	// Name — only include if changed
	if !m.Name.Equal(prior.Name) {
		req.Name = m.Name.ValueString()
	}

	// Description — only include if changed
	if !m.Description.Equal(prior.Description) {
		req.Description = m.Description.ValueString()
	}

	// Type — only include if changed
	if !m.Type.Equal(prior.Type) {
		req.Type = m.Type.ValueString()
	}

	// Asset Types — only include if changed
	if !m.AssetTypes.Equal(prior.AssetTypes) {
		var assetTypes []string
		diags.Append(m.AssetTypes.ElementsAs(ctx, &assetTypes, false)...)
		req.AssetTypes = assetTypes
	}

	// Severity — only include if changed
	if !m.Severity.Equal(prior.Severity) {
		req.Severity = m.Severity.ValueString()
	}

	// Query — only include if changed
	if !m.Query.Equal(prior.Query) {
		if !m.Query.IsNull() && !m.Query.IsUnknown() {
			var queryModel RuleQueryModel
			diags.Append(m.Query.As(ctx, &queryModel, basetypes.ObjectAsOptions{})...)
			if !diags.HasError() {
				req.Query = &cloudsecTypes.QueryResponse{
					XQL: queryModel.XQL.ValueString(),
				}
			}
		}
	}

	// Metadata — only include if changed
	if !m.Metadata.Equal(prior.Metadata) {
		if !m.Metadata.IsNull() && !m.Metadata.IsUnknown() {
			var metadataModel RuleMetadataModel
			diags.Append(m.Metadata.As(ctx, &metadataModel, basetypes.ObjectAsOptions{})...)
			if !diags.HasError() && !metadataModel.Issue.IsNull() {
				var issueModel IssueModel
				diags.Append(metadataModel.Issue.As(ctx, &issueModel, basetypes.ObjectAsOptions{})...)
				if !diags.HasError() {
					req.Metadata = &cloudsecTypes.MetadataRequest{
						Issue: &cloudsecTypes.IssueRequest{
							Recommendation: issueModel.Recommendation.ValueString(),
						},
					}
				}
			}
		}
	}

	// Compliance Metadata — only include if changed
	if !m.ComplianceMetadata.Equal(prior.ComplianceMetadata) {
		if !m.ComplianceMetadata.IsNull() && !m.ComplianceMetadata.IsUnknown() {
			var complianceList []ComplianceMetadataModel
			diags.Append(m.ComplianceMetadata.ElementsAs(ctx, &complianceList, false)...)
			if !diags.HasError() {
				cmInputs := make([]cloudsecTypes.ComplianceMetadataInput, len(complianceList))
				for i, cm := range complianceList {
					cmInputs[i] = cloudsecTypes.ComplianceMetadataInput{
						ControlID: cm.ControlID.ValueString(),
					}
				}
				req.ComplianceMetadata = cmInputs
			}
		}
	}

	// Labels — only include if changed
	if !m.Labels.Equal(prior.Labels) {
		if !m.Labels.IsNull() && !m.Labels.IsUnknown() {
			var labels []string
			diags.Append(m.Labels.ElementsAs(ctx, &labels, false)...)
			req.Labels = labels
		}
	}

	// Enabled — only include if changed
	if !m.Enabled.Equal(prior.Enabled) {
		enabled := m.Enabled.ValueBool()
		req.Enabled = &enabled
	}

	return req
}

// FromSDKResponse populates the Terraform model from an SDK RuleResponse.
func (m *CloudSecRuleResourceModel) FromSDKResponse(ctx context.Context, diags *diag.Diagnostics, remote *cloudsecTypes.RuleResponse) {
	if remote == nil {
		diags.AddError("Rule not found", "The requested rule does not exist.")
		return
	}

	m.ID = types.StringValue(remote.ID)
	m.Name = types.StringValue(remote.Name)

	// Handle optional string fields - set to null if empty to match Terraform's null handling
	if remote.Description == "" {
		m.Description = types.StringNull()
	} else {
		m.Description = types.StringValue(remote.Description)
	}

	m.Class = types.StringValue(remote.Class)
	m.Type = types.StringValue(remote.Type)
	m.Severity = types.StringValue(strings.ToLower(remote.Severity))
	m.Enabled = types.BoolValue(remote.Enabled)
	m.SystemDefault = types.BoolValue(remote.SystemDefault)

	if remote.CreatedBy == "" {
		m.CreatedBy = types.StringNull()
	} else {
		m.CreatedBy = types.StringValue(remote.CreatedBy)
	}

	m.CreatedOn = types.Int64Value(remote.CreatedOn)

	if remote.LastModifiedBy == "" {
		m.LastModifiedBy = types.StringNull()
	} else {
		m.LastModifiedBy = types.StringValue(remote.LastModifiedBy)
	}

	m.LastModifiedOn = types.Int64Value(remote.LastModifiedOn)
	m.Deleted = types.BoolValue(remote.Deleted)
	m.DeletedAt = types.Int64Value(remote.DeletedAt)

	if remote.DeletedBy == "" {
		m.DeletedBy = types.StringNull()
	} else {
		m.DeletedBy = types.StringValue(remote.DeletedBy)
	}

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

	// Labels - use Set (unordered) to avoid order mismatch with API response
	if len(remote.Labels) > 0 {
		elements := make([]attr.Value, len(remote.Labels))
		for i, label := range remote.Labels {
			elements[i] = types.StringValue(label)
		}
		labelsSet, d := types.SetValue(types.StringType, elements)
		diags.Append(d...)
		m.Labels = labelsSet
	} else {
		m.Labels = types.SetNull(types.StringType)
	}

	// Query
	if remote.Query != nil {
		queryObj, d := types.ObjectValue(
			GetQueryAttrTypes(),
			map[string]attr.Value{
				"xql": types.StringValue(remote.Query.XQL),
			},
		)
		diags.Append(d...)
		m.Query = queryObj
	} else {
		m.Query = types.ObjectNull(GetQueryAttrTypes())
	}

	// Metadata — always return a populated object (never null) since the schema
	// marks metadata as Computed.  Some stacks return null or empty metadata on
	// GET even though the CREATE response included {issue:{recommendation:""}}.
	// Returning null here would cause Terraform to detect drift on every refresh.
	recommendation := ""
	if remote.Metadata != nil && remote.Metadata.Issue != nil {
		recommendation = remote.Metadata.Issue.Recommendation
	}

	issueObj, d := types.ObjectValue(
		GetIssueAttrTypes(),
		map[string]attr.Value{
			"recommendation": types.StringValue(recommendation),
		},
	)
	diags.Append(d...)

	metadataObj, d := types.ObjectValue(
		GetMetadataAttrTypes(),
		map[string]attr.Value{
			"issue": issueObj,
		},
	)
	diags.Append(d...)
	m.Metadata = metadataObj

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
		// If the model already has compliance_metadata (from the plan/prior state),
		// preserve it — the API has eventual consistency for compliance associations.
		// The write succeeded (HTTP 200) but the immediate GET hasn't propagated yet.
		// We rebuild the list with known values only (control_id from plan, empty strings
		// for computed fields) to avoid "unknown value after apply" errors.
		if !m.ComplianceMetadata.IsNull() && !m.ComplianceMetadata.IsUnknown() && len(m.ComplianceMetadata.Elements()) > 0 {
			preservedElems := make([]attr.Value, 0, len(m.ComplianceMetadata.Elements()))
			for _, elem := range m.ComplianceMetadata.Elements() {
				obj, ok := elem.(types.Object)
				if !ok {
					continue
				}
				attrs := obj.Attributes()
				controlID := ""
				if cid, ok := attrs["control_id"].(types.String); ok && !cid.IsNull() && !cid.IsUnknown() {
					controlID = cid.ValueString()
				}
				// Use known values from the plan element where available,
				// fall back to empty string for any unknown/null computed fields.
				standardID := ""
				if sid, ok := attrs["standard_id"].(types.String); ok && !sid.IsNull() && !sid.IsUnknown() {
					standardID = sid.ValueString()
				}
				standardName := ""
				if sn, ok := attrs["standard_name"].(types.String); ok && !sn.IsNull() && !sn.IsUnknown() {
					standardName = sn.ValueString()
				}
				controlName := ""
				if cn, ok := attrs["control_name"].(types.String); ok && !cn.IsNull() && !cn.IsUnknown() {
					controlName = cn.ValueString()
				}
				cmObj, d := types.ObjectValue(
					GetComplianceMetadataAttrTypes(),
					map[string]attr.Value{
						"control_id":    types.StringValue(controlID),
						"standard_id":   types.StringValue(standardID),
						"standard_name": types.StringValue(standardName),
						"control_name":  types.StringValue(controlName),
					},
				)
				diags.Append(d...)
				preservedElems = append(preservedElems, cmObj)
			}
			preservedList, d := types.ListValue(
				types.ObjectType{AttrTypes: GetComplianceMetadataAttrTypes()},
				preservedElems,
			)
			diags.Append(d...)
			m.ComplianceMetadata = preservedList
		} else {
			m.ComplianceMetadata = types.ListNull(types.ObjectType{AttrTypes: GetComplianceMetadataAttrTypes()})
		}
	}
}
