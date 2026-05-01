// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package models

import (
	"context"

	cloudsecTypes "github.com/PaloAltoNetworks/cortex-cloud-go/types/cloudsec"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
)

// CloudSecPolicyResourceModel represents the Terraform model for a CloudSec policy resource.
type CloudSecPolicyResourceModel struct {
	ID            types.String `tfsdk:"id"`
	Name          types.String `tfsdk:"name"`
	Description   types.String `tfsdk:"description"`
	Labels        types.Set    `tfsdk:"labels"`
	RuleMatching  types.Object `tfsdk:"rule_matching"`
	AssetMatching types.Object `tfsdk:"asset_matching"`
	Enabled       types.Bool   `tfsdk:"enabled"`
	Mode          types.String `tfsdk:"mode"`
	CreatedAt     types.Int64  `tfsdk:"created_at"`
	CreatedBy     types.String `tfsdk:"created_by"`
	UpdatedAt     types.Int64  `tfsdk:"updated_at"`
	UpdatedBy     types.String `tfsdk:"updated_by"`
}

// RuleMatchingModel represents the rule matching configuration.
type RuleMatchingModel struct {
	Type           types.String `tfsdk:"type"`
	Rules          types.List   `tfsdk:"rules"`
	FilterCriteria types.Object `tfsdk:"filter_criteria"`
}

// AssetMatchingModel represents the asset matching configuration.
type AssetMatchingModel struct {
	Type            types.String `tfsdk:"type"`
	AssetGroupIDs   types.List   `tfsdk:"asset_group_ids"`
	CloudAccountIDs types.List   `tfsdk:"cloud_account_ids"`
}

// GetRuleMatchingAttrTypes returns the attribute types for rule matching.
func GetRuleMatchingAttrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"type":            types.StringType,
		"rules":           types.ListType{ElemType: types.StringType},
		"filter_criteria": types.ObjectType{AttrTypes: GetFilterCriteriaAttrTypes()},
	}
}

// GetAssetMatchingAttrTypes returns the attribute types for asset matching.
func GetAssetMatchingAttrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"type":              types.StringType,
		"asset_group_ids":   types.ListType{ElemType: types.Int64Type},
		"cloud_account_ids": types.ListType{ElemType: types.StringType},
	}
}

// ToSDKCreateRequest converts the Terraform model to an SDK PolicyCreateRequest.
func (m *CloudSecPolicyResourceModel) ToSDKCreateRequest(ctx context.Context, diags *diag.Diagnostics) cloudsecTypes.PolicyCreateRequest {
	req := cloudsecTypes.PolicyCreateRequest{
		Name: m.Name.ValueString(),
	}

	// Description (optional)
	if !m.Description.IsNull() && !m.Description.IsUnknown() {
		req.Description = m.Description.ValueString()
	}

	// Labels (optional)
	if !m.Labels.IsNull() && !m.Labels.IsUnknown() {
		var labels []string
		diags.Append(m.Labels.ElementsAs(ctx, &labels, false)...)
		req.Labels = labels
	}

	// Rule Matching (required)
	if !m.RuleMatching.IsNull() && !m.RuleMatching.IsUnknown() {
		var ruleMatching RuleMatchingModel
		diags.Append(m.RuleMatching.As(ctx, &ruleMatching, basetypes.ObjectAsOptions{})...)
		if !diags.HasError() {
			req.RuleMatchingType = ruleMatching.Type.ValueString()

			// Handle different rule matching types
			switch req.RuleMatchingType {
			case "RULES":
				if !ruleMatching.Rules.IsNull() && !ruleMatching.Rules.IsUnknown() {
					var rules []string
					diags.Append(ruleMatching.Rules.ElementsAs(ctx, &rules, false)...)
					req.AssociatedRuleIDs = rules
				}
			case "RULE_FILTER":
				if !ruleMatching.FilterCriteria.IsNull() && !ruleMatching.FilterCriteria.IsUnknown() {
					req.AssociatedRuleFilter = ToSDKFilterCriteria(ctx, ruleMatching.FilterCriteria, diags)
				}
			}
		}
	}

	// Asset Matching (required)
	if !m.AssetMatching.IsNull() && !m.AssetMatching.IsUnknown() {
		var assetMatching AssetMatchingModel
		diags.Append(m.AssetMatching.As(ctx, &assetMatching, basetypes.ObjectAsOptions{})...)
		if !diags.HasError() {
			req.AssetMatchingType = assetMatching.Type.ValueString()

			// Handle different asset matching types
			switch req.AssetMatchingType {
			case "ASSET_GROUPS":
				if !assetMatching.AssetGroupIDs.IsNull() && !assetMatching.AssetGroupIDs.IsUnknown() {
					var assetGroupIDs []int64
					diags.Append(assetMatching.AssetGroupIDs.ElementsAs(ctx, &assetGroupIDs, false)...)
					// Convert int64 to int32
					req.AssociatedAssetGroupIDs = make([]int32, len(assetGroupIDs))
					for i, id := range assetGroupIDs {
						req.AssociatedAssetGroupIDs[i] = int32(id)
					}
				}
			case "CLOUD_ACCOUNTS":
				if !assetMatching.CloudAccountIDs.IsNull() && !assetMatching.CloudAccountIDs.IsUnknown() {
					var cloudAccountIDs []string
					diags.Append(assetMatching.CloudAccountIDs.ElementsAs(ctx, &cloudAccountIDs, false)...)
					req.AssociatedCloudAccountIDs = cloudAccountIDs
				}
			}
		}
	}

	// Enabled (optional)
	if !m.Enabled.IsNull() && !m.Enabled.IsUnknown() {
		enabled := m.Enabled.ValueBool()
		req.Enabled = &enabled
	}

	return req
}

// ToSDKUpdateRequest converts the Terraform model to an SDK PolicyUpdateRequest.
func (m *CloudSecPolicyResourceModel) ToSDKUpdateRequest(ctx context.Context, diags *diag.Diagnostics) cloudsecTypes.PolicyUpdateRequest {
	req := cloudsecTypes.PolicyUpdateRequest{}

	// ID
	if !m.ID.IsNull() && !m.ID.IsUnknown() {
		req.ID = m.ID.ValueString()
	}

	// Name (optional in update)
	if !m.Name.IsNull() && !m.Name.IsUnknown() {
		req.Name = m.Name.ValueString()
	}

	// Description (optional)
	if !m.Description.IsNull() && !m.Description.IsUnknown() {
		req.Description = m.Description.ValueString()
	}

	// Labels (optional)
	if !m.Labels.IsNull() && !m.Labels.IsUnknown() {
		var labels []string
		diags.Append(m.Labels.ElementsAs(ctx, &labels, false)...)
		req.Labels = labels
	}

	// Rule Matching (optional in update)
	if !m.RuleMatching.IsNull() && !m.RuleMatching.IsUnknown() {
		var ruleMatching RuleMatchingModel
		diags.Append(m.RuleMatching.As(ctx, &ruleMatching, basetypes.ObjectAsOptions{})...)
		if !diags.HasError() {
			req.RuleMatchingType = ruleMatching.Type.ValueString()

			// Handle different rule matching types
			switch req.RuleMatchingType {
			case "RULES":
				if !ruleMatching.Rules.IsNull() && !ruleMatching.Rules.IsUnknown() {
					var rules []string
					diags.Append(ruleMatching.Rules.ElementsAs(ctx, &rules, false)...)
					req.AssociatedRuleIDs = rules
				}
			case "RULE_FILTER":
				if !ruleMatching.FilterCriteria.IsNull() && !ruleMatching.FilterCriteria.IsUnknown() {
					req.AssociatedRuleFilter = ToSDKFilterCriteria(ctx, ruleMatching.FilterCriteria, diags)
				}
			}
		}
	}

	// Asset Matching (optional in update)
	if !m.AssetMatching.IsNull() && !m.AssetMatching.IsUnknown() {
		var assetMatching AssetMatchingModel
		diags.Append(m.AssetMatching.As(ctx, &assetMatching, basetypes.ObjectAsOptions{})...)
		if !diags.HasError() {
			req.AssetMatchingType = assetMatching.Type.ValueString()

			// Handle different asset matching types
			switch req.AssetMatchingType {
			case "ASSET_GROUPS":
				if !assetMatching.AssetGroupIDs.IsNull() && !assetMatching.AssetGroupIDs.IsUnknown() {
					var assetGroupIDs []int64
					diags.Append(assetMatching.AssetGroupIDs.ElementsAs(ctx, &assetGroupIDs, false)...)
					// Convert int64 to int32
					req.AssociatedAssetGroupIDs = make([]int32, len(assetGroupIDs))
					for i, id := range assetGroupIDs {
						req.AssociatedAssetGroupIDs[i] = int32(id)
					}
				}
			case "CLOUD_ACCOUNTS":
				if !assetMatching.CloudAccountIDs.IsNull() && !assetMatching.CloudAccountIDs.IsUnknown() {
					var cloudAccountIDs []string
					diags.Append(assetMatching.CloudAccountIDs.ElementsAs(ctx, &cloudAccountIDs, false)...)
					req.AssociatedCloudAccountIDs = cloudAccountIDs
				}
			}
		}
	}

	// Enabled (optional)
	if !m.Enabled.IsNull() && !m.Enabled.IsUnknown() {
		enabled := m.Enabled.ValueBool()
		req.Enabled = &enabled
	}

	return req
}

// FromSDKResponse populates the Terraform model from an SDK PolicyResponse.
func (m *CloudSecPolicyResourceModel) FromSDKResponse(ctx context.Context, diags *diag.Diagnostics, remote *cloudsecTypes.PolicyResponse) {
	if remote == nil {
		diags.AddError("Policy not found", "The requested policy does not exist.")
		return
	}

	m.ID = types.StringValue(remote.ID)
	m.Name = types.StringValue(remote.Name)

	// Description - set to null if empty to match Terraform's null handling
	if remote.Description == "" {
		m.Description = types.StringNull()
	} else {
		m.Description = types.StringValue(remote.Description)
	}

	m.Enabled = types.BoolValue(remote.Enabled)
	m.Mode = types.StringValue(remote.Mode)
	m.CreatedAt = types.Int64Value(remote.CreationTime)
	m.CreatedBy = types.StringValue(remote.CreatedBy)
	m.UpdatedAt = types.Int64Value(remote.ModificationTime)
	m.UpdatedBy = types.StringValue(remote.ModifiedBy)

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

	// Rule Matching
	ruleMatchingAttrs := map[string]attr.Value{
		"type":            types.StringValue(remote.RuleMatchingType),
		"rules":           types.ListNull(types.StringType),
		"filter_criteria": types.ObjectNull(GetFilterCriteriaAttrTypes()),
	}

	switch remote.RuleMatchingType {
	case "RULES":
		if len(remote.AssociatedRuleIDs) > 0 {
			rulesList, d := types.ListValueFrom(ctx, types.StringType, remote.AssociatedRuleIDs)
			diags.Append(d...)
			ruleMatchingAttrs["rules"] = rulesList
		}
	case "RULE_FILTER":
		if remote.AssociatedRuleFilter != nil {
			ruleMatchingAttrs["filter_criteria"] = FromSDKFilterCriteria(ctx, remote.AssociatedRuleFilter, diags)
		}
	}

	ruleMatchingObj, d := types.ObjectValue(GetRuleMatchingAttrTypes(), ruleMatchingAttrs)
	diags.Append(d...)
	m.RuleMatching = ruleMatchingObj

	// Asset Matching
	assetMatchingAttrs := map[string]attr.Value{
		"type":              types.StringValue(remote.AssetMatchingType),
		"asset_group_ids":   types.ListNull(types.Int64Type),
		"cloud_account_ids": types.ListNull(types.StringType),
	}

	switch remote.AssetMatchingType {
	case "ASSET_GROUPS":
		if len(remote.AssociatedAssetGroupIDs) > 0 {
			// Convert int32 to int64
			assetGroupIDs := make([]int64, len(remote.AssociatedAssetGroupIDs))
			for i, id := range remote.AssociatedAssetGroupIDs {
				assetGroupIDs[i] = int64(id)
			}
			assetGroupsList, d := types.ListValueFrom(ctx, types.Int64Type, assetGroupIDs)
			diags.Append(d...)
			assetMatchingAttrs["asset_group_ids"] = assetGroupsList
		}
	case "CLOUD_ACCOUNTS":
		if len(remote.AssociatedCloudAccountIDs) > 0 {
			cloudAccountsList, d := types.ListValueFrom(ctx, types.StringType, remote.AssociatedCloudAccountIDs)
			diags.Append(d...)
			assetMatchingAttrs["cloud_account_ids"] = cloudAccountsList
		}
	}

	assetMatchingObj, d := types.ObjectValue(GetAssetMatchingAttrTypes(), assetMatchingAttrs)
	diags.Append(d...)
	m.AssetMatching = assetMatchingObj
}
