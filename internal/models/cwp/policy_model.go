// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package models

import (
	"context"

	cwpTypes "github.com/PaloAltoNetworks/cortex-cloud-go/types/cwp"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// PolicyModel is the Terraform model for a CWP policy.
type PolicyModel struct {
	ID                  types.String `tfsdk:"id"`
	Revision            types.Int64  `tfsdk:"revision"`
	CreatedAt           types.String `tfsdk:"created_at"`
	ModifiedAt          types.String `tfsdk:"modified_at"`
	Type                types.String `tfsdk:"type"`
	CreatedBy           types.String `tfsdk:"created_by"`
	Disabled            types.Bool   `tfsdk:"disabled"`
	Name                types.String `tfsdk:"name"`
	Description         types.String `tfsdk:"description"`
	EvaluationModes     types.List   `tfsdk:"evaluation_modes"`
	EvaluationStage     types.String `tfsdk:"evaluation_stage"`
	PolicyRules         types.List   `tfsdk:"policy_rules"`
	Condition           types.String `tfsdk:"condition"`
	Exception           types.String `tfsdk:"exception"`
	AssetScope          types.String `tfsdk:"asset_scope"`
	AssetGroupIDs       types.List   `tfsdk:"asset_group_ids"`
	AssetGroups         types.List   `tfsdk:"asset_groups"`
	PolicyAction        types.String `tfsdk:"action"`
	PolicySeverity      types.String `tfsdk:"severity"`
	RemediationGuidance types.String `tfsdk:"remediation_guidance"`
}

// PoliciesDataSourceModel is the model for an individual CWP rule attached to
// the policy.
type PolicyRuleModel struct {
	Action                  types.String `tfsdk:"action"`
	ID                      types.String `tfsdk:"id"`
	PolicyID                types.String `tfsdk:"policy_id"`
	PolicyRevision          types.Int32  `tfsdk:"policy_revision"`
	RemediationGuidance     types.String `tfsdk:"remediation_guidance"`
	RuleID                  types.String `tfsdk:"rule_id"`
	RuleName                types.String `tfsdk:"rule_name"`
	Severity                types.String `tfsdk:"severity"`
	UserRemediationGuidance types.String `tfsdk:"user_remediation_guidance"`
}

func (m PolicyRuleModel) GetAttrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"action":                    types.StringType,
		"id":                        types.StringType,
		"policy_id":                 types.StringType,
		"policy_revision":           types.Int32Type,
		"remediation_guidance":      types.StringType,
		"rule_id":                   types.StringType,
		"rule_name":                 types.StringType,
		"severity":                  types.StringType,
		"user_remediation_guidance": types.StringType,
	}
}

// PoliciesDataSourceModel is the model for the policies list data source.
type PoliciesDataSourceModel struct {
	ID          types.String  `tfsdk:"id"`
	PolicyTypes types.List    `tfsdk:"policy_types"`
	Policies    []PolicyModel `tfsdk:"policies"`
}

// ToCreateRequest converts the Terraform model to an SDK create request.
func (m *PolicyModel) ToCreateRequest(ctx context.Context, diags *diag.Diagnostics) cwpTypes.CreateOrUpdatePolicyRequest {
	tflog.Debug(ctx, "Converting CWP policy model to create request")

	req := cwpTypes.CreateOrUpdatePolicyRequest{
		Type:            m.Type.ValueString(),
		Name:            m.Name.ValueString(),
		EvaluationStage: m.EvaluationStage.ValueString(),
	}

	// Optional string fields
	if !m.Description.IsNull() && !m.Description.IsUnknown() {
		req.Description = m.Description.ValueString()
	}

	if !m.Condition.IsNull() && !m.Condition.IsUnknown() {
		req.Condition = m.Condition.ValueString()
	}

	if !m.Exception.IsNull() && !m.Exception.IsUnknown() {
		req.Exception = m.Exception.ValueString()
	}

	if !m.AssetScope.IsNull() && !m.AssetScope.IsUnknown() {
		req.AssetScope = m.AssetScope.ValueString()
	}

	if !m.RemediationGuidance.IsNull() && !m.RemediationGuidance.IsUnknown() {
		req.RemediationGuidance = m.RemediationGuidance.ValueString()
	}

	// Convert evaluation_modes
	tflog.Trace(ctx, "Converting CWP policy evaluation modes")
	if !m.EvaluationModes.IsNull() && !m.EvaluationModes.IsUnknown() {
		var modes []string
		diags.Append(m.EvaluationModes.ElementsAs(ctx, &modes, false)...)
		if diags.HasError() {
			return req
		}
		req.EvaluationModes = modes
	}

	// Convert policy rules
	tflog.Trace(ctx, "Converting CWP policy rules")
	var policyRuleModels []PolicyRuleModel
	diags.Append(m.PolicyRules.ElementsAs(ctx, &policyRuleModels, false)...)
	if diags.HasError() {
		return req
	}

	var policyRules []cwpTypes.PolicyRule
	for _, ruleModel := range policyRuleModels {
		rule := cwpTypes.PolicyRule{
			Action:   ruleModel.Action.ValueString(),
			RuleID:   ruleModel.RuleID.ValueString(),
			Severity: ruleModel.Severity.ValueString(),
		}

		if !ruleModel.ID.IsNull() && !ruleModel.ID.IsUnknown() {
			id := ruleModel.ID.ValueString()
			rule.ID = &id
		}

		if !ruleModel.PolicyID.IsNull() && !ruleModel.PolicyID.IsUnknown() {
			policyID := ruleModel.PolicyID.ValueString()
			rule.PolicyID = &policyID
		}

		if !ruleModel.PolicyRevision.IsNull() && !ruleModel.PolicyRevision.IsUnknown() {
			rev := int(ruleModel.PolicyRevision.ValueInt32())
			rule.PolicyRevision = &rev
		}

		if !ruleModel.RemediationGuidance.IsNull() && !ruleModel.RemediationGuidance.IsUnknown() {
			guidance := ruleModel.RemediationGuidance.ValueString()
			rule.RemediationGuidance = &guidance
		}

		if !ruleModel.RuleName.IsNull() && !ruleModel.RuleName.IsUnknown() {
			name := ruleModel.RuleName.ValueString()
			rule.RuleName = &name
		}

		if !ruleModel.UserRemediationGuidance.IsNull() && !ruleModel.UserRemediationGuidance.IsUnknown() {
			userGuidance := ruleModel.UserRemediationGuidance.ValueString()
			rule.UserRemediationGuidance = &userGuidance
		}

		policyRules = append(policyRules, rule)
	}
	req.PolicyRules = policyRules

	// Convert asset_group_ids
	if !m.AssetGroupIDs.IsNull() && !m.AssetGroupIDs.IsUnknown() {
		var groupIDs []int64
		diags.Append(m.AssetGroupIDs.ElementsAs(ctx, &groupIDs, false)...)
		if diags.HasError() {
			return req
		}

		req.AssetGroupIDs = make([]int, len(groupIDs))
		for i, groupID := range groupIDs {
			req.AssetGroupIDs[i] = int(groupID)
		}
	}

	return req
}

// ToUpdateRequest converts the Terraform model to an SDK update request.
func (m *PolicyModel) ToUpdateRequest(ctx context.Context, diags *diag.Diagnostics) (req cwpTypes.CreateOrUpdatePolicyRequest) {
	tflog.Debug(ctx, "Converting CWP policy model to update request")

	// The update endpoint's payload is the same as the create endpoint
	// with the exception of a configured ID field, so we use ToCreateRequest
	// to handle the bulk of the conversion, then populate the ID field.
	req = m.ToCreateRequest(ctx, diags)
	if diags.HasError() {
		return req
	}

	req.ID = m.ID.ValueString()

	return req
}

// RefreshFromRemote updates the Terraform model from the SDK response.
func (m *PolicyModel) RefreshFromRemote(ctx context.Context, diags *diag.Diagnostics, remote *cwpTypes.Policy) {
	tflog.Debug(ctx, "Refreshing CWP policy model from remote")

	if remote == nil {
		diags.AddError("CWP Policy Not Found", "The requested CWP policy does not exist.")
		return
	}

	m.ID = types.StringValue(remote.ID)
	m.Type = types.StringValue(remote.Type)
	m.CreatedBy = types.StringValue(remote.CreatedBy)
	m.Name = types.StringValue(remote.Name)
	m.Description = types.StringValue(remote.Description)
	m.EvaluationStage = types.StringValue(remote.EvaluationStage)
	m.Condition = types.StringValue(remote.Condition)
	m.Exception = types.StringValue(remote.Exception)
	m.AssetScope = types.StringValue(remote.AssetScope)
	m.PolicyAction = types.StringValue(remote.PolicyAction)
	m.PolicySeverity = types.StringValue(remote.PolicySeverity)
	m.RemediationGuidance = types.StringValue(remote.RemediationGuidance)
	m.CreatedAt = types.StringValue(remote.CreatedAt)
	m.ModifiedAt = types.StringValue(remote.ModifiedAt)
	m.Disabled = types.BoolValue(remote.Disabled)
	m.Revision = types.Int64Value(int64(remote.Revision))

	// Convert evaluation_modes list
	if len(remote.EvaluationModes) == 0 {
		m.EvaluationModes = types.ListNull(types.StringType)
	} else {
		modeElements := make([]attr.Value, len(remote.EvaluationModes))
		for i, mode := range remote.EvaluationModes {
			modeElements[i] = types.StringValue(mode)
		}
		modeList, modeDiags := types.ListValue(types.StringType, modeElements)
		diags.Append(modeDiags...)
		if diags.HasError() {
			return
		}
		m.EvaluationModes = modeList
	}

	// Convert policy_rules
	if len(remote.PolicyRules) == 0 {
		m.PolicyRules = types.ListNull(types.ObjectType{AttrTypes: PolicyRuleModel{}.GetAttrTypes()})
	} else {
		var ruleModels []PolicyRuleModel
		for _, rule := range remote.PolicyRules {
			ruleModel := PolicyRuleModel{
				Action:                  types.StringValue(rule.Action),
				RuleID:                  types.StringValue(rule.RuleID),
				Severity:                types.StringValue(rule.Severity),
				UserRemediationGuidance: types.StringPointerValue(rule.UserRemediationGuidance),
				ID:                      types.StringPointerValue(rule.ID),
				PolicyID:                types.StringPointerValue(rule.PolicyID),
				RemediationGuidance:     types.StringPointerValue(rule.RemediationGuidance),
			}

			if rule.PolicyRevision != nil {
				ruleModel.PolicyRevision = types.Int32Value(int32(*rule.PolicyRevision))
			} else {
				ruleModel.PolicyRevision = types.Int32Null()
			}

			ruleModels = append(ruleModels, ruleModel)
		}

		ruleList, ruleDiags := types.ListValueFrom(ctx, types.ObjectType{AttrTypes: PolicyRuleModel{}.GetAttrTypes()}, ruleModels)
		diags.Append(ruleDiags...)
		if diags.HasError() {
			return
		}
		m.PolicyRules = ruleList
	}

	// Convert asset_group_ids list
	if len(remote.AssetGroupIDs) == 0 {
		m.AssetGroupIDs = types.ListNull(types.Int64Type)
	} else {
		groupIDElements := make([]attr.Value, len(remote.AssetGroupIDs))
		for i, groupID := range remote.AssetGroupIDs {
			groupIDElements[i] = types.Int64Value(int64(groupID))
		}
		groupIDList, groupIDDiags := types.ListValue(types.Int64Type, groupIDElements)
		diags.Append(groupIDDiags...)
		if diags.HasError() {
			return
		}
		m.AssetGroupIDs = groupIDList
	}

	// Convert asset_groups list
	if len(remote.AssetGroups) == 0 {
		m.AssetGroups = types.ListNull(types.StringType)
	} else {
		groupElements := make([]attr.Value, len(remote.AssetGroups))
		for i, group := range remote.AssetGroups {
			groupElements[i] = types.StringValue(group)
		}
		groupList, groupDiags := types.ListValue(types.StringType, groupElements)
		diags.Append(groupDiags...)
		if diags.HasError() {
			return
		}
		m.AssetGroups = groupList
	}
}

// RefreshFromRemote updates the data source model from the SDK response.
func (m *PoliciesDataSourceModel) RefreshFromRemote(ctx context.Context, diags *diag.Diagnostics, remote []cwpTypes.Policy) {
	tflog.Debug(ctx, "Refreshing CWP policies data source model from remote")

	// Set a static ID for the data source
	m.ID = types.StringValue("cwp_policies")

	// Convert each policy
	m.Policies = make([]PolicyModel, len(remote))
	for i, policy := range remote {
		m.Policies[i].RefreshFromRemote(ctx, diags, &policy)
		if diags.HasError() {
			return
		}
	}
}
