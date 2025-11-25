// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package models

import (
	"context"

	cwpTypes "github.com/PaloAltoNetworks/cortex-cloud-go/types/cwp"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// PolicyModel is the model for the cwp_policy resource.
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
	EvaluationModes     types.List   `tfsdk:"evaluation_modes"` // []string
	EvaluationStage     types.String `tfsdk:"evaluation_stage"`
	RulesIDs            types.List   `tfsdk:"rules_ids"` // []string
	Condition           types.String `tfsdk:"condition"`
	Exception           types.String `tfsdk:"exception"`
	AssetScope          types.String `tfsdk:"asset_scope"`
	AssetGroupIDs       types.List   `tfsdk:"asset_group_ids"` // []int
	AssetGroups         types.List   `tfsdk:"asset_groups"`    // []string
	PolicyAction        types.String `tfsdk:"policy_action"`
	PolicySeverity      types.String `tfsdk:"policy_severity"`
	RemediationGuidance types.String `tfsdk:"remediation_guidance"`
}

// ToCreateRequest converts the model to a CreatePolicyRequest for the SDK.
func (m *PolicyModel) ToCreateRequest() cwpTypes.CreatePolicyRequest {
	var evaluationModes []string
	if !m.EvaluationModes.IsNull() && !m.EvaluationModes.IsUnknown() {
		m.EvaluationModes.ElementsAs(context.Background(), &evaluationModes, false)
	}

	var rulesIDs []string
	if !m.RulesIDs.IsNull() && !m.RulesIDs.IsUnknown() {
		m.RulesIDs.ElementsAs(context.Background(), &rulesIDs, false)
	}

	var assetGroupIDs []int
	if !m.AssetGroupIDs.IsNull() && !m.AssetGroupIDs.IsUnknown() {
		m.AssetGroupIDs.ElementsAs(context.Background(), &assetGroupIDs, false)
	}

	req := cwpTypes.CreatePolicyRequest{
		Type:                m.Type.ValueString(),
		Name:                m.Name.ValueString(),
		Description:         m.Description.ValueString(),
		EvaluationStage:     m.EvaluationStage.ValueString(),
		RulesIDs:            rulesIDs,
		AssetGroupIDs:       assetGroupIDs,
		PolicyAction:        m.PolicyAction.ValueString(),
		PolicySeverity:      m.PolicySeverity.ValueString(),
		RemediationGuidance: m.RemediationGuidance.ValueString(),
	}

	return req
}

// ToUpdateRequest converts the model to an UpdatePolicyRequest for the SDK.
func (m *PolicyModel) ToUpdateRequest() cwpTypes.UpdatePolicyRequest {
	var evaluationModes []string
	if !m.EvaluationModes.IsNull() && !m.EvaluationModes.IsUnknown() {
		m.EvaluationModes.ElementsAs(context.Background(), &evaluationModes, false)
	}

	var rulesIDs []string
	if !m.RulesIDs.IsNull() && !m.RulesIDs.IsUnknown() {
		m.RulesIDs.ElementsAs(context.Background(), &rulesIDs, false)
	}

	var assetGroupIDs []int
	if !m.AssetGroupIDs.IsNull() && !m.AssetGroupIDs.IsUnknown() {
		m.AssetGroupIDs.ElementsAs(context.Background(), &assetGroupIDs, false)
	}

	var assetGroups []string
	if !m.AssetGroups.IsNull() && !m.AssetGroups.IsUnknown() {
		m.AssetGroups.ElementsAs(context.Background(), &assetGroups, false)
	}

	// Create an UpdatePolicyRequest by directly setting the embedded Policy fields
	// This works because Go's struct embedding allows direct field access
	req := cwpTypes.UpdatePolicyRequest{}
	req.Revision = int(m.Revision.ValueInt64())
	req.CreatedAt = m.CreatedAt.ValueString()
	req.ModifiedAt = m.ModifiedAt.ValueString()
	req.Type = m.Type.ValueString()
	req.CreatedBy = m.CreatedBy.ValueString()
	req.Disabled = m.Disabled.ValueBool()
	req.Name = m.Name.ValueString()
	req.Description = m.Description.ValueString()
	req.EvaluationModes = evaluationModes
	req.EvaluationStage = m.EvaluationStage.ValueString()
	req.RulesIDs = rulesIDs
	req.Condition = m.Condition.ValueString()
	req.Exception = m.Exception.ValueString()
	req.AssetScope = m.AssetScope.ValueString()
	req.AssetGroupIDs = assetGroupIDs
	req.AssetGroups = assetGroups
	req.PolicyAction = m.PolicyAction.ValueString()
	req.PolicySeverity = m.PolicySeverity.ValueString()
	req.RemediationGuidance = m.RemediationGuidance.ValueString()

	return req
}

// RefreshFromRemote populates the model from the SDK's Policy object.
func (m *PolicyModel) RefreshFromRemote(ctx context.Context, diags *diag.Diagnostics, remote *cwpTypes.Policy) {
	if remote == nil {
		diags.AddError("Policy not found", "The requested policy does not exist.")
		return
	}

	m.ID = types.StringValue(remote.ID)
	m.Revision = types.Int64Value(int64(remote.Revision))
	m.CreatedAt = types.StringValue(remote.CreatedAt)
	m.ModifiedAt = types.StringValue(remote.ModifiedAt)
	m.Type = types.StringValue(remote.Type)
	m.CreatedBy = types.StringValue(remote.CreatedBy)
	m.Disabled = types.BoolValue(remote.Disabled)
	m.Name = types.StringValue(remote.Name)

	// Handle optional string fields - use null for empty strings if not set in config
	if remote.Description == "" && m.Description.IsNull() {
		m.Description = types.StringNull()
	} else {
		m.Description = types.StringValue(remote.Description)
	}

	if remote.EvaluationStage == "" && m.EvaluationStage.IsNull() {
		m.EvaluationStage = types.StringNull()
	} else {
		m.EvaluationStage = types.StringValue(remote.EvaluationStage)
	}

	if remote.Condition == "" && m.Condition.IsNull() {
		m.Condition = types.StringNull()
	} else {
		m.Condition = types.StringValue(remote.Condition)
	}

	if remote.Exception == "" && m.Exception.IsNull() {
		m.Exception = types.StringNull()
	} else {
		m.Exception = types.StringValue(remote.Exception)
	}

	if remote.AssetScope == "" && m.AssetScope.IsNull() {
		m.AssetScope = types.StringNull()
	} else {
		m.AssetScope = types.StringValue(remote.AssetScope)
	}

	if remote.PolicyAction == "" && m.PolicyAction.IsNull() {
		m.PolicyAction = types.StringNull()
	} else {
		m.PolicyAction = types.StringValue(remote.PolicyAction)
	}

	if remote.PolicySeverity == "" && m.PolicySeverity.IsNull() {
		m.PolicySeverity = types.StringNull()
	} else {
		m.PolicySeverity = types.StringValue(remote.PolicySeverity)
	}

	if remote.RemediationGuidance == "" && m.RemediationGuidance.IsNull() {
		m.RemediationGuidance = types.StringNull()
	} else {
		m.RemediationGuidance = types.StringValue(remote.RemediationGuidance)
	}

	// Handle EvaluationModes slice
	if len(remote.EvaluationModes) == 0 {
		if m.EvaluationModes.IsNull() {
			m.EvaluationModes = types.ListNull(types.StringType)
		} else {
			// Keep existing empty list if it was configured
			evalModesList, evalModesdiag := types.ListValueFrom(ctx, types.StringType, []string{})
			diags.Append(evalModesdiag...)
			if !diags.HasError() {
				m.EvaluationModes = evalModesList
			}
		}
	} else {
		evalModesList, evalModesdiag := types.ListValueFrom(ctx, types.StringType, remote.EvaluationModes)
		diags.Append(evalModesdiag...)
		if !diags.HasError() {
			m.EvaluationModes = evalModesList
		}
	}

	// Handle RulesIDs slice
	if len(remote.RulesIDs) == 0 {
		if m.RulesIDs.IsNull() {
			m.RulesIDs = types.ListNull(types.StringType)
		} else {
			rulesIDsList, rulesIDsdiag := types.ListValueFrom(ctx, types.StringType, []string{})
			diags.Append(rulesIDsdiag...)
			if !diags.HasError() {
				m.RulesIDs = rulesIDsList
			}
		}
	} else {
		rulesIDsList, rulesIDsdiag := types.ListValueFrom(ctx, types.StringType, remote.RulesIDs)
		diags.Append(rulesIDsdiag...)
		if !diags.HasError() {
			m.RulesIDs = rulesIDsList
		}
	}

	// Handle AssetGroupIDs slice
	if len(remote.AssetGroupIDs) == 0 {
		if m.AssetGroupIDs.IsNull() {
			m.AssetGroupIDs = types.ListNull(types.Int64Type)
		} else {
			assetGroupIDsList, assetGroupIDsdiag := types.ListValueFrom(ctx, types.Int64Type, []int64{})
			diags.Append(assetGroupIDsdiag...)
			if !diags.HasError() {
				m.AssetGroupIDs = assetGroupIDsList
			}
		}
	} else {
		assetGroupIDs := make([]int64, len(remote.AssetGroupIDs))
		for i, id := range remote.AssetGroupIDs {
			assetGroupIDs[i] = int64(id)
		}
		assetGroupIDsList, assetGroupIDsdiag := types.ListValueFrom(ctx, types.Int64Type, assetGroupIDs)
		diags.Append(assetGroupIDsdiag...)
		if !diags.HasError() {
			m.AssetGroupIDs = assetGroupIDsList
		}
	}

	// Handle AssetGroups slice
	if len(remote.AssetGroups) == 0 {
		m.AssetGroups = types.ListNull(types.StringType)
	} else {
		assetGroupsList, assetGroupsdiag := types.ListValueFrom(ctx, types.StringType, remote.AssetGroups)
		diags.Append(assetGroupsdiag...)
		if !diags.HasError() {
			m.AssetGroups = assetGroupsList
		}
	}
}
