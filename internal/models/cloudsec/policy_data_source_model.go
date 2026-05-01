// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package models

import (
	"context"

	cloudsecTypes "github.com/PaloAltoNetworks/cortex-cloud-go/types/cloudsec"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// CloudSecPolicyDataSourceModel represents the Terraform model for a CloudSec policy data source.
// This is a read-only model used for data source queries.
type CloudSecPolicyDataSourceModel struct {
	ID                        types.String `tfsdk:"id"`
	Name                      types.String `tfsdk:"name"`
	Description               types.String `tfsdk:"description"`
	Labels                    types.List   `tfsdk:"labels"`
	RuleMatchingType          types.String `tfsdk:"rule_matching_type"`
	AssociatedRuleIDs         types.List   `tfsdk:"associated_rule_ids"`
	AssetMatchingType         types.String `tfsdk:"asset_matching_type"`
	AssociatedAssetGroupIDs   types.List   `tfsdk:"associated_asset_group_ids"`
	AssociatedCloudAccountIDs types.List   `tfsdk:"associated_cloud_account_ids"`
	Enabled                   types.Bool   `tfsdk:"enabled"`
	Mode                      types.String `tfsdk:"mode"`
	CreatedAt                 types.Int64  `tfsdk:"created_at"`
	CreatedBy                 types.String `tfsdk:"created_by"`
	UpdatedAt                 types.Int64  `tfsdk:"updated_at"`
	UpdatedBy                 types.String `tfsdk:"updated_by"`
}

// FromSDKResponse populates the data source model from SDK PolicyResponse.
func (m *CloudSecPolicyDataSourceModel) FromSDKResponse(ctx context.Context, diags *diag.Diagnostics, remote *cloudsecTypes.PolicyResponse) {
	if remote == nil {
		diags.AddError("Policy not found", "The requested policy does not exist.")
		return
	}

	m.ID = types.StringValue(remote.ID)
	m.Name = types.StringValue(remote.Name)
	m.Description = types.StringValue(remote.Description)
	m.RuleMatchingType = types.StringValue(remote.RuleMatchingType)
	m.AssetMatchingType = types.StringValue(remote.AssetMatchingType)
	m.Enabled = types.BoolValue(remote.Enabled)
	m.Mode = types.StringValue(remote.Mode)
	m.CreatedAt = types.Int64Value(remote.CreationTime)
	m.CreatedBy = types.StringValue(remote.CreatedBy)
	m.UpdatedAt = types.Int64Value(remote.ModificationTime)
	m.UpdatedBy = types.StringValue(remote.ModifiedBy)

	// Labels
	if len(remote.Labels) > 0 {
		labelsList, d := types.ListValueFrom(ctx, types.StringType, remote.Labels)
		diags.Append(d...)
		m.Labels = labelsList
	} else {
		m.Labels = types.ListNull(types.StringType)
	}

	// Associated Rule IDs
	if len(remote.AssociatedRuleIDs) > 0 {
		ruleIDsList, d := types.ListValueFrom(ctx, types.StringType, remote.AssociatedRuleIDs)
		diags.Append(d...)
		m.AssociatedRuleIDs = ruleIDsList
	} else {
		m.AssociatedRuleIDs = types.ListNull(types.StringType)
	}

	// Associated Asset Group IDs
	if len(remote.AssociatedAssetGroupIDs) > 0 {
		// Convert int32 to int64 for Terraform
		assetGroupIDs := make([]int64, len(remote.AssociatedAssetGroupIDs))
		for i, id := range remote.AssociatedAssetGroupIDs {
			assetGroupIDs[i] = int64(id)
		}
		assetGroupsList, d := types.ListValueFrom(ctx, types.Int64Type, assetGroupIDs)
		diags.Append(d...)
		m.AssociatedAssetGroupIDs = assetGroupsList
	} else {
		m.AssociatedAssetGroupIDs = types.ListNull(types.Int64Type)
	}

	// Associated Cloud Account IDs
	if len(remote.AssociatedCloudAccountIDs) > 0 {
		cloudAccountsList, d := types.ListValueFrom(ctx, types.StringType, remote.AssociatedCloudAccountIDs)
		diags.Append(d...)
		m.AssociatedCloudAccountIDs = cloudAccountsList
	} else {
		m.AssociatedCloudAccountIDs = types.ListNull(types.StringType)
	}
}
