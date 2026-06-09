// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package models

import (
	"context"

	appsecTypes "github.com/PaloAltoNetworks/cortex-cloud-go/types/appsec"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// RulesDataSourceModel is the model for the rules list data source.
type RulesDataSourceModel struct {
	ID       types.String `tfsdk:"id"`
	IsCustom types.Bool   `tfsdk:"is_custom"`
	Limit    types.Int64  `tfsdk:"limit"`
	Offset   types.Int64  `tfsdk:"offset"`
	Rules    []RuleModel  `tfsdk:"rules"`
}

// PoliciesDataSourceModel is the model for the policies list data source.
type PoliciesDataSourceModel struct {
	ID       types.String  `tfsdk:"id"`
	IsCustom types.Bool    `tfsdk:"is_custom"`
	Status   types.String  `tfsdk:"status"`
	Policies []PolicyModel `tfsdk:"policies"`
}

// ToListRulesRequest converts the data source model to an SDK list request.
func (m *RulesDataSourceModel) ToListRequest(ctx context.Context, diags *diag.Diagnostics) appsecTypes.ListRequest {
	tflog.Debug(ctx, "Converting rules data source model to list request")

	return appsecTypes.ListRequest{
		IsCustom: m.IsCustom.ValueBool(),
		Limit:    int(m.Limit.ValueInt64()),
		Offset:   int(m.Offset.ValueInt64()),
	}
}

// RefreshFromRemote updates the data source model from the SDK response.
func (m *RulesDataSourceModel) RefreshFromRemote(ctx context.Context, diags *diag.Diagnostics, remote []appsecTypes.Rule) {
	tflog.Debug(ctx, "Refreshing rules data source model from remote")

	m.ID = types.StringValue("appsec_rules")

	m.Rules = make([]RuleModel, len(remote))
	for i, rule := range remote {
		m.Rules[i].RefreshFromRemote(ctx, diags, &rule)
		if diags.HasError() {
			return
		}
	}
}

// ToListPoliciesRequest converts the data source model to an SDK list request.
func (m *PoliciesDataSourceModel) ToListRequest(ctx context.Context, diags *diag.Diagnostics) appsecTypes.ListPoliciesRequest {
	tflog.Debug(ctx, "Converting policies data source model to list request")

	return appsecTypes.ListPoliciesRequest{
		IsCustom: m.IsCustom.ValueBool(),
		Status:   m.Status.ValueString(),
	}
}

// RefreshFromRemote updates the data source model from the SDK response.
func (m *PoliciesDataSourceModel) RefreshFromRemote(ctx context.Context, diags *diag.Diagnostics, remote []appsecTypes.Policy) {
	tflog.Debug(ctx, "Refreshing policies data source model from remote")

	m.ID = types.StringValue("appsec_policies")

	m.Policies = make([]PolicyModel, len(remote))
	for i, policy := range remote {
		m.Policies[i].RefreshFromRemote(ctx, diags, &policy)
		if diags.HasError() {
			return
		}
	}
}
