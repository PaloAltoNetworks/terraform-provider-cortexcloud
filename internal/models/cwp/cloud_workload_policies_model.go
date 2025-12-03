package models

import (
	"context"

	cwpTypes "github.com/PaloAltoNetworks/cortex-cloud-go/types/cwp"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// CloudWorkloadPoliciesDataSourceModel is the model for the policies data source.
type CloudWorkloadPoliciesDataSourceModel struct {
	PolicyTypes types.List `tfsdk:"policy_types"`
	Policies    types.List `tfsdk:"policies"`
}

func (m *CloudWorkloadPoliciesDataSourceModel) RefreshFromRemote(ctx context.Context, diagnostics *diag.Diagnostics, remote []cwpTypes.CloudWorkloadPolicy) {
	policies, policesDiags := types.ListValueFrom(ctx, m.Policies.ElementType(ctx), remote)
	diagnostics.Append(policesDiags...)
	if diagnostics.HasError() {
		return
	}

	m.Policies = policies
}
