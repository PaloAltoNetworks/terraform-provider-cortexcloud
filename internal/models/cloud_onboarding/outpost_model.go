// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package models

import (
	"context"

	cortexEnums "github.com/PaloAltoNetworks/cortex-cloud-go/enums"
	cloudOnboardingTypes "github.com/PaloAltoNetworks/cortex-cloud-go/types/cloudonboarding"
	filterTypes "github.com/PaloAltoNetworks/cortex-cloud-go/types/filter"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// OutpostModel is the model for a single outpost object.
type OutpostModel struct {
	ID            types.String `tfsdk:"id"`
	CloudProvider types.String `tfsdk:"cloud_provider"`
	CreatedAt     types.Int64  `tfsdk:"created_at"`
	Type          types.String `tfsdk:"type"`
}

// ToListRequest creates a ListOutpostsRequest to find a single outpost by ID.
func (m *OutpostModel) ToListRequest(ctx context.Context, diags *diag.Diagnostics) *cloudOnboardingTypes.ListOutpostsRequest {
	tflog.Debug(ctx, "Creating ListOutpostsRequest from OutpostModel")

	return cloudOnboardingTypes.NewListOutpostsRequest(
		cloudOnboardingTypes.WithOutpostFilterData(
			filterTypes.FilterData{
				Filter: filterTypes.NewAndFilter(
					filterTypes.NewSearchFilter(
						cortexEnums.SearchFieldOutpostID.String(),
						cortexEnums.SearchTypeEqualTo.String(),
						m.ID.ValueString(),
					),
				),
				Paging: filterTypes.PagingFilter{
					From: 0,
					To:   1000,
				},
			},
		),
	)
}

// RefreshFromRemote populates the model from a single SDK Outpost object.
func (m *OutpostModel) RefreshFromRemote(ctx context.Context, diags *diag.Diagnostics, remote cloudOnboardingTypes.Outpost) {
	tflog.Debug(ctx, "Refreshing OutpostModel from remote")

	m.ID = types.StringValue(remote.OutpostID)
	m.CloudProvider = types.StringValue(remote.CloudProvider)
	m.CreatedAt = types.Int64Value(int64(remote.CreatedAt))
	m.Type = types.StringValue(remote.Type)
}
