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

// OutpostsDataSourceModel is the model for the outposts data source (plural).
type OutpostsDataSourceModel struct {
	ID                 types.String                              `tfsdk:"id"`
	CloudProvider      types.String                              `tfsdk:"cloud_provider"`
	Outposts           []OutpostModel                            `tfsdk:"outposts"`
}

// ToListRequest creates a ListOutpostsRequest from the data source's filters.
func (m *OutpostsDataSourceModel) ToListRequest(ctx context.Context, diags *diag.Diagnostics) *cloudOnboardingTypes.ListOutpostsRequest {
	tflog.Debug(ctx, "Creating ListOutpostsRequest from OutpostsDataSourceModel")

	var filters []filterTypes.Filter
	if !m.CloudProvider.IsNull() && !m.CloudProvider.IsUnknown() {
		filters = append(filters, filterTypes.NewSearchFilter(
			cortexEnums.SearchFieldProvider.String(),
			cortexEnums.SearchTypeEqualTo.String(),
			m.CloudProvider.ValueString(),
		))
	}
	return cloudOnboardingTypes.NewListOutpostsRequest(
		cloudOnboardingTypes.WithOutpostFilterData(
			filterTypes.FilterData{
				Filter: filterTypes.NewAndFilter(
					filters...,
				),
				Paging: filterTypes.PagingFilter{
					From: 0,
					To:   1000,
				},
			},
		),
	)
}

// RefreshFromRemote populates the model from a list of SDK Outpost objects.
func (m *OutpostsDataSourceModel) RefreshFromRemote(ctx context.Context, diags *diag.Diagnostics, remote []cloudOnboardingTypes.Outpost) {
	tflog.Debug(ctx, "Refreshing OutpostsDataSourceModel from remote")

	var outposts []OutpostModel
	for _, outpostData := range remote {
		var outpostModel OutpostModel
		outpostModel.RefreshFromRemote(ctx, diags, outpostData)
		if diags.HasError() {
			return
		}
		outposts = append(outposts, outpostModel)
	}

	m.Outposts = outposts
	m.ID = types.StringValue("cortexcloud_outposts")
}
