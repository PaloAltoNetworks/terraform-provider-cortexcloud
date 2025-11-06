// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package models

import (
	"context"
	"math"
	"strconv"

	cortexEnums "github.com/PaloAltoNetworks/cortex-cloud-go/enums"
	cloudOnboardingTypes "github.com/PaloAltoNetworks/cortex-cloud-go/types/cloudonboarding"
	filterTypes "github.com/PaloAltoNetworks/cortex-cloud-go/types/filter"
	models "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/shared"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// OutpostsDataSourceModel is the model for the outposts data source (plural).
type OutpostsDataSourceModel struct {
	ID                 types.String                              `tfsdk:"id"`
	CloudProvider      types.String                              `tfsdk:"cloud_provider"`
	Status             types.String                              `tfsdk:"status"`
	OutpostAccountName types.String                              `tfsdk:"outpost_account_name"`
	OutpostAccountID   types.Int64                               `tfsdk:"outpost_account_id"`
	CreatedAt          *models.FilterRangeInt64Model             `tfsdk:"created_at"`
	NumberOfInstances  *models.FilterGreaterOrLessThanInt64Model `tfsdk:"number_of_instances"`
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
	if !m.Status.IsNull() && !m.Status.IsUnknown() {
		filters = append(filters, filterTypes.NewSearchFilter(
			cortexEnums.SearchFieldStatus.String(),
			cortexEnums.SearchTypeContains.String(),
			m.Status.ValueString(),
		))
	}
	if !m.OutpostAccountName.IsNull() && !m.OutpostAccountName.IsUnknown() {
		filters = append(filters, filterTypes.NewSearchFilter(
			cortexEnums.SearchFieldOutpostAccountName.String(),
			cortexEnums.SearchTypeContains.String(),
			m.OutpostAccountName.ValueString(),
		))
	}
	if !m.OutpostAccountID.IsNull() && !m.OutpostAccountID.IsUnknown() {
		filters = append(filters, filterTypes.NewSearchFilter(
			cortexEnums.SearchFieldOutpostAccountID.String(),
			cortexEnums.SearchTypeContains.String(),
			strconv.FormatInt(m.OutpostAccountID.ValueInt64(), 10),
		))
	}
	if m.CreatedAt != nil {
		var (
			fromVal, toVal = (*m.CreatedAt).From, (*m.CreatedAt).To
			from, to       = 0, math.MaxInt64
		)
		if !fromVal.IsNull() && !fromVal.IsUnknown() {
			from = int(fromVal.ValueInt64())
		}
		if !toVal.IsNull() && !toVal.IsUnknown() {
			to = int(toVal.ValueInt64())
		}
		filters = append(filters, filterTypes.NewTimespanFilter(
			cortexEnums.SearchFieldCreationTime.String(),
			cortexEnums.SearchTypeEqualTo.String(),
			from,
			to,
		))
	}
	if m.NumberOfInstances != nil {
		var (
			conditionVal, valueVal = (*m.NumberOfInstances).Condition, (*m.NumberOfInstances).Value
			condition              = cortexEnums.SearchTypeEqualTo.String()
			value                  int
		)
		if !conditionVal.IsNull() && !conditionVal.IsUnknown() {
			condition = conditionVal.ValueString()
		}
		if !valueVal.IsNull() && !valueVal.IsUnknown() {
			value = int(valueVal.ValueInt64())
		}
		filters = append(filters, filterTypes.NewSearchFilter(
			cortexEnums.SearchFieldCreationTime.String(),
			condition,
			strconv.Itoa(value),
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
				Sort: []filterTypes.SortFilter{
					{
						Field: cortexEnums.SearchFieldInstanceName.String(),
						Order: "ASC",
					},
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
