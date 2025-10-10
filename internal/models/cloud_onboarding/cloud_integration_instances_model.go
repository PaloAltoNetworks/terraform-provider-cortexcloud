// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package models

import (
	"context"

	cortexEnums "github.com/PaloAltoNetworks/cortex-cloud-go/enums"
	cloudOnboardingTypes "github.com/PaloAltoNetworks/cortex-cloud-go/types/cloudonboarding"
	filterTypes "github.com/PaloAltoNetworks/cortex-cloud-go/types/filter"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// CloudIntegrationInstancesDataSourceModel is the model for the cloud_integration_instances data source.
type CloudIntegrationInstancesDataSourceModel struct {
	ID                   types.String                    `tfsdk:"id"`
	CloudProvider        types.String                    `tfsdk:"cloud_provider"`
	Name                 types.String                    `tfsdk:"name"`
	Status               types.String                    `tfsdk:"status"`
	Scope                types.String                    `tfsdk:"scope"`
	ScanMode             types.String                    `tfsdk:"scan_mode"`
	CreationTime         types.String                    `tfsdk:"creation_time"`
	OutpostID            types.String                    `tfsdk:"outpost_id"`
	AuthenticationMethod types.String                    `tfsdk:"authentication_method"`
	InstanceID           types.String                    `tfsdk:"instance_id"`
	Instances            []cloudIntegrationInstanceModel `tfsdk:"instances"`
	TotalCount types.Int32 `tfsdk:"total_count"`
}

// cloudIntegrationInstancesModel is the model for the individual cloud integration instances returned by the API according to the configured filter values.
type cloudIntegrationInstanceModel struct {
	ID                     types.String `tfsdk:"id"`
	AdditionalCapabilities types.Object `tfsdk:"additional_capabilities"`
	CloudProvider          types.String `tfsdk:"cloud_provider"`
	CustomResourcesTags    types.Set    `tfsdk:"custom_resources_tags"`
	InstanceName           types.String `tfsdk:"instance_name"`
	Scope                  types.String `tfsdk:"scope"`
	Status                 types.String `tfsdk:"status"`
	AccountName            types.String `tfsdk:"account_name"`
	TotalAccounts          types.Int32  `tfsdk:"total_accounts"`
	ScanMode               types.String `tfsdk:"scan_mode"`
	CreationTime           types.Int64  `tfsdk:"creation_time"`
	ProvisioningMethod     types.String `tfsdk:"provisioning_method"`
	UpdateStatus           types.String `tfsdk:"update_status"`
	IsPendingChanges       types.Bool   `tfsdk:"is_pending_changes"`
	OutpostID              types.String `tfsdk:"outpost_id"`
}

var (
	additionalCapabilitiesAttrTypes = map[string]attr.Type{
		"data_security_posture_management": types.BoolType,
		"registry_scanning":                types.BoolType,
		"registry_scanning_options": types.ObjectType{
			AttrTypes: map[string]attr.Type{
				"type": types.StringType,
			},
		},
		"agentless_disk_scanning": types.BoolType,
		"xsiam_analytics":         types.BoolType,
	}
	customResourcesTagsAttrTypes = types.SetType{
		ElemType: types.ObjectType{
			AttrTypes: map[string]attr.Type{
				"key":   types.StringType,
				"value": types.StringType,
			},
		},
	}
)

// ToListRequest converts the model to a ListIntegrationInstancesRequest.
func (m *CloudIntegrationInstancesDataSourceModel) ToListRequest(ctx context.Context, diags *diag.Diagnostics) cloudOnboardingTypes.ListIntegrationInstancesRequest {
	tflog.Debug(ctx, "Creating ListIntegrationInstancesRequest from CloudIntegrationInstancesDataSourceModel")

	var filters []filterTypes.Filter
	if !m.CloudProvider.IsNull() && !m.CloudProvider.IsUnknown() {
		filters = append(filters, filterTypes.NewSearchFilter(
			cortexEnums.SearchFieldProvider.String(),
			"EQ",
			m.CloudProvider.ValueString(),
		))
	}
	if !m.Name.IsNull() && !m.Name.IsUnknown() {
		filters = append(filters, filterTypes.NewSearchFilter(
			cortexEnums.SearchFieldInstanceName.String(),
			"WILDCARD",
			m.Name.ValueString(),
		))
	}
	if !m.Status.IsNull() && !m.Status.IsUnknown() {
		filters = append(filters, filterTypes.NewSearchFilter(
			cortexEnums.SearchFieldStatus.String(),
			"EQ",
			m.Status.ValueString(),
		))
	}
	if !m.Scope.IsNull() && !m.Scope.IsUnknown() {
		filters = append(filters, filterTypes.NewSearchFilter(
			cortexEnums.SearchFieldScope.String(),
			"EQ",
			m.Scope.ValueString(),
		))
	}
	if !m.ScanMode.IsNull() && !m.ScanMode.IsUnknown() {
		filters = append(filters, filterTypes.NewSearchFilter(
			cortexEnums.SearchFieldScanMode.String(),
			"EQ",
			m.ScanMode.ValueString(),
		))
	}
	if !m.CreationTime.IsNull() && !m.CreationTime.IsUnknown() {
		filters = append(filters, filterTypes.NewSearchFilter(
			cortexEnums.SearchFieldCreationTime.String(),
			"EQ",
			m.CreationTime.ValueString(),
		))
	}
	if !m.OutpostID.IsNull() && !m.OutpostID.IsUnknown() {
		filters = append(filters, filterTypes.NewSearchFilter(
			cortexEnums.SearchFieldOutpostID.String(),
			"WILDCARD",
			m.OutpostID.ValueString(),
		))
	}
	if !m.AuthenticationMethod.IsNull() && !m.AuthenticationMethod.IsUnknown() {
		filters = append(filters, filterTypes.NewSearchFilter(
			cortexEnums.SearchFieldAuthenticationMethod.String(),
			"EQ",
			m.AuthenticationMethod.ValueString(),
		))
	}
	if !m.InstanceID.IsNull() && !m.InstanceID.IsUnknown() {
		filters = append(filters, filterTypes.NewSearchFilter(
			cortexEnums.SearchFieldID.String(),
			"WILDCARD",
			m.InstanceID.ValueString(),
		))
	}

	var finalFilter filterTypes.Filter
	if len(filters) > 0 {
		finalFilter = filterTypes.NewAndFilter(filters...)
	}

	return cloudOnboardingTypes.ListIntegrationInstancesRequest{
		FilterData: filterTypes.FilterData{
			Filter: finalFilter,
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
	}
}


// RefreshFromRemote refreshes the model from the remote API response.
func (m *CloudIntegrationInstancesDataSourceModel) RefreshFromRemote(ctx context.Context, diags *diag.Diagnostics, remote []cloudOnboardingTypes.IntegrationInstance) {
	tflog.Debug(ctx, "Refreshing cloud integration instances model from remote")

	var instances []cloudIntegrationInstanceModel
	for _, data := range remote {
		var instanceModel cloudIntegrationInstanceModel
		var diagsRefresh diag.Diagnostics

		tflog.Trace(ctx, "Converting AdditionalCapabilities to Terraform type")
		additionalCapabilities, diagsRefresh := types.ObjectValueFrom(ctx, additionalCapabilitiesAttrTypes, data.AdditionalCapabilities)
		diags.Append(diagsRefresh...)
		if diags.HasError() {
			return
		}

		tflog.Trace(ctx, "Converting CustomResourceTags to Terraform type")
		tags, diagsRefresh := types.SetValueFrom(ctx, customResourcesTagsAttrTypes.ElemType, data.CustomResourcesTags)
		diags.Append(diagsRefresh...)
		if diags.HasError() {
			return
		}

		var isPendingChanges bool = false
		if data.IsPendingChanges == 1 {
			isPendingChanges = true
		}

		instanceModel.ID = types.StringValue(data.ID)
		instanceModel.AccountName = types.StringValue(data.AccountName)
		instanceModel.TotalAccounts = types.Int32Value(int32(data.Accounts))
		instanceModel.ScanMode = types.StringValue(data.Scan.ScanMethod)
		instanceModel.CreationTime = types.Int64Value(int64(data.CreationTime))
		instanceModel.AdditionalCapabilities = additionalCapabilities
		instanceModel.CloudProvider = types.StringValue(data.CloudProvider)
		instanceModel.ProvisioningMethod = types.StringValue(data.ProvisioningMethod)
		instanceModel.CustomResourcesTags = tags
		instanceModel.UpdateStatus = types.StringValue(data.UpdateStatus)
		instanceModel.IsPendingChanges = types.BoolValue(isPendingChanges)
		instanceModel.InstanceName = types.StringValue(data.InstanceName)
		instanceModel.Scope = types.StringValue(data.Scope)
		instanceModel.Status = types.StringValue(data.Status)
		instanceModel.OutpostID = types.StringValue(data.OutpostID)

		instances = append(instances, instanceModel)
	}
	m.Instances = instances
	m.TotalCount = types.Int32Value(int32(len(instances)))
	m.ID = types.StringValue("cortexcloud_cloud_integration_instances")
}
