// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package models

import (
	"context"

	cloudOnboardingTypes "github.com/PaloAltoNetworks/cortex-cloud-go/types/cloudonboarding"
	filterTypes "github.com/PaloAltoNetworks/cortex-cloud-go/types/filter"
	cortexEnums "github.com/PaloAltoNetworks/cortex-cloud-go/enums"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

type CloudIntegrationInstanceModel struct {
	ID                      types.String         `tfsdk:"id"`
	AdditionalCapabilities  types.Object         `tfsdk:"additional_capabilities"`
	CloudProvider           types.String         `tfsdk:"cloud_provider"`
	Collector               types.String         `tfsdk:"collector"`
	CollectionConfiguration types.Object         `tfsdk:"collection_configuration"`
	CustomResourcesTags     types.Set            `tfsdk:"custom_resources_tags"`
	InstanceName            types.String         `tfsdk:"instance_name"`
	Scan                    types.Object         `tfsdk:"scan"`
	Scope                   types.String         `tfsdk:"scope"`
	Status                  types.String         `tfsdk:"status"`
	SecurityCapabilities    []SecurityCapability `tfsdk:"security_capabilities"`
	UpgradeAvailable        types.Bool           `tfsdk:"upgrade_available"`
}

type SecurityCapability struct {
	Name             types.String `tfsdk:"name"`
	Description      types.String `tfsdk:"description"`
	StatusCode       types.Int32  `tfsdk:"status_code"`
	Status           types.String `tfsdk:"status"`
	LastScanCoverage types.Object `tfsdk:"last_scan_coverage"`
}

var lastScanCoverageAttrTypes = map[string]attr.Type{
	"excluded":    types.Int32Type,
	"issues":      types.Int32Type,
	"pending":     types.Int32Type,
	"success":     types.Int32Type,
	"unsupported": types.Int32Type,
}

func securityCapabilityStatusToString(statusCode int) string {
	switch statusCode {
	case 0:
		return "Connected"
	case 1:
		return "Warning"
	case 2:
		return "Disabled"
	case 3:
		return "Error"
	case 4:
		return "Retrieving"
	default:
		return "Unknown"
	}
}

func (m *CloudIntegrationInstanceModel) ToGetRequest(ctx context.Context, diags *diag.Diagnostics) cloudOnboardingTypes.GetIntegrationInstanceRequest {
	tflog.Debug(ctx, "Creating GetIntegrationInstanceRequest from CloudIntegrationInstanceModel")
	return cloudOnboardingTypes.GetIntegrationInstanceRequest{
		InstanceID: m.ID.ValueString(),
	}
}

func (m *CloudIntegrationInstanceModel) ToListRequest(ctx context.Context, diags *diag.Diagnostics) cloudOnboardingTypes.ListIntegrationInstancesRequest {
	tflog.Debug(ctx, "Creating ListIntegrationInstancesRequest from CloudIntegrationInstanceModel")
	return cloudOnboardingTypes.ListIntegrationInstancesRequest{
		FilterData: filterTypes.FilterData{
			Filter: filterTypes.NewAndFilter(
				filterTypes.NewSearchFilter(
					cortexEnums.SearchFieldID.String(),
					cortexEnums.SearchTypeWildcard.String(), 
					m.InstanceName.ValueString(),
				),
				filterTypes.NewSearchFilter(
					cortexEnums.SearchFieldStatus.String(),
					cortexEnums.SearchTypeNotEqualTo.String(),
					cortexEnums.IntegrationInstanceStatusPending.String(),
				),
			),
			Paging: filterTypes.PagingFilter{
				From: 0,
				To:   1000,
			},
			Sort: []filterTypes.SortFilter{
				{
					Field: "INSTANCE_NAME",
					Order: "ASC",
				},
			},
		},
	}
}

func (m *CloudIntegrationInstanceModel) RefreshFromRemote(ctx context.Context, diags *diag.Diagnostics, data cloudOnboardingTypes.IntegrationInstance) {
	tflog.Debug(ctx, "Refreshing attribute values")

	var diagsRefresh diag.Diagnostics

	tflog.Trace(ctx, "Converting AdditionalCapabilities to Terraform type")
	additionalCapabilities, diagsRefresh := types.ObjectValueFrom(ctx, m.AdditionalCapabilities.AttributeTypes(ctx), data.AdditionalCapabilities)
	diags.Append(diagsRefresh...)
	if diags.HasError() {
		return
	}

	tflog.Trace(ctx, "Converting CollectionConfiguration to Terraform type")
	collectionConfiguration, diagsRefresh := types.ObjectValueFrom(ctx, m.CollectionConfiguration.AttributeTypes(ctx), data.CollectionConfiguration)
	diags.Append(diagsRefresh...)
	if diags.HasError() {
		return
	}

	tflog.Trace(ctx, "Converting CustomResourceTags to Terraform type")
	tags, diagsRefresh := types.SetValueFrom(ctx, m.CustomResourcesTags.ElementType(ctx), data.CustomResourcesTags)
	diags.Append(diagsRefresh...)
	if diags.HasError() {
		return
	}

	tflog.Trace(ctx, "Converting Scan to Terraform type")
	// TODO: StatusUI and outpost_id should be null instead of default
	// empty values if not present in API response
	scan, diagsRefresh := types.ObjectValueFrom(ctx, m.Scan.AttributeTypes(ctx), data.Scan)
	diags.Append(diagsRefresh...)
	if diags.HasError() {
		return
	}

	tflog.Trace(ctx, "Converting SecurityCapabilities to Terraform type")
	var securityCapabilities []SecurityCapability
	for _, sc := range data.SecurityCapabilities {
		securityCapability := SecurityCapability{
			Name:        types.StringValue(sc.Name),
			Description: types.StringValue(sc.Description),
			StatusCode:  types.Int32Value(int32(sc.Status)),
			Status:      types.StringValue(securityCapabilityStatusToString(sc.Status)),
		}

		if sc.LastScanCoverage != nil {
			lastScanCoverage, diags := types.ObjectValueFrom(ctx, lastScanCoverageAttrTypes, sc.LastScanCoverage)
			diagsRefresh.Append(diags...)
			if diags.HasError() {
				return
			}
			securityCapability.LastScanCoverage = lastScanCoverage
		} else {
			securityCapability.LastScanCoverage = types.ObjectNull(lastScanCoverageAttrTypes)
		}

		securityCapabilities = append(securityCapabilities, securityCapability)
	}

	m.ID = types.StringValue(data.ID)
	m.AdditionalCapabilities = additionalCapabilities
	m.CloudProvider = types.StringValue(data.CloudProvider)
	m.Collector = types.StringValue(data.Collector)
	m.CollectionConfiguration = collectionConfiguration
	m.CustomResourcesTags = tags
	m.InstanceName = types.StringValue(data.InstanceName)
	m.Scan = scan
	m.Scope = types.StringValue(data.Scope)
	m.Status = types.StringValue(data.Status)
	m.SecurityCapabilities = securityCapabilities
	m.UpgradeAvailable = types.BoolValue(data.UpgradeAvailable)
}
