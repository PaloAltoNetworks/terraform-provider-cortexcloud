// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package models

import (
	"context"

	cortexTypes "github.com/PaloAltoNetworks/cortex-cloud-go/types"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// *********************************************************
// Structs
// *********************************************************

type CloudIntegrationInstanceModel struct {
	Id                      types.String `tfsdk:"id"`
	AdditionalCapabilities  types.Object `tfsdk:"additional_capabilities"`
	CloudProvider           types.String `tfsdk:"cloud_provider"`
	Collector               types.String `tfsdk:"collector"`
	CollectionConfiguration types.Object `tfsdk:"collection_configuration"`
	CustomResourcesTags     types.Set    `tfsdk:"custom_resources_tags"`
	InstanceName            types.String `tfsdk:"instance_name"`
	Scan                    types.Object `tfsdk:"scan"`
	Status                  types.String `tfsdk:"status"`
	SecurityCapabilities    types.Set    `tfsdk:"security_capabilities"`
}

func (m *CloudIntegrationInstanceModel) ToGetRequest(ctx context.Context, diagnostics *diag.Diagnostics) cortexTypes.GetIntegrationInstanceRequest {
	return cortexTypes.GetIntegrationInstanceRequest{
		InstanceID: m.Id.ValueString(),
	}
}

func (m *CloudIntegrationInstanceModel) RefreshPropertyValues(ctx context.Context, diagnostics *diag.Diagnostics, response cortexTypes.GetIntegrationInstanceResponse) {
	data, err := response.Marshal()
	if err != nil {
		diagnostics.AddError(
			"Value Conversion Error", // TODO: standardize this
			err.Error(),
		)
		return
	}

	additionalCapabilities, diags := types.ObjectValueFrom(ctx, m.AdditionalCapabilities.AttributeTypes(ctx), data.AdditionalCapabilities)
	diagnostics.Append(diags...)
	if diagnostics.HasError() {
		return
	}

	collectionConfiguration, diags := types.ObjectValueFrom(ctx, m.CollectionConfiguration.AttributeTypes(ctx), data.CollectionConfiguration)
	diagnostics.Append(diags...)
	if diagnostics.HasError() {
		return
	}

	tags, diags := types.SetValueFrom(ctx, m.CustomResourcesTags.ElementType(ctx), data.CustomResourcesTags)
	diagnostics.Append(diags...)
	if diagnostics.HasError() {
		return
	}

	scan, diags := types.ObjectValueFrom(ctx, m.Scan.AttributeTypes(ctx), data.Scan)
	diagnostics.Append(diags...)
	if diagnostics.HasError() {
		return
	}

	securityCapabilities, diags := types.SetValueFrom(ctx, m.SecurityCapabilities.ElementType(ctx), data.SecurityCapabilities)
	diagnostics.Append(diags...)
	if diagnostics.HasError() {
		return
	}

	m.Id = types.StringValue(data.ID)
	m.AdditionalCapabilities = additionalCapabilities
	m.CloudProvider = types.StringValue(data.CloudProvider)
	m.Collector = types.StringValue(data.Collector)
	m.CollectionConfiguration = collectionConfiguration
	m.CustomResourcesTags = tags
	m.InstanceName = types.StringValue(data.InstanceName)
	m.Scan = scan
	m.Status = types.StringValue(data.Status)
	m.SecurityCapabilities = securityCapabilities
}
