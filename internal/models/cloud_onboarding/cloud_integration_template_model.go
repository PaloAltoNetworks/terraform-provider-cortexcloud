// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package models

import (
	"context"

	cortexTypes "github.com/PaloAltoNetworks/cortex-cloud-go/types"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	//"github.com/hashicorp/terraform-plugin-log/tflog"
)

// ----------------------------------------------------------------------------
// Structs
// ----------------------------------------------------------------------------

type CloudIntegrationTemplateModel struct {
	AccountDetails            types.Object `tfsdk:"account_details"`
	AdditionalCapabilities    types.Object `tfsdk:"additional_capabilities"`
	CloudProvider             types.String `tfsdk:"cloud_provider"`
	CollectionConfiguration   types.Object `tfsdk:"collection_configuration"`
	CustomResourcesTags       types.Set    `tfsdk:"custom_resources_tags"`
	InstanceName              types.String `tfsdk:"instance_name"`
	ScanMode                  types.String `tfsdk:"scan_mode"`
	Scope                     types.String `tfsdk:"scope"`
	ScopeModifications        types.Object `tfsdk:"scope_modifications"`
	Status                    types.String `tfsdk:"status"`
	TrackingGuid              types.String `tfsdk:"tracking_guid"`
	OutpostId                 types.String `tfsdk:"outpost_id"`
	AutomatedDeploymentLink   types.String `tfsdk:"automated_deployment_link"`
	ManualDeploymentLink      types.String `tfsdk:"manual_deployment_link"`
	CloudFormationTemplateUrl types.String `tfsdk:"cloud_formation_template_url"`
}

func (m *CloudIntegrationTemplateModel) ToCreateRequest(ctx context.Context, diagnostics *diag.Diagnostics) cortexTypes.CreateIntegrationTemplateRequest {
	var additionalCapabilities cortexTypes.AdditionalCapabilities
	diagnostics.Append(m.AdditionalCapabilities.As(ctx, &additionalCapabilities, basetypes.ObjectAsOptions{})...)

	var collectionConfiguration cortexTypes.CollectionConfiguration
	diagnostics.Append(m.CollectionConfiguration.As(ctx, &collectionConfiguration, basetypes.ObjectAsOptions{})...)

	var customResourcesTags []cortexTypes.Tag
	diagnostics.Append(m.CustomResourcesTags.ElementsAs(ctx, &customResourcesTags, false)...)

	var scopeModifications cortexTypes.ScopeModifications
	diagnostics.Append(m.ScopeModifications.As(ctx, &scopeModifications, basetypes.ObjectAsOptions{})...)

	if diagnostics.HasError() {
		return cortexTypes.CreateIntegrationTemplateRequest{}
	}

	request := cortexTypes.CreateIntegrationTemplateRequest{
		AdditionalCapabilities:  additionalCapabilities,
		CloudProvider:           m.CloudProvider.ValueString(),
		CollectionConfiguration: collectionConfiguration,
		CustomResourcesTags:     customResourcesTags,
		InstanceName:            m.InstanceName.ValueString(),
		ScanMode:                m.ScanMode.ValueString(),
		Scope:                   m.Scope.ValueString(),
		ScopeModifications:      scopeModifications,
	}

	return request
}

// ----------------------------------------------------------------------------
// SDK Request Conversion
// ----------------------------------------------------------------------------

func (m *CloudIntegrationTemplateModel) ToGetRequest(ctx context.Context, diagnostics *diag.Diagnostics) cortexTypes.ListIntegrationInstancesRequest {
	andFilters := []*cortexTypes.Filter{
		{
			SearchField: "ID",
			SearchType:  "EQ",
			SearchValue: m.TrackingGuid.ValueString(),
		},
		{
			SearchField: "STATUS",
			SearchType:  "EQ",
			SearchValue: "PENDING",
		},
	}

	return cortexTypes.ListIntegrationInstancesRequest{
		FilterData: cortexTypes.FilterData{
			Filter: cortexTypes.Filter{
				And: andFilters,
			},
			Paging: cortexTypes.PagingFilter{
				From: 0,
				To:   1000,
			},
		},
	}
}

func (m *CloudIntegrationTemplateModel) ToUpdateRequest(ctx context.Context, diagnostics *diag.Diagnostics) cortexTypes.EditIntegrationInstanceRequest {
	var additionalCapabilities cortexTypes.AdditionalCapabilities
	diagnostics.Append(m.AdditionalCapabilities.As(ctx, &additionalCapabilities, basetypes.ObjectAsOptions{})...)

	var collectionConfiguration cortexTypes.CollectionConfiguration
	diagnostics.Append(m.CollectionConfiguration.As(ctx, &collectionConfiguration, basetypes.ObjectAsOptions{})...)

	var customResourcesTags []cortexTypes.Tag
	diagnostics.Append(m.CustomResourcesTags.ElementsAs(ctx, &customResourcesTags, false)...)

	var scopeModifications cortexTypes.ScopeModifications
	diagnostics.Append(m.ScopeModifications.As(ctx, &scopeModifications, basetypes.ObjectAsOptions{})...)

	if diagnostics.HasError() {
		return cortexTypes.EditIntegrationInstanceRequest{}
	}

	return cortexTypes.EditIntegrationInstanceRequest{
		AdditionalCapabilities:  additionalCapabilities,
		CloudProvider:           m.CloudProvider.ValueString(),
		CollectionConfiguration: collectionConfiguration,
		CustomResourcesTags:     customResourcesTags,
		InstanceID:              m.TrackingGuid.ValueString(),
		InstanceName:            m.InstanceName.ValueString(),
		ScopeModifications:      scopeModifications,
		//ScanEnvId:               m.OutpostId.ValueString(),
		ScanEnvID: "43083abe03a648e7b029b9b1b5403b13",
	}
}

func (m *CloudIntegrationTemplateModel) ToDeleteRequest(ctx context.Context, diagnostics *diag.Diagnostics) cortexTypes.DeleteIntegrationInstanceRequest {
	return cortexTypes.DeleteIntegrationInstanceRequest{
		IDs: []string{m.TrackingGuid.ValueString()},
	}
}

// ----------------------------------------------------------------------------
// Refresh Resource Attributes
// ----------------------------------------------------------------------------

func (m *CloudIntegrationTemplateModel) RefreshComputedPropertyValues(diagnostics *diag.Diagnostics, response cortexTypes.CreateTemplateOrEditIntegrationInstanceResponse) {
	var (
		cloudFormationTemplateUrl = ""
		err                       error
	)
	if m.CloudProvider.ValueString() == "AWS" {
		cloudFormationTemplateUrl, err = response.GetTemplateUrl()
		if err != nil {
			diagnostics.AddError(
				"Error Parsing Template URL",
				err.Error(),
			)
		}
	}

	m.TrackingGuid = types.StringValue(response.Automated.TrackingGuid)
	m.AutomatedDeploymentLink = types.StringValue(response.Automated.Link)
	m.ManualDeploymentLink = types.StringValue(response.Manual.CF)
	m.CloudFormationTemplateUrl = types.StringValue(cloudFormationTemplateUrl)
}

func (m *CloudIntegrationTemplateModel) RefreshConfiguredPropertyValues(ctx context.Context, diagnostics *diag.Diagnostics, response cortexTypes.ListIntegrationInstancesResponseWrapper) {
	// TODO: move this check outside?
	if len(response.Data) == 0 || len(response.Data) > 1 {
		m.Status = types.StringNull()
		m.InstanceName = types.StringNull()
		m.OutpostId = types.StringNull()

		if len(response.Data) == 0 {
			diagnostics.AddWarning(
				"Integration Status Unknown",
				"Unable to retrieve computed values for the following arguments "+
					"from the Cortex Cloud API: status, instance_name, account_name, "+
					"outpost_id, creation_time\n\n"+
					"The provider will attempt to populate these arguments during "+
					"the next terraform apply operation.",
			)
		} else if len(response.Data) > 1 {
			diagnostics.AddWarning(
				"Integration Status Unknown",
				"Multiple values returned for the following arguments: "+
					"status, instance_name, account_name, outpost_id, creation_time\n\n"+
					"The provider will attempt to populate these arguments during "+
					"the next terraform refresh or apply operation.",
			)
		}

		return
	}

	marshalledResponse, err := response.Marshal()
	if err != nil {
		diagnostics.AddError(
			"Value Conversion Error", // TODO: standardize this
			err.Error(),
		)
		return
	}

	data := marshalledResponse[0]

	var (
		additionalCapabilities  basetypes.ObjectValue
		collectionConfiguration basetypes.ObjectValue
		tags                    basetypes.SetValue
		diags                   diag.Diagnostics
	)

	additionalCapabilities, diags = types.ObjectValueFrom(ctx, m.AdditionalCapabilities.AttributeTypes(ctx), data.AdditionalCapabilities)
	diagnostics.Append(diags...)
	if diagnostics.HasError() {
		return
	}

	// TODO: remove this conditional when API bug is fixed and CollectionConfiguration
	// isnt returned as an empty string
	if response.Data[0].CollectionConfiguration != "" {
		collectionConfiguration, diags = types.ObjectValueFrom(ctx, m.CollectionConfiguration.AttributeTypes(ctx), data.CollectionConfiguration)
		diagnostics.Append(diags...)
		if diagnostics.HasError() {
			return
		}
	} else {
		collectionConfiguration = types.ObjectNull(m.CollectionConfiguration.AttributeTypes(ctx))
	}

	tags, diags = types.SetValueFrom(ctx, m.CustomResourcesTags.ElementType(ctx), data.CustomResourcesTags)
	diagnostics.Append(diags...)
	if diagnostics.HasError() {
		return
	}

	m.AdditionalCapabilities = additionalCapabilities
	m.CloudProvider = types.StringValue(data.CloudProvider)
	//m.CollectionConfiguration = collectionConfiguration
	// TEMPORARY
	if !collectionConfiguration.IsNull() {
		m.CollectionConfiguration = collectionConfiguration
	}
	// END TEMPORARY
	m.CustomResourcesTags = tags
	m.InstanceName = types.StringValue(data.InstanceName)
	m.ScanMode = types.StringValue(data.Scan.ScanMethod)
	m.Status = types.StringValue(data.Status)
	// TODO: add OutpostId to IntegrationInstance struct?
	m.OutpostId = types.StringValue(response.Data[0].OutpostID)
}
