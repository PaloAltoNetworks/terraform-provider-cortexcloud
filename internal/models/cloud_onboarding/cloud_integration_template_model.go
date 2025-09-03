// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package models

import (
	"context"

	"github.com/PaloAltoNetworks/cortex-cloud-go/cloudonboarding"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
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

func (m *CloudIntegrationTemplateModel) ToCreateRequest(ctx context.Context, diagnostics *diag.Diagnostics) cloudonboarding.CreateIntegrationTemplateRequest {
	var additionalCapabilities cloudonboarding.AdditionalCapabilities
	diagnostics.Append(m.AdditionalCapabilities.As(ctx, &additionalCapabilities, basetypes.ObjectAsOptions{})...)

	var collectionConfiguration cloudonboarding.CollectionConfiguration
	diagnostics.Append(m.CollectionConfiguration.As(ctx, &collectionConfiguration, basetypes.ObjectAsOptions{})...)

	var customResourcesTags []cloudonboarding.Tag
	diagnostics.Append(m.CustomResourcesTags.ElementsAs(ctx, &customResourcesTags, false)...)

	var scopeModifications cloudonboarding.ScopeModifications
	diagnostics.Append(m.ScopeModifications.As(ctx, &scopeModifications, basetypes.ObjectAsOptions{})...)

	if diagnostics.HasError() {
		return cloudonboarding.CreateIntegrationTemplateRequest{}
	}

	request := cloudonboarding.CreateIntegrationTemplateRequest{
		Data: cloudonboarding.CreateIntegrationTemplateRequestData{
			AdditionalCapabilities:  additionalCapabilities,
			CloudProvider:           m.CloudProvider.ValueString(),
			CollectionConfiguration: collectionConfiguration,
			CustomResourcesTags:     customResourcesTags,
			InstanceName:            m.InstanceName.ValueString(),
			ScanMode:                m.ScanMode.ValueString(),
			Scope:                   m.Scope.ValueString(),
			ScopeModifications:      scopeModifications,
		},
	}

	return request
}

// ----------------------------------------------------------------------------
// SDK Request Conversion
// ----------------------------------------------------------------------------

func (m *CloudIntegrationTemplateModel) ToGetRequest(ctx context.Context, diagnostics *diag.Diagnostics) cloudonboarding.ListIntegrationInstancesRequest {
	andFilters := []cloudonboarding.Criteria{
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

	return cloudonboarding.ListIntegrationInstancesRequest{
		RequestData: cloudonboarding.ListIntegrationInstancesRequestData{
			FilterData: cloudonboarding.FilterData{
				Filter: cloudonboarding.CriteriaFilter{
					And: andFilters,
				},
				Paging: cloudonboarding.PagingFilter{
					From: 0,
					To:   1000,
				},
			},
		},
	}
}

func (m *CloudIntegrationTemplateModel) ToUpdateRequest(ctx context.Context, diagnostics *diag.Diagnostics) cloudonboarding.EditIntegrationInstanceRequest {
	var additionalCapabilities cloudonboarding.AdditionalCapabilities
	diagnostics.Append(m.AdditionalCapabilities.As(ctx, &additionalCapabilities, basetypes.ObjectAsOptions{})...)

	var collectionConfiguration cloudonboarding.CollectionConfiguration
	diagnostics.Append(m.CollectionConfiguration.As(ctx, &collectionConfiguration, basetypes.ObjectAsOptions{})...)

	var customResourcesTags []cloudonboarding.Tag
	diagnostics.Append(m.CustomResourcesTags.ElementsAs(ctx, &customResourcesTags, false)...)

	var scopeModifications cloudonboarding.ScopeModifications
	diagnostics.Append(m.ScopeModifications.As(ctx, &scopeModifications, basetypes.ObjectAsOptions{})...)

	if diagnostics.HasError() {
		return cloudonboarding.EditIntegrationInstanceRequest{}
	}

	return cloudonboarding.EditIntegrationInstanceRequest{
		RequestData: cloudonboarding.EditIntegrationInstanceRequestData{
			AdditionalCapabilities:  additionalCapabilities,
			CloudProvider:           m.CloudProvider.ValueString(),
			CollectionConfiguration: collectionConfiguration,
			CustomResourcesTags:     customResourcesTags,
			InstanceId:              m.TrackingGuid.ValueString(),
			InstanceName:            m.InstanceName.ValueString(),
			ScopeModifications:      scopeModifications,
			//ScanEnvId:               m.OutpostId.ValueString(),
			ScanEnvId: "43083abe03a648e7b029b9b1b5403b13",
		},
	}
}

func (m *CloudIntegrationTemplateModel) ToDeleteRequest(ctx context.Context, diagnostics *diag.Diagnostics) cloudonboarding.DeleteInstanceRequest {
	return cloudonboarding.DeleteInstanceRequest{
		Data: cloudonboarding.DeleteInstanceRequestData{
			Ids: []string{m.TrackingGuid.ValueString()},
		},
	}
}

// ----------------------------------------------------------------------------
// Refresh Resource Attributes
// ----------------------------------------------------------------------------

func (m *CloudIntegrationTemplateModel) RefreshComputedPropertyValues(diagnostics *diag.Diagnostics, response cloudonboarding.CreateTemplateOrEditIntegrationInstanceResponse) {
	data := response.Reply

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

	m.TrackingGuid = types.StringValue(data.Automated.TrackingGuid)
	m.AutomatedDeploymentLink = types.StringValue(data.Automated.Link)
	m.ManualDeploymentLink = types.StringValue(data.Manual.TF_ARM)
	m.CloudFormationTemplateUrl = types.StringValue(cloudFormationTemplateUrl)
}

func (m *CloudIntegrationTemplateModel) RefreshConfiguredPropertyValues(ctx context.Context, diagnostics *diag.Diagnostics, response cloudonboarding.ListIntegrationInstancesResponse) {
	// TODO: move this check outside?
	if len(response.Reply.Data) == 0 || len(response.Reply.Data) > 1 {
		m.Status = types.StringNull()
		m.InstanceName = types.StringNull()
		m.OutpostId = types.StringNull()

		if len(response.Reply.Data) == 0 {
			diagnostics.AddWarning(
				"Integration Status Unknown",
				"Unable to retrieve computed values for the following arguments "+
					"from the Cortex Cloud API: status, instance_name, account_name, "+
					"outpost_id, creation_time\n\n"+
					"The provider will attempt to populate these arguments during "+
					"the next terraform apply operation.",
			)
		} else if len(response.Reply.Data) > 1 {
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
	if response.Reply.Data[0].CollectionConfiguration != "" {
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
	m.OutpostId = types.StringValue(response.Reply.Data[0].OutpostId)
}
