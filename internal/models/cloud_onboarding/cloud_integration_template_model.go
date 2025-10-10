// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package models

import (
	"context"

	cloudOnboardingTypes "github.com/PaloAltoNetworks/cortex-cloud-go/types/cloudonboarding"
	filterTypes "github.com/PaloAltoNetworks/cortex-cloud-go/types/filter"
	cortexEnums "github.com/PaloAltoNetworks/cortex-cloud-go/enums"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	//"github.com/hashicorp/terraform-plugin-log/tflog"
)

type CloudIntegrationTemplateModel struct {
	//AccountDetails            types.Object `tfsdk:"account_details"`
	AdditionalCapabilities    types.Object `tfsdk:"additional_capabilities"`
	CloudProvider             types.String `tfsdk:"cloud_provider"`
	CollectionConfiguration   types.Object `tfsdk:"collection_configuration"`
	CustomResourcesTags       types.Set    `tfsdk:"custom_resources_tags"`
	InstanceName              types.String `tfsdk:"instance_name"`
	ScanMode                  types.String `tfsdk:"scan_mode"`
	Scope                     types.String `tfsdk:"scope"`
	ScopeModifications        types.Object `tfsdk:"scope_modifications"`
	Status                    types.String `tfsdk:"status"`
	TrackingGUID              types.String `tfsdk:"tracking_guid"`
	OutpostID                 types.String `tfsdk:"outpost_id"`
	AutomatedDeploymentURL   types.String `tfsdk:"automated_deployment_url"`
	ManualDeploymentURL      types.String `tfsdk:"manual_deployment_url"`
	CloudFormationTemplateURL types.String `tfsdk:"cloud_formation_template_url"`
}

func (m *CloudIntegrationTemplateModel) ToCreateRequest(ctx context.Context, diagnostics *diag.Diagnostics) cloudOnboardingTypes.CreateIntegrationTemplateRequest {
	var additionalCapabilities cloudOnboardingTypes.AdditionalCapabilities
	diagnostics.Append(m.AdditionalCapabilities.As(ctx, &additionalCapabilities, basetypes.ObjectAsOptions{})...)

	var collectionConfiguration cloudOnboardingTypes.CollectionConfiguration
	diagnostics.Append(m.CollectionConfiguration.As(ctx, &collectionConfiguration, basetypes.ObjectAsOptions{})...)

	var customResourcesTags []cloudOnboardingTypes.Tag
	diagnostics.Append(m.CustomResourcesTags.ElementsAs(ctx, &customResourcesTags, false)...)

	var scopeModifications cloudOnboardingTypes.ScopeModifications
	diagnostics.Append(m.ScopeModifications.As(ctx, &scopeModifications, basetypes.ObjectAsOptions{})...)

	if diagnostics.HasError() {
		return cloudOnboardingTypes.CreateIntegrationTemplateRequest{}
	}

	request := cloudOnboardingTypes.CreateIntegrationTemplateRequest{
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

func (m *CloudIntegrationTemplateModel) ToGetRequest(ctx context.Context, diagnostics *diag.Diagnostics) cloudOnboardingTypes.ListIntegrationInstancesRequest {
	return cloudOnboardingTypes.ListIntegrationInstancesRequest{
		FilterData: filterTypes.FilterData{
			Filter: filterTypes.NewAndFilter(
				filterTypes.NewSearchFilter(
					cortexEnums.SearchFieldID.String(),
					cortexEnums.SearchTypeEqualTo.String(), 
					m.TrackingGUID.ValueString(),
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
		},
	}
}

func (m *CloudIntegrationTemplateModel) ToUpdateRequest(ctx context.Context, diagnostics *diag.Diagnostics) cloudOnboardingTypes.EditIntegrationInstanceRequest {
	var additionalCapabilities cloudOnboardingTypes.AdditionalCapabilities
	diagnostics.Append(m.AdditionalCapabilities.As(ctx, &additionalCapabilities, basetypes.ObjectAsOptions{})...)

	var collectionConfiguration cloudOnboardingTypes.CollectionConfiguration
	diagnostics.Append(m.CollectionConfiguration.As(ctx, &collectionConfiguration, basetypes.ObjectAsOptions{})...)

	var customResourcesTags []cloudOnboardingTypes.Tag
	diagnostics.Append(m.CustomResourcesTags.ElementsAs(ctx, &customResourcesTags, false)...)

	var scopeModifications cloudOnboardingTypes.ScopeModifications
	diagnostics.Append(m.ScopeModifications.As(ctx, &scopeModifications, basetypes.ObjectAsOptions{})...)

	if diagnostics.HasError() {
		return cloudOnboardingTypes.EditIntegrationInstanceRequest{}
	}

	return cloudOnboardingTypes.EditIntegrationInstanceRequest{
		AdditionalCapabilities:  additionalCapabilities,
		CloudProvider:           m.CloudProvider.ValueString(),
		CollectionConfiguration: collectionConfiguration,
		CustomResourcesTags:     customResourcesTags,
		InstanceID:              m.TrackingGUID.ValueString(),
		InstanceName:            m.InstanceName.ValueString(),
		ScopeModifications:      scopeModifications,
		ScanEnvID:               m.OutpostID.ValueString(),
	}
}

func (m *CloudIntegrationTemplateModel) ToDeleteRequest(ctx context.Context, diagnostics *diag.Diagnostics) cloudOnboardingTypes.DeleteIntegrationInstanceRequest {
	return cloudOnboardingTypes.DeleteIntegrationInstanceRequest{
		IDs: []string{m.TrackingGUID.ValueString()},
	}
}

// ----------------------------------------------------------------------------
// Refresh Resource Attributes
// ----------------------------------------------------------------------------

func (m *CloudIntegrationTemplateModel) RefreshComputedPropertyValues(diagnostics *diag.Diagnostics, response cloudOnboardingTypes.CreateTemplateOrEditIntegrationInstanceResponse) {
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

	m.TrackingGUID = types.StringValue(response.Automated.TrackingGuid)
	m.AutomatedDeploymentURL = types.StringValue(response.Automated.Link)
	m.ManualDeploymentURL = types.StringValue(response.Manual.CF)
	m.CloudFormationTemplateURL = types.StringValue(cloudFormationTemplateUrl)
}

func (m *CloudIntegrationTemplateModel) RefreshConfiguredPropertyValues(ctx context.Context, diagnostics *diag.Diagnostics, response cloudOnboardingTypes.ListIntegrationInstancesResponseWrapper) {
	// TODO: move this check outside?
	if len(response.Data) == 0 || len(response.Data) > 1 {
		m.Status = types.StringNull()
		m.InstanceName = types.StringNull()
		m.OutpostID = types.StringNull()

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
	m.OutpostID = types.StringValue(response.Data[0].OutpostID)
}
