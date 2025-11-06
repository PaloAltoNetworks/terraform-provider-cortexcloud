// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package models

/*
import (
	"context"
	"fmt"

	"github.com/PaloAltoNetworks/cortex-cloud-go/enums"
	cortexEnums "github.com/PaloAltoNetworks/cortex-cloud-go/enums"
	cloudOnboardingTypes "github.com/PaloAltoNetworks/cortex-cloud-go/types/cloudonboarding"
	filterTypes "github.com/PaloAltoNetworks/cortex-cloud-go/types/filter"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

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
	TrackingGUID              types.String `tfsdk:"tracking_guid"`
	OutpostID                 types.String `tfsdk:"outpost_id"`
	AutomatedDeploymentURL    types.String `tfsdk:"automated_deployment_url"`
	ManualDeploymentURL       types.String `tfsdk:"manual_deployment_url"`
	CloudFormationTemplateURL types.String `tfsdk:"cloud_formation_template_url"`
	ARMTemplateURL            types.String `tfsdk:"arm_template_url"`
}

func (m *CloudIntegrationTemplateModel) ToCreateRequest(ctx context.Context, diagnostics *diag.Diagnostics) *cloudOnboardingTypes.CreateIntegrationTemplateRequest {
	tflog.Debug(ctx, "Executing ToCreateRequest")

	//var accountDetails *cloudOnboardingTypes.AccountDetails = nil
	var accountDetails cloudOnboardingTypes.AccountDetails
	if !m.AccountDetails.IsNull() {
		//tflog.Debug(ctx, "Error diagnostic in AccountDetails")
		diagnostics.Append(m.AccountDetails.As(ctx, &accountDetails, basetypes.ObjectAsOptions{})...)
	}

	var additionalCapabilities cloudOnboardingTypes.AdditionalCapabilities
	diagnostics.Append(m.AdditionalCapabilities.As(ctx, &additionalCapabilities, basetypes.ObjectAsOptions{})...)

	var collectionConfiguration cloudOnboardingTypes.CollectionConfiguration
	diagnostics.Append(m.CollectionConfiguration.As(ctx, &collectionConfiguration, basetypes.ObjectAsOptions{})...)

	var customResourcesTags []cloudOnboardingTypes.Tag
	diagnostics.Append(m.CustomResourcesTags.ElementsAs(ctx, &customResourcesTags, false)...)

	var scopeModifications cloudOnboardingTypes.ScopeModifications
	diagnostics.Append(m.ScopeModifications.As(ctx, &scopeModifications, basetypes.ObjectAsOptions{})...)

	if diagnostics.HasError() {
		return nil
	}

	return cloudOnboardingTypes.NewCreateIntegrationTemplateRequest(
		cloudOnboardingTypes.WithAccountDetails(&accountDetails),
		cloudOnboardingTypes.WithAdditionalCapabilities(additionalCapabilities),
		cloudOnboardingTypes.WithCloudProvider(m.CloudProvider.ValueString()),
		cloudOnboardingTypes.WithCollectionConfiguration(collectionConfiguration),
		cloudOnboardingTypes.WithCustomResourcesTags(customResourcesTags),
		cloudOnboardingTypes.WithInstanceName(m.InstanceName.ValueString()),
		cloudOnboardingTypes.WithScanMode(m.ScanMode.ValueString()),
		cloudOnboardingTypes.WithScope(m.Scope.ValueString()),
		cloudOnboardingTypes.WithScopeModifications(scopeModifications),
	)
}

func (m *CloudIntegrationTemplateModel) ToGetRequest(ctx context.Context, diagnostics *diag.Diagnostics) *cloudOnboardingTypes.ListIntegrationInstancesRequest {
	var filter filterTypes.Filter
	switch m.CloudProvider.ValueString() {
	case enums.CloudProviderAWS.String():
		filter = filterTypes.NewAndFilter(
			filterTypes.NewSearchFilter(
				cortexEnums.SearchFieldID.String(),
				cortexEnums.SearchTypeEqualTo.String(),
				m.TrackingGUID.ValueString(),
			),
			filterTypes.NewSearchFilter(
				cortexEnums.SearchFieldStatus.String(),
				cortexEnums.SearchTypeEqualTo.String(),
				cortexEnums.IntegrationInstanceStatusPending.String(),
			),
		)
	default:
		filter = filterTypes.NewAndFilter(
			filterTypes.NewSearchFilter(
				cortexEnums.SearchFieldID.String(),
				cortexEnums.SearchTypeEqualTo.String(),
				m.TrackingGUID.ValueString(),
			),
			filterTypes.NewSearchFilter(
				cortexEnums.SearchFieldStatus.String(),
				cortexEnums.SearchTypeEqualTo.String(),
				cortexEnums.IntegrationInstanceStatusPending.String(),
			),
		)
	}

	return cloudOnboardingTypes.NewListIntegrationInstancesRequest(
		cloudOnboardingTypes.WithIntegrationFilterData(
			filterTypes.FilterData{
				Filter: filter,
				Paging: filterTypes.PagingFilter{
					From: 0,
					To:   1000,
				},
			},
		),
	)
}

//func (m *CloudIntegrationTemplateModel) ToUpdateRequest(ctx context.Context, diagnostics *diag.Diagnostics) cloudOnboardingTypes.EditIntegrationInstanceRequest {
//	var additionalCapabilities cloudOnboardingTypes.AdditionalCapabilities
//	diagnostics.Append(m.AdditionalCapabilities.As(ctx, &additionalCapabilities, basetypes.ObjectAsOptions{})...)
//
//	var collectionConfiguration cloudOnboardingTypes.CollectionConfiguration
//	diagnostics.Append(m.CollectionConfiguration.As(ctx, &collectionConfiguration, basetypes.ObjectAsOptions{})...)
//
//	var customResourcesTags []cloudOnboardingTypes.Tag
//	diagnostics.Append(m.CustomResourcesTags.ElementsAs(ctx, &customResourcesTags, false)...)
//
//	var scopeModifications cloudOnboardingTypes.ScopeModifications
//	diagnostics.Append(m.ScopeModifications.As(ctx, &scopeModifications, basetypes.ObjectAsOptions{})...)
//
//	if diagnostics.HasError() {
//		return cloudOnboardingTypes.EditIntegrationInstanceRequest{}
//	}
//
//	return cloudOnboardingTypes.EditIntegrationInstanceRequest{
//		AdditionalCapabilities:  additionalCapabilities,
//		CloudProvider:           m.CloudProvider.ValueString(),
//		CollectionConfiguration: collectionConfiguration,
//		CustomResourcesTags:     customResourcesTags,
//		InstanceID:              m.TrackingGUID.ValueString(),
//		InstanceName:            m.InstanceName.ValueString(),
//		ScopeModifications:      scopeModifications,
//		ScanEnvID:               m.OutpostID.ValueString(),
//	}
//}
//
//func (m *CloudIntegrationTemplateModel) ToDeleteRequest(ctx context.Context, diagnostics *diag.Diagnostics) cloudOnboardingTypes.DeleteIntegrationInstanceRequest {
//	return cloudOnboardingTypes.DeleteIntegrationInstanceRequest{
//		IDs: []string{m.TrackingGUID.ValueString()},
//	}
//}

func (m *CloudIntegrationTemplateModel) SetGeneratedValues(diagnostics *diag.Diagnostics, response cloudOnboardingTypes.CreateTemplateOrEditIntegrationInstanceResponse) {
	tflog.Debug(context.Background(), "Executing SetGeneratedValues")

	if response.Automated.TrackingGUID == nil {
		m.TrackingGUID = types.StringNull()
	} else {
		m.TrackingGUID = types.StringValue(*response.Automated.TrackingGUID)
	}

	if response.Automated.Link == nil {
		m.AutomatedDeploymentURL = types.StringNull()
	} else {
		m.AutomatedDeploymentURL = types.StringValue(*response.Automated.Link)
	}

	switch m.CloudProvider.ValueString() {
	case enums.CloudProviderAWS.String():
		tflog.Debug(context.Background(), "handling AWS values")

		m.AccountDetails = types.ObjectNull(m.AccountDetails.AttributeTypes(context.Background()))
		m.ARMTemplateURL = types.StringNull()

		cloudFormationTemplateURL, err := response.GetCloudFormationTemplateURL()
		if err != nil {
			diagnostics.AddError(
				"Error Parsing CloudFormation Template URL",
				fmt.Sprintf("Failed to parse CloudFormation template URL from API response: %s", err.Error()),
			)
		}

		tflog.Debug(context.Background(), "setting cloud formation template URL")
		m.CloudFormationTemplateURL = types.StringValue(cloudFormationTemplateURL)

		if response.Manual.CF != nil {
			tflog.Debug(context.Background(), "setting manual deployment URL to Manual.CF")
			m.ManualDeploymentURL = types.StringValue(*response.Manual.CF)
		} else {
			tflog.Debug(context.Background(), "setting manual deployment URL to nil")
			m.ManualDeploymentURL = types.StringNull()
		}
	case enums.CloudProviderAzure.String():
		tflog.Debug(context.Background(), "handling Azure values")

		m.CloudFormationTemplateURL = types.StringNull()

		trackingGUID, err := response.GetTrackingGUIDFromAzureResponse()
		if err != nil {
			diagnostics.AddError(
				"Error Parsing Tracking GUID",
				fmt.Sprintf("Failed to parse tracking GUID from API response: %s", err.Error()),
			)
		}

		tflog.Debug(context.Background(), "setting tracking GUID")
		m.TrackingGUID = types.StringValue(trackingGUID)

		if response.Manual.ARM != nil {
			tflog.Debug(context.Background(), "setting manual deployment URL to Manual.ARM")
			m.ManualDeploymentURL = types.StringValue(*response.Manual.ARM)
		} else {
			tflog.Debug(context.Background(), "setting manual deployment URL to nil")
			m.ManualDeploymentURL = types.StringNull()
		}
	default:
		// TODO: return a "please send this to developers" message
		diagnostics.AddError(
			"Error Setting Manual Deployment URL",
			fmt.Sprintf("Invalid cloud provider \"%s\".", m.CloudProvider.ValueString()),
		)
		return
	}
}

func (m *CloudIntegrationTemplateModel) RefreshConfiguredPropertyValues(ctx context.Context, diagnostics *diag.Diagnostics, response cloudOnboardingTypes.IntegrationInstance) {
	tflog.Debug(context.Background(), "Executing RefreshConfiguredPropertyValues")

	//if m.CloudProvider.ValueString() == enums.CloudProviderAzure.String() {
	//	var accountDetails basetypes.ObjectValue
	//	accountDetails, diags := types.ObjectValueFrom(ctx, m.AccountDetails.AttributeTypes(ctx), response.AccountName)
	//	//m.AccountDetails = types.ObjectNull(
	//	//	//	m.AccountDetails.AttributeTypes(ctx)
	//	//	//	map[string]attr.Type{
	//	//	//		"organization_id": types.StringType
	//	//	//	}
	//	//)
	//}

	var (
		additionalCapabilities  basetypes.ObjectValue
		collectionConfiguration basetypes.ObjectValue
		tags                    basetypes.SetValue
		diags                   diag.Diagnostics
	)

	additionalCapabilities, diags = types.ObjectValueFrom(ctx, m.AdditionalCapabilities.AttributeTypes(ctx), response.AdditionalCapabilities)
	diagnostics.Append(diags...)
	if diagnostics.HasError() {
		return
	}

	collectionConfiguration, diags = types.ObjectValueFrom(ctx, m.CollectionConfiguration.AttributeTypes(ctx), response.CollectionConfiguration)
	diagnostics.Append(diags...)
	if diagnostics.HasError() {
		return
	}

	tags, diags = types.SetValueFrom(ctx, m.CustomResourcesTags.ElementType(ctx), response.CustomResourcesTags)
	diagnostics.Append(diags...)
	if diagnostics.HasError() {
		return
	}
 
	//m.AccountDetails = types.ObjectNull(m.AccountDetails.AttributeTypes(ctx))
	m.AdditionalCapabilities = additionalCapabilities
	m.CloudProvider = types.StringValue(response.CloudProvider)
	m.CollectionConfiguration = collectionConfiguration
	m.CustomResourcesTags = tags
	m.InstanceName = types.StringValue(response.InstanceName)
	m.ScanMode = types.StringValue(response.Scan.ScanMethod)
	m.Status = types.StringValue(response.Status)
	m.OutpostID = types.StringValue(response.OutpostID)
}
*/
