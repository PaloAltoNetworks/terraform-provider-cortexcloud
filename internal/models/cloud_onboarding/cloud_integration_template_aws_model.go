// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package models

import (
	"context"
	"fmt"
	"slices"

	"github.com/PaloAltoNetworks/cortex-cloud-go/enums"
	cortexEnums "github.com/PaloAltoNetworks/cortex-cloud-go/enums"
	cloudOnboardingTypes "github.com/PaloAltoNetworks/cortex-cloud-go/types/cloudonboarding"
	filterTypes "github.com/PaloAltoNetworks/cortex-cloud-go/types/filter"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var managedByPANWTag = cloudOnboardingTypes.Tag{
	Key: "managed_by",
	Value: "paloaltonetworks",
}

type CloudIntegrationTemplateAwsModel struct {
	AdditionalCapabilities    types.Object `tfsdk:"additional_capabilities"`
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
	CloudFormationTemplateURL types.String `tfsdk:"cloudformation_template_url"`
}

type scopeModificationsAws struct {
	Accounts      *scopeModificationAccounts `json:"accounts,omitempty" tfsdk:"accounts"`
	Regions       *scopeModificationRegions `json:"regions,omitempty" tfsdk:"regions"`
}

type scopeModificationAccounts struct {
	Enabled    bool     `json:"enabled" tfsdk:"enabled"`
	Type       *string   `json:"type,omitempty" tfsdk:"type"`
	AccountIDs *[]string `json:"account_ids,omitempty" tfsdk:"account_ids"`
}

func (m *CloudIntegrationTemplateAwsModel) ToCreateRequest(ctx context.Context, diagnostics *diag.Diagnostics) *cloudOnboardingTypes.CreateIntegrationTemplateRequest {
	ctx = tflog.SetField(ctx, "resource_operation", "ToCreateRequest")

	var additionalCapabilities cloudOnboardingTypes.AdditionalCapabilities
	diagnostics.Append(m.AdditionalCapabilities.As(ctx, &additionalCapabilities, basetypes.ObjectAsOptions{})...)

	var collectionConfiguration cloudOnboardingTypes.CollectionConfiguration
	diagnostics.Append(m.CollectionConfiguration.As(ctx, &collectionConfiguration, basetypes.ObjectAsOptions{})...)

	var customResourcesTags []cloudOnboardingTypes.Tag
	diagnostics.Append(m.CustomResourcesTags.ElementsAs(ctx, &customResourcesTags, false)...)

	// TODO: figure out how to handle this without the intermediate types
	var scopeModificationsValue scopeModificationsAws
	diagnostics.Append(m.ScopeModifications.As(ctx, &scopeModificationsValue, basetypes.ObjectAsOptions{})...)

	scopeModifications := cloudOnboardingTypes.ScopeModifications{}
	if scopeModificationsValue.Regions != nil {
		scopeModifications.Regions = &cloudOnboardingTypes.ScopeModificationRegions{
			Enabled: scopeModificationsValue.Regions.Enabled,
			Type: scopeModificationsValue.Regions.Type,
			Regions: scopeModificationsValue.Regions.Regions,
		}
	}
	if scopeModificationsValue.Accounts != nil {
		scopeModifications.Accounts = &cloudOnboardingTypes.ScopeModificationGeneric{
			Enabled: scopeModificationsValue.Accounts.Enabled,
			Type: scopeModificationsValue.Accounts.Type,
			AccountIDs: scopeModificationsValue.Accounts.AccountIDs,
		}
	}

	if diagnostics.HasError() {
		return nil
	}

	if !slices.Contains(customResourcesTags, managedByPANWTag) {
		customResourcesTags = append(customResourcesTags, managedByPANWTag)
	}

	return cloudOnboardingTypes.NewCreateIntegrationTemplateRequest(
		cloudOnboardingTypes.WithAdditionalCapabilities(additionalCapabilities),
		cloudOnboardingTypes.WithCloudProvider(enums.CloudProviderAWS.String()),
		cloudOnboardingTypes.WithCollectionConfiguration(collectionConfiguration),
		cloudOnboardingTypes.WithCustomResourcesTags(customResourcesTags),
		cloudOnboardingTypes.WithInstanceName(m.InstanceName.ValueString()),
		cloudOnboardingTypes.WithScanMode(m.ScanMode.ValueString()),
		cloudOnboardingTypes.WithScope(m.Scope.ValueString()),
		cloudOnboardingTypes.WithScopeModifications(scopeModifications),
	)
}

func (m *CloudIntegrationTemplateAwsModel) ToGetRequest(ctx context.Context, diagnostics *diag.Diagnostics) *cloudOnboardingTypes.ListIntegrationInstancesRequest {
	ctx = tflog.SetField(ctx, "resource_operation", "ToGetRequest")

	filter := filterTypes.NewAndFilter(
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

func (m *CloudIntegrationTemplateAwsModel) SetGeneratedValues(ctx context.Context, diagnostics *diag.Diagnostics, response cloudOnboardingTypes.CreateTemplateOrEditIntegrationInstanceResponse) {
	ctx = tflog.SetField(ctx, "resource_operation", "SetGeneratedValues")

	if m.OutpostID.IsNull() || m.OutpostID.IsUnknown() {
		m.OutpostID = types.StringNull()
	}

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

	cloudFormationTemplateURL, err := response.GetCloudFormationTemplateURL()
	if err != nil {
		diagnostics.AddError(
			"Error Parsing CloudFormation Template URL",
			fmt.Sprintf("Failed to parse CloudFormation template URL from API response: %s", err.Error()),
		)
	}

	tflog.Debug(ctx, "Setting cloud formation template URL")
	m.CloudFormationTemplateURL = types.StringValue(cloudFormationTemplateURL)

	if response.Manual.CF != nil {
		tflog.Debug(ctx, "Setting manual deployment URL to Manual.CF")
		m.ManualDeploymentURL = types.StringValue(*response.Manual.CF)
	} else {
		tflog.Debug(ctx, "Setting manual deployment URL to nil")
		m.ManualDeploymentURL = types.StringNull()
	}
}

func (m *CloudIntegrationTemplateAwsModel) RefreshConfiguredPropertyValues(ctx context.Context, diagnostics *diag.Diagnostics, state CloudIntegrationTemplateAwsModel, apiResponse cloudOnboardingTypes.IntegrationInstance) {
	ctx = tflog.SetField(ctx, "resource_operation", "RefreshConfiguredPropertyValues")

	var (
		diags                   diag.Diagnostics
		additionalCapabilities  basetypes.ObjectValue
		customResourcesTags = types.SetNull(types.ObjectType{
			AttrTypes: map[string]attr.Type{
				"key": types.StringType,
				"value": types.StringType,
			},
		})
	)

	additionalCapabilities, diags = types.ObjectValueFrom(ctx, m.AdditionalCapabilities.AttributeTypes(ctx), apiResponse.AdditionalCapabilities)
	diagnostics.Append(diags...)
	if diagnostics.HasError() {
		return
	}

	if !state.CustomResourcesTags.IsNull() {
		for idx, tag := range apiResponse.CustomResourcesTags {
			if tag == managedByPANWTag {
				if len(apiResponse.CustomResourcesTags) == 1 {
					apiResponse.CustomResourcesTags = []cloudOnboardingTypes.Tag{}
				} else {
					apiResponse.CustomResourcesTags = append(
						apiResponse.CustomResourcesTags[:idx],
						apiResponse.CustomResourcesTags[idx+1:]...,
					)
				}
			}
		}

		customResourcesTags, diags = types.SetValueFrom(ctx, m.CustomResourcesTags.ElementType(ctx), apiResponse.CustomResourcesTags)
		diagnostics.Append(diags...)
		if diagnostics.HasError() {
			return
		}
	}
	m.CustomResourcesTags = customResourcesTags

	if state.InstanceName.IsNull() && apiResponse.InstanceName == "" {
		m.InstanceName = types.StringNull()
	} else {
		m.InstanceName = types.StringValue(apiResponse.InstanceName)
	}

	// For now, we're keeping outpost_id as null if not configured by the user
	// as we do not have a means of retrieving the default outpost from the
	// platform
	m.OutpostID = types.StringValue(apiResponse.OutpostID)

	m.AdditionalCapabilities = additionalCapabilities
	m.ScanMode = types.StringValue(apiResponse.Scan.ScanMethod)
	m.Status = types.StringValue(apiResponse.Status)

}
