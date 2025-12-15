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
	"github.com/hashicorp/terraform-plugin-framework/attr"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

type CloudIntegrationTemplateAzureModel struct {
	AccountDetails          types.Object `tfsdk:"account_details"`
	AdditionalCapabilities  types.Object `tfsdk:"additional_capabilities"`
	CollectionConfiguration types.Object `tfsdk:"collection_configuration"`
	CustomResourcesTags     types.Set    `tfsdk:"custom_resources_tags"`
	InstanceName            types.String `tfsdk:"instance_name"`
	ScanMode                types.String `tfsdk:"scan_mode"`
	Scope                   types.String `tfsdk:"scope"`
	ScopeModifications      types.Object `tfsdk:"scope_modifications"`
	Status                  types.String `tfsdk:"status"`
	TrackingGUID            types.String `tfsdk:"tracking_guid"`
	OutpostID               types.String `tfsdk:"outpost_id"`
	TerraformModuleURL      types.String `tfsdk:"terraform_module_url"`
	ARMTemplateURL          types.String `tfsdk:"arm_template_url"`
}

type scopeModificationsAzure struct {
	Subscriptions *scopeModificationSubscriptions `json:"subscriptions,omitempty" tfsdk:"subscriptions"`
	Regions       *scopeModificationRegions       `json:"regions,omitempty" tfsdk:"regions"`
}

type scopeModificationSubscriptions struct {
	Enabled         bool      `json:"enabled" tfsdk:"enabled"`
	Type            *string   `json:"type,omitempty" tfsdk:"type"`
	SubscriptionIDs *[]string `json:"subscription_ids,omitempty" tfsdk:"subscription_ids"`
}

func (m *CloudIntegrationTemplateAzureModel) ToCreateRequest(ctx context.Context, diagnostics *diag.Diagnostics) *cloudOnboardingTypes.CreateIntegrationTemplateRequest {
	ctx = tflog.SetField(ctx, "resource_operation", "ToCreateRequest")

	var accountDetails cloudOnboardingTypes.AccountDetails
	if !m.AccountDetails.IsNull() {
		diagnostics.Append(m.AccountDetails.As(ctx, &accountDetails, basetypes.ObjectAsOptions{})...)
	}

	var additionalCapabilities cloudOnboardingTypes.AdditionalCapabilities
	diagnostics.Append(m.AdditionalCapabilities.As(ctx, &additionalCapabilities, basetypes.ObjectAsOptions{})...)

	var collectionConfiguration cloudOnboardingTypes.CollectionConfiguration
	diagnostics.Append(m.CollectionConfiguration.As(ctx, &collectionConfiguration, basetypes.ObjectAsOptions{})...)

	var customResourcesTags []cloudOnboardingTypes.Tag
	diagnostics.Append(m.CustomResourcesTags.ElementsAs(ctx, &customResourcesTags, false)...)

	var scopeModificationsValue scopeModificationsAzure
	diagnostics.Append(m.ScopeModifications.As(ctx, &scopeModificationsValue, basetypes.ObjectAsOptions{})...)

	scopeModifications := cloudOnboardingTypes.ScopeModifications{}
	if scopeModificationsValue.Regions != nil {
		scopeModifications.Regions = &cloudOnboardingTypes.ScopeModificationRegions{
			Enabled: scopeModificationsValue.Regions.Enabled,
			Type:    scopeModificationsValue.Regions.Type,
			Regions: scopeModificationsValue.Regions.Regions,
		}
	}
	if scopeModificationsValue.Subscriptions != nil {
		scopeModifications.Subscriptions = &cloudOnboardingTypes.ScopeModificationGeneric{
			Enabled:         scopeModificationsValue.Subscriptions.Enabled,
			Type:            scopeModificationsValue.Subscriptions.Type,
			SubscriptionIDs: scopeModificationsValue.Subscriptions.SubscriptionIDs,
		}
	}

	if diagnostics.HasError() {
		return nil
	}

	if !slices.Contains(customResourcesTags, managedByPANWTag) {
		customResourcesTags = append(customResourcesTags, managedByPANWTag)
	}

	return cloudOnboardingTypes.NewCreateIntegrationTemplateRequest(
		cloudOnboardingTypes.WithAccountDetails(&accountDetails),
		cloudOnboardingTypes.WithAdditionalCapabilities(additionalCapabilities),
		cloudOnboardingTypes.WithCloudProvider(enums.CloudProviderAzure.String()),
		cloudOnboardingTypes.WithCollectionConfiguration(collectionConfiguration),
		cloudOnboardingTypes.WithCustomResourcesTags(customResourcesTags),
		cloudOnboardingTypes.WithInstanceName(m.InstanceName.ValueString()),
		cloudOnboardingTypes.WithScanMode(m.ScanMode.ValueString()),
		cloudOnboardingTypes.WithScope(m.Scope.ValueString()),
		cloudOnboardingTypes.WithScopeModifications(scopeModifications),
	)
}

func (m *CloudIntegrationTemplateAzureModel) ToGetRequest(ctx context.Context, diagnostics *diag.Diagnostics) *cloudOnboardingTypes.ListIntegrationInstancesRequest {
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

func (m *CloudIntegrationTemplateAzureModel) SetGeneratedValues(ctx context.Context, diagnostics *diag.Diagnostics, response cloudOnboardingTypes.CreateTemplateOrEditIntegrationInstanceResponse) {
	ctx = tflog.SetField(ctx, "resource_operation", "SetGeneratedValues")

	trackingGUID, err := response.GetTrackingGUIDFromARMURL()
	if err != nil {
		diagnostics.AddError(
			"Error Parsing Tracking GUID",
			fmt.Sprintf("Failed to parse tracking GUID from API response: %s", err.Error()),
		)
	}

	tflog.Debug(context.Background(), "Setting tracking GUID")
	m.TrackingGUID = types.StringValue(trackingGUID)

	if response.Manual.TF != nil {
		tflog.Debug(context.Background(), "Setting Terraform module URL")
		m.TerraformModuleURL = types.StringValue(*response.Manual.TF)
	} else {
		tflog.Debug(context.Background(), "Terraform module URL not found, setting Terraform deployment URL to nil")
		m.TerraformModuleURL = types.StringNull()
	}

	if response.Manual.ARM != nil {
		tflog.Debug(context.Background(), "Setting ARM deployment URL")
		m.ARMTemplateURL = types.StringValue(*response.Manual.ARM)
	} else {
		tflog.Debug(context.Background(), "ARM deployment URL not found, setting ARM deployment URL to nil")
		m.ARMTemplateURL = types.StringNull()
	}
}

func (m *CloudIntegrationTemplateAzureModel) RefreshConfiguredPropertyValues(ctx context.Context, diagnostics *diag.Diagnostics, apiResponse cloudOnboardingTypes.IntegrationInstance) {
	ctx = tflog.SetField(ctx, "resource_operation", "RefreshConfiguredPropertyValues")

	var (
		additionalCapabilities basetypes.ObjectValue
		diags                  diag.Diagnostics
		customResourcesTags    = types.SetNull(types.ObjectType{
			AttrTypes: map[string]attr.Type{
				"key":   types.StringType,
				"value": types.StringType,
			},
		})
	)

	additionalCapabilities, diags = types.ObjectValueFrom(ctx, m.AdditionalCapabilities.AttributeTypes(ctx), apiResponse.AdditionalCapabilities)
	diagnostics.Append(diags...)
	if diagnostics.HasError() {
		return
	}

	if !m.CustomResourcesTags.IsNull() {
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

	if m.InstanceName.IsNull() && apiResponse.InstanceName == "" {
		m.InstanceName = types.StringNull()
	} else {
		m.InstanceName = types.StringValue(apiResponse.InstanceName)
	}

	m.AdditionalCapabilities = additionalCapabilities
	m.ScanMode = types.StringValue(apiResponse.Scan.ScanMethod)
	m.Status = types.StringValue(apiResponse.Status)
}
