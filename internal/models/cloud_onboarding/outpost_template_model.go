// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package models

import (
	"context"
	"fmt"
	"slices"

	cloudOnboardingTypes "github.com/PaloAltoNetworks/cortex-cloud-go/types/cloudonboarding"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// OutpostTemplateModel is the model for a single outpost object.
type OutpostTemplateModel struct {
	ID                  types.String `tfsdk:"id"`
	CloudProvider       types.String `tfsdk:"cloud_provider"`
	CustomResourcesTags types.Set    `tfsdk:"custom_resources_tags"`
	TerraformModuleURL  types.String `tfsdk:"terraform_module_url"`
}

func (m *OutpostTemplateModel) ToCreateRequest(ctx context.Context, diagnostics *diag.Diagnostics) cloudOnboardingTypes.CreateOutpostTemplateRequest {
	ctx = tflog.SetField(ctx, "resource_operation", "ToCreateRequest")

	var customResourcesTags []cloudOnboardingTypes.Tag
	diagnostics.Append(m.CustomResourcesTags.ElementsAs(ctx, &customResourcesTags, false)...)

	if !slices.Contains(customResourcesTags, defaultIntegrationTemplatePANWTag) {
		customResourcesTags = append(customResourcesTags, defaultIntegrationTemplatePANWTag)
	}

	return cloudOnboardingTypes.NewCreateOutpostTemplateRequest(
		m.CloudProvider.ValueString(),
		cloudOnboardingTypes.WithCustomResourceTags(customResourcesTags),
	)
}

func (m *OutpostTemplateModel) RefreshFromRemote(ctx context.Context, diagnostics *diag.Diagnostics, remote *cloudOnboardingTypes.CreateTemplateOrEditIntegrationInstanceResponse) {
	if remote == nil {
		diagnostics.AddError(
			"Error Refreshing Outpost Template Resource",
			"Received nil API response. Please report this issue to the provider developers.",
		)
		return
	}

	if remote.Manual.TF == nil || *remote.Manual.TF == "" {
		diagnostics.AddError(
			"Error Refreshing Outpost Template Resource",
			"Received nil or empty value for Terraform module URL in API response. Please report this issue to the provider developers.",
		)
		return
	}

	m.TerraformModuleURL = types.StringPointerValue(remote.Manual.TF)

	trackingGUID, err := remote.GetTrackingGUIDFromTerraformURL()
	if err != nil {
		diagnostics.AddError(
			"Error Parsing ID",
			fmt.Sprintf("Failed to parse ID from API response: %s", err.Error()),
		)
	}
	tflog.Debug(context.Background(), fmt.Sprintf("Setting ID (trackingGUID): %s", trackingGUID))
	m.ID = types.StringValue(trackingGUID)
}
