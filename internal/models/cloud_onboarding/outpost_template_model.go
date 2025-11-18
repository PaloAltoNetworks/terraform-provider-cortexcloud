// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package models

import (
	"context"
	"slices"

	cloudOnboardingTypes "github.com/PaloAltoNetworks/cortex-cloud-go/types/cloudonboarding"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// OutpostTemplateModel is the model for a single outpost object.
type OutpostTemplateModel struct {
	CloudProvider types.String `tfsdk:"cloud_provider"`
	CustomResourcesTags       types.Set    `tfsdk:"custom_resources_tags"`
	TerraformModuleURL       types.String `tfsdk:"terraform_module_url"`
}

func (m *OutpostTemplateModel) ToCreateRequest(ctx context.Context, diagnostics *diag.Diagnostics) *cloudOnboardingTypes.CreateOutpostTemplateRequest {
	ctx = tflog.SetField(ctx, "resource_operation", "ToCreateRequest")

	var customResourcesTags []cloudOnboardingTypes.Tag
	diagnostics.Append(m.CustomResourcesTags.ElementsAs(ctx, &customResourcesTags, false)...)
	
	if !slices.Contains(customResourcesTags, managedByPANWTag) {
		customResourcesTags = append(customResourcesTags, managedByPANWTag)
	}

	return cloudOnboardingTypes.NewCreateOutpostTemplateRequest(
		m.CloudProvider.ValueString(),
		cloudOnboardingTypes.WithCustomResourceTags(customResourcesTags),
	)
}
