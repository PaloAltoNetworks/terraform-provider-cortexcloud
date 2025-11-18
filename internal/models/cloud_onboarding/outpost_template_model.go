// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package models

import (
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// OutpostTemplateAwsModel is the model for a single outpost object.
type OutpostTemplateAwsModel struct {
	CustomResourcesTags       types.Set    `tfsdk:"custom_resources_tags"`
	TerraformModuleURL       types.String `tfsdk:"terraform_module_url"`
}
