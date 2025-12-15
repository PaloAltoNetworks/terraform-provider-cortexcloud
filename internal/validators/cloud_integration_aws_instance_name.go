// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package validators

import (
	"context"
	"fmt"
	"regexp"

	"github.com/PaloAltoNetworks/cortex-cloud-go/enums"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
)

func ValidateCloudIntegrationInstanceName() validateCloudIntegrationInstanceName {
	return validateCloudIntegrationInstanceName{}
}

type validateCloudIntegrationInstanceName struct{}

func (v validateCloudIntegrationInstanceName) Description(ctx context.Context) string {
	return ""
}

func (v validateCloudIntegrationInstanceName) MarkdownDescription(ctx context.Context) string {
	return ""
}

func (v validateCloudIntegrationInstanceName) ValidateString(ctx context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}

	var cloudProvider basetypes.StringValue
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("cloud_provider"), &cloudProvider)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if cloudProvider.IsNull() || cloudProvider.IsUnknown() {
		return
	}

	instanceName := req.ConfigValue.ValueString()
	cloudProviderName := cloudProvider.ValueString()

	cloudFormationStackNameRegexp := "^[a-zA-Z][-a-zA-Z0-9]*$"
	isAws := (cloudProviderName == enums.CloudProviderAWS.String())
	isValidStackName, err := regexp.Match(cloudFormationStackNameRegexp, []byte(instanceName))
	if err != nil {
		resp.Diagnostics.AddError(
			"Validation Error",
			fmt.Sprintf("Failed to evaluate regular expression \"%s\" against string value \"%s\"", cloudFormationStackNameRegexp, instanceName),
		)
	}

	if isAws && !isValidStackName {
		resp.Diagnostics.AddAttributeError(
			req.Path,
			"Validation Error",
			fmt.Sprintf("Value must satisfy regex pattern \"%s\" for AWS integrations", cloudFormationStackNameRegexp),
		)
	}
}
