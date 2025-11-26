// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package util

import (
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/diag"
)

func AddMissingRequiredProviderConfigurationValue(diagnostics *diag.Diagnostics, attributeName, attributeNamePretty, attributeEnvVar string) {
	diagnostics.AddError(
		fmt.Sprintf("%s Is Required", attributeNamePretty),
		fmt.Sprintf("Recieved unknown or empty value for required configuration parameter \"%s\". Either set the value in the provider configuration, or use the %s environment variable.", attributeName, attributeEnvVar),
	)
}

func AddUnexpectedResourceConfigurationTypeError(diagnostics *diag.Diagnostics, expectedType, receivedType any) {
	diagnostics.AddError(
		"Unexpected Resource Configuration Type",
		fmt.Sprintf("Expected %T, got: %T. Please report this issue to the provider developers.", expectedType, receivedType),
	)
}

func AddUnexpectedDataSourceConfigurationTypeError(diagnostics *diag.Diagnostics, expectedType, receivedType any) {
	diagnostics.AddError(
		"Unexpected Data Source Configuration Type",
		fmt.Sprintf("Expected %T, got: %T. Please report this issue to the provider developers.", expectedType, receivedType),
	)
}

func AddUnexpectedEphemeralResourceConfigurationTypeError(diagnostics *diag.Diagnostics, expectedType, receivedType any) {
	diagnostics.AddError(
		"Unexpected Ephemeral Resource Configuration Type",
		fmt.Sprintf("Expected %T, got: %T. Please report this issue to the provider developers.", expectedType, receivedType),
	)
}
