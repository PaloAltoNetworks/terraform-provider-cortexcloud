// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package util

import (
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/diag"
)

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
