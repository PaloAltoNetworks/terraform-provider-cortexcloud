// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package util

import (
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	//"github.com/hashicorp/terraform-plugin-framework/path"
)

func AddUnexpectedResourceConfigureTypeError(diagnostics *diag.Diagnostics, expectedType, recievedType any) {
	diagnostics.AddError(
		"Unexpected Resource Configure Type",
		fmt.Sprintf("Expected %T, got: %T. Please report this issue to the provider developers.", expectedType, recievedType),
	)
}

//func AddValueConversionAttributeError(diagnostics *diag.Diagnostics, attributePath path.Path) {
//	diagnostics.AddAttributeError(
//		attributePath,
//		"Value Conversion Error",
//		fmt.Sprintf("Expected %T, got: %T. Please report this issue to the provider developers.", expectedType, recievedType),
//	)
//}
