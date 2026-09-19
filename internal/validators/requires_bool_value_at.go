// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package validators

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework-validators/helpers/validatordiag"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ validator.String = RequiresBoolValueAtValidator{}
	_ validator.Object = RequiresBoolValueAtValidator{}
)

// RequiresBoolValueAtValidator reports an error when the attribute it is
// applied to is configured while a boolean attribute elsewhere in the
// configuration does not hold the required value.
//
// This is the companion of AlsoRequiresOnBoolValue and not a duplicate of it.
// AlsoRequiresOnBoolValue asks whether a companion attribute is present;
// this asks what a companion toggle is set to. An API that enables a feature
// with a toggle and configures it with a separate option set needs both
// directions to describe its rule: the toggle requires the options, and the
// options require the toggle to be switched on. Presence alone cannot express
// the second half, because a toggle explicitly set to false is present.
//
// A null companion counts as not holding the required value. An attribute the
// practitioner never wrote is not switched on, and the platforms this guards
// treat an omitted toggle exactly as they treat a disabled one.
type RequiresBoolValueAtValidator struct {
	ExpectedValue   bool
	PathExpressions path.Expressions
}

// RequiresBoolValueAt returns a validator for string attributes that may only
// be configured when the boolean attributes at the given paths hold
// expectedValue.
func RequiresBoolValueAt(expectedValue bool, expressions ...path.Expression) validator.String {
	return RequiresBoolValueAtValidator{
		ExpectedValue:   expectedValue,
		PathExpressions: expressions,
	}
}

// RequiresBoolValueAtObject returns the same validator for object attributes.
func RequiresBoolValueAtObject(expectedValue bool, expressions ...path.Expression) validator.Object {
	return RequiresBoolValueAtValidator{
		ExpectedValue:   expectedValue,
		PathExpressions: expressions,
	}
}

func (v RequiresBoolValueAtValidator) MarkdownDescription(ctx context.Context) string {
	return fmt.Sprintf("may only be configured when %s is %t", v.PathExpressions, v.ExpectedValue)
}

func (v RequiresBoolValueAtValidator) Description(ctx context.Context) string {
	return v.MarkdownDescription(ctx)
}

// validate resolves each companion path and reports the ones that do not hold
// the required value.
func (v RequiresBoolValueAtValidator) validate(
	ctx context.Context,
	config tfsdk.Config,
	configValue attr.Value,
	attributePath path.Path,
	pathExpression path.Expression,
	diagnostics *diag.Diagnostics,
) {
	// An attribute that is not configured cannot conflict with anything.
	if configValue.IsNull() || configValue.IsUnknown() {
		return
	}

	expressions := pathExpression.MergeExpressions(v.PathExpressions...)

	for _, expression := range expressions {
		matchedPaths, diags := config.PathMatches(ctx, expression)

		diagnostics.Append(diags...)

		// Collect every error rather than stopping at the first.
		if diags.HasError() {
			continue
		}

		for _, matchedPath := range matchedPaths {
			// Skip the attribute this validator is applied to.
			if matchedPath.Equal(attributePath) {
				continue
			}

			var matchedValue attr.Value

			diags := config.GetAttribute(ctx, matchedPath, &matchedValue)
			diagnostics.Append(diags...)

			if diags.HasError() {
				continue
			}

			// Defer until the companion has a known value. Validation runs
			// again once it does.
			if matchedValue.IsUnknown() {
				return
			}

			boolValue, ok := matchedValue.(types.Bool)
			if ok == false {
				diagnostics.Append(validatordiag.InvalidAttributeCombinationDiagnostic(
					attributePath,
					fmt.Sprintf("The %q attribute is not a boolean, so %q cannot be validated against it", matchedPath, attributePath),
				))

				continue
			}

			// A companion the practitioner never wrote is not switched on.
			if boolValue.IsNull() || boolValue.ValueBool() != v.ExpectedValue {
				diagnostics.Append(validatordiag.InvalidAttributeCombinationDiagnostic(
					attributePath,
					fmt.Sprintf(
						"The %q attribute may only be configured when the %q attribute is %t.",
						attributePath, matchedPath, v.ExpectedValue,
					),
				))
			}
		}
	}
}

// ValidateString implements validator.String.
func (v RequiresBoolValueAtValidator) ValidateString(ctx context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	v.validate(ctx, req.Config, req.ConfigValue, req.Path, req.PathExpression, &resp.Diagnostics)
}

// ValidateObject implements validator.Object.
func (v RequiresBoolValueAtValidator) ValidateObject(ctx context.Context, req validator.ObjectRequest, resp *validator.ObjectResponse) {
	v.validate(ctx, req.Config, req.ConfigValue, req.Path, req.PathExpression, &resp.Diagnostics)
}
