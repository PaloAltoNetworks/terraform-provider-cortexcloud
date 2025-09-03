// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package validators

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/helpers/validatordiag"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
)

var (
	_ validator.String = AlsoRequiresOnValuesValidator{}
	_ validator.Bool   = AlsoRequiresOnValuesValidator{}
	//_ validator.Int32
)

type AlsoRequiresOnValuesValidator struct {
	OnStringValues  []string
	OnBoolValues    []bool
	PathExpressions path.Expressions
}

type AlsoRequiresOnValuesValidatorRequest struct {
	Config         tfsdk.Config
	ConfigValue    attr.Value
	Path           path.Path
	PathExpression path.Expression
	ValuesMessage  string
}

type AlsoRequiresOnValuesValidatorResponse struct {
	Diagnostics diag.Diagnostics
}

func AlsoRequiresOnStringValues(onValues []string, expressions ...path.Expression) validator.String {
	return AlsoRequiresOnValuesValidator{
		OnStringValues:  onValues,
		PathExpressions: expressions,
	}
}

func AlsoRequiresOnBoolValues(onValues []bool, expressions ...path.Expression) validator.Bool {
	return AlsoRequiresOnValuesValidator{
		OnBoolValues:    onValues,
		PathExpressions: expressions,
	}
}

func (v AlsoRequiresOnValuesValidator) MarkdownDescription(ctx context.Context) string {
	return "TODO"
}

func (v AlsoRequiresOnValuesValidator) Description(ctx context.Context) string {
	return v.MarkdownDescription(ctx)
}

func (v AlsoRequiresOnValuesValidator) Validate(ctx context.Context, req AlsoRequiresOnValuesValidatorRequest, resp *AlsoRequiresOnValuesValidatorResponse) {
	if req.ConfigValue.IsNull() {
		return
	}

	expressions := req.PathExpression.MergeExpressions(v.PathExpressions...)

	for _, expression := range expressions {
		matchedPaths, diags := req.Config.PathMatches(ctx, expression)

		resp.Diagnostics.Append(diags...)

		// Collect all errors
		if diags.HasError() {
			continue
		}

		for _, mp := range matchedPaths {
			// If the user specifies the same attribute this validator is applied to,
			// also as part of the input, skip it
			if mp.Equal(req.Path) {
				continue
			}

			var mpVal attr.Value
			diags := req.Config.GetAttribute(ctx, mp, &mpVal)
			resp.Diagnostics.Append(diags...)

			// Collect all errors
			if diags.HasError() {
				continue
			}

			// Delay validation until all involved attribute have a known value
			if mpVal.IsUnknown() {
				return
			}

			if mpVal.IsNull() {
				resp.Diagnostics.Append(validatordiag.InvalidAttributeCombinationDiagnostic(
					req.Path,
					fmt.Sprintf("Attribute %q must be specified when %q is specified with values [ %s ]", mp, req.Path, req.ValuesMessage),
				))
			}
		}
	}
}

// ValidateString implements validator.String.
func (v AlsoRequiresOnValuesValidator) ValidateString(ctx context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	// If attribute configuration is null, there is nothing else to validate
	if req.ConfigValue.IsNull() {
		return
	}

	valueMessageArr := []string{}
	for _, stringValue := range v.OnStringValues {
		valueMessageArr = append(valueMessageArr, fmt.Sprintf("`%s`", stringValue))
	}

	for _, value := range v.OnStringValues {
		if value == req.ConfigValue.ValueString() {
			validateReq := AlsoRequiresOnValuesValidatorRequest{
				Config:         req.Config,
				ConfigValue:    req.ConfigValue,
				Path:           req.Path,
				PathExpression: req.PathExpression,
				ValuesMessage:  strings.Join(valueMessageArr, ", "),
			}
			validateResp := &AlsoRequiresOnValuesValidatorResponse{}

			v.Validate(ctx, validateReq, validateResp)
			resp.Diagnostics.Append(validateResp.Diagnostics...)
			return
		}
	}
}

// ValidateBool implements validator.Bool.
func (v AlsoRequiresOnValuesValidator) ValidateBool(ctx context.Context, req validator.BoolRequest, resp *validator.BoolResponse) {
	// If attribute configuration is null, there is nothing else to validate
	if req.ConfigValue.IsNull() {
		return
	}

	valueMessageArr := []string{}
	for _, boolValue := range v.OnBoolValues {
		valueMessageArr = append(valueMessageArr, fmt.Sprintf("`%t`", boolValue))
	}

	for _, value := range v.OnBoolValues {
		if value == req.ConfigValue.ValueBool() {
			validateReq := AlsoRequiresOnValuesValidatorRequest{
				Config:         req.Config,
				ConfigValue:    req.ConfigValue,
				Path:           req.Path,
				PathExpression: req.PathExpression,
				ValuesMessage:  strings.Join(valueMessageArr, ", "),
			}
			validateResp := &AlsoRequiresOnValuesValidatorResponse{}

			v.Validate(ctx, validateReq, validateResp)
			resp.Diagnostics.Append(validateResp.Diagnostics...)
			return
		}
	}
}
