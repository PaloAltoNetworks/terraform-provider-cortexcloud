// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package validators

import (
	"context"
	"fmt"

	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/util"

	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
)

var _ validator.String = ControlLabelTitleCaseValidator{}

// ControlLabelTitleCaseValidator warns when a compliance control category or
// subcategory is not already in the form the API stores it in.
//
// The API accepts any free-text value and normalizes it (whitespace trimmed,
// each word Title Cased). The provider keeps the configured value in state, so
// this is only a nudge to write the stored form; it never fails validation.
type ControlLabelTitleCaseValidator struct{}

// ControlLabelTitleCase returns a validator that emits a warning diagnostic
// when a configured value differs from its API-normalized form.
func ControlLabelTitleCase() validator.String {
	return ControlLabelTitleCaseValidator{}
}

// Description implements validator.Describer.
func (v ControlLabelTitleCaseValidator) Description(_ context.Context) string {
	return "Warns when the value is not in Title Case, the form in which the API stores it."
}

// MarkdownDescription implements validator.Describer.
func (v ControlLabelTitleCaseValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

// ValidateString implements validator.String.
func (v ControlLabelTitleCaseValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}

	value := req.ConfigValue.ValueString()
	if value == "" {
		return
	}

	normalized := util.NormalizeControlLabel(value)
	if normalized == value {
		return
	}

	resp.Diagnostics.AddAttributeWarning(
		req.Path,
		"Value Will Be Normalized By The API",
		fmt.Sprintf(
			"The API stores %q as %q (whitespace trimmed, each word Title Cased). "+
				"Use %q in the configuration to avoid this warning.",
			value, normalized, normalized,
		),
	)
}
