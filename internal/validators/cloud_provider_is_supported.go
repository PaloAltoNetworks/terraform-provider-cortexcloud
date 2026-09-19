// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package validators

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
)

var _ validator.String = CloudProviderIsSupportedValidator{}

// CloudProviderIsSupportedValidator reports an error when a cloud provider is
// valid for the platform as a whole but not for the feature being configured.
//
// This is not a substitute for stringvalidator.OneOf. OneOf answers "is this a
// cloud provider?"; this answers "does this feature support that cloud
// provider yet?". The distinction matters in the diagnostic: a practitioner who
// writes a provider the platform plainly supports elsewhere needs to be told
// the capability is missing, not handed a list that makes their input look
// like a typo.
type CloudProviderIsSupportedValidator struct {
	Supported   []string
	Unsupported []string
	Feature     string
}

// CloudProviderIsSupported returns a validator that accepts only the given
// cloud providers, naming the unsupported ones in its diagnostic.
func CloudProviderIsSupported(feature string, supported []string, unsupported []string) validator.String {
	return CloudProviderIsSupportedValidator{
		Supported:   supported,
		Unsupported: unsupported,
		Feature:     feature,
	}
}

func (v CloudProviderIsSupportedValidator) MarkdownDescription(ctx context.Context) string {
	return fmt.Sprintf("must be one of: %s", strings.Join(v.Supported, ", "))
}

func (v CloudProviderIsSupportedValidator) Description(ctx context.Context) string {
	return v.MarkdownDescription(ctx)
}

// ValidateString refuses any value outside the supported set.
//
// Unknown and null values are left alone: the framework re-runs validation once
// an unknown is resolved, and a missing required attribute is already reported
// by the framework itself.
func (v CloudProviderIsSupportedValidator) ValidateString(
	ctx context.Context,
	req validator.StringRequest,
	resp *validator.StringResponse,
) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}

	value := req.ConfigValue.ValueString()
	if slices.Contains(v.Supported, value) {
		return
	}

	// A provider the platform knows but this feature does not yet implement is
	// a capability gap, and saying so prevents it being read as a typo or as a
	// provider defect.
	if slices.Contains(v.Unsupported, value) {
		resp.Diagnostics.AddAttributeError(
			req.Path,
			fmt.Sprintf("Unsupported Cloud Provider for %s", v.Feature),
			fmt.Sprintf("%q is not supported for %s. Supported cloud providers are %s. "+
				"This is a platform limitation rather than a configuration error: "+
				"the %s API does not accept %s connectors, so Terraform refuses the "+
				"value here instead of failing during apply.",
				value,
				v.Feature,
				strings.Join(v.Supported, " and "),
				v.Feature,
				value,
			),
		)

		return
	}

	resp.Diagnostics.AddAttributeError(
		req.Path,
		"Invalid Cloud Provider",
		fmt.Sprintf("%q is not a valid cloud provider for %s. Supported cloud providers are %s.",
			value,
			v.Feature,
			strings.Join(v.Supported, " and "),
		),
	)
}
