// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package util

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	sdkErrors "github.com/PaloAltoNetworks/cortex-cloud-go/errors"
	"github.com/hashicorp/terraform-plugin-framework/diag"
)

// FormatAPIError returns a human-readable error message that includes
// per-field validation details when the underlying error is a structured
// CortexCloudAPIError. For non-API errors (or API errors with no details),
// it returns err.Error() unchanged.
//
// This bridges the SDK's structured error type to provider diagnostics so
// HTTP 422 ValidateError responses surface their per-field messages instead
// of being swallowed as a single opaque "Validation Failed" line.
func FormatAPIError(err error) string {
	if err == nil {
		return ""
	}
	var apiErr *sdkErrors.CortexCloudAPIError
	if !errors.As(err, &apiErr) {
		return err.Error()
	}

	sb := strings.Builder{}
	sb.WriteString(err.Error())

	if apiErr.Details != nil && len(apiErr.Details.Fields) > 0 {
		// err.Error() already prints these for the fallback shape, but if the
		// API surface that produced this error doesn't go through the fallback
		// branch (e.g. a wrapping error), make absolutely sure the per-field
		// details are still surfaced to the user.
		formatted := formatFieldDetails(apiErr.Details.Fields)
		if !strings.Contains(sb.String(), formatted) {
			if !strings.HasSuffix(sb.String(), "\n") {
				sb.WriteString("\n")
			}
			sb.WriteString(formatted)
		}
	}
	return sb.String()
}

func formatFieldDetails(fields map[string]sdkErrors.CortexCloudAPIErrorParams) string {
	if len(fields) == 0 {
		return ""
	}
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	sb := strings.Builder{}
	sb.WriteString("Validation details:\n")
	for _, k := range keys {
		sb.WriteString(fmt.Sprintf("  - %s: %s\n", k, fields[k].Message))
	}
	return sb.String()
}

func AddMissingRequiredProviderConfigurationValue(diagnostics *diag.Diagnostics, attributeName, attributeNamePretty, attributeEnvVar string) {
	diagnostics.AddError(
		fmt.Sprintf("%s Is Required", attributeNamePretty),
		fmt.Sprintf("Recieved unknown or empty value for required configuration parameter \"%s\". Either set the value in the provider configuration, or use the %s environment variable.", attributeName, attributeEnvVar),
	)
}

func AddInvalidProviderConfigurationValue(diagnostics *diag.Diagnostics, attributeName, attributeNamePretty, attributeInput string, attributeExpectedValues []string) {
	diagnostics.AddError(
		fmt.Sprintf("Invalid %s", attributeNamePretty),
		fmt.Sprintf("Recieved invalid input for configuration parameter \"%s\": \"%s\". Expected one of: %s", attributeName, attributeInput, strings.Join(attributeExpectedValues, ", ")),
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
