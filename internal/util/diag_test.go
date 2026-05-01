// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package util

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	sdkErrors "github.com/PaloAltoNetworks/cortex-cloud-go/errors"
)

// TestFormatAPIError_PerFieldDetails synthesises a 422 response that mirrors
// the AppSec policy CREATE/UPDATE failure mode where the API rejects missing
// trigger keys. The formatted error must surface every per-field message so
// the user can see exactly which fields the API complained about — instead
// of an opaque "Validation Failed" line.
func TestFormatAPIError_PerFieldDetails(t *testing.T) {
	jsonBody := `{
		"errorCode": "ValidateError",
		"message": "Validation Failed",
		"details": {
			"policy.triggers.ciImage":       { "message": "'ciImage' is required" },
			"policy.triggers.imageRegistry": { "message": "'imageRegistry' is required" }
		}
	}`

	var apiErr sdkErrors.CortexCloudAPIError
	if err := json.Unmarshal([]byte(jsonBody), &apiErr); err != nil {
		t.Fatalf("setup: failed to unmarshal API error: %v", err)
	}

	formatted := FormatAPIError(&apiErr)

	wantSubstrings := []string{
		"ValidateError",
		"Validation Failed",
		"policy.triggers.ciImage",
		"'ciImage' is required",
		"policy.triggers.imageRegistry",
		"'imageRegistry' is required",
	}
	for _, want := range wantSubstrings {
		if !strings.Contains(formatted, want) {
			t.Errorf("FormatAPIError output missing %q in:\n%s", want, formatted)
		}
	}
}

// TestFormatAPIError_NonAPIError verifies that non-API errors pass through
// unchanged.
func TestFormatAPIError_NonAPIError(t *testing.T) {
	err := errors.New("something went wrong")
	got := FormatAPIError(err)
	if got != "something went wrong" {
		t.Errorf("expected pass-through, got %q", got)
	}
}

// TestFormatAPIError_NilError returns empty string.
func TestFormatAPIError_NilError(t *testing.T) {
	if got := FormatAPIError(nil); got != "" {
		t.Errorf("expected empty string for nil error, got %q", got)
	}
}
