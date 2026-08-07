// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package platform

import (
	"errors"
	"strings"
	"testing"
)

// TestEnrichScopeError verifies the dataset-SBAC coupling errors get an
// actionable hint appended, and that unrelated errors pass through unchanged.
func TestEnrichScopeError(t *testing.T) {
	tests := []struct {
		name        string
		err         error
		wantHint    bool
		wantContain string
	}{
		{
			name:        "nil error",
			err:         nil,
			wantHint:    false,
			wantContain: "",
		},
		{
			name:        "SBAC disabled (please remove)",
			err:         errors.New("Datasets SBAC scope configuration is not enabled. Please remove datasets_rows section"),
			wantHint:    true,
			wantContain: "Remove the `datasets_rows` block",
		},
		{
			name:        "SBAC enabled (please add)",
			err:         errors.New("Datasets SBAC scope configuration is enabled. Please add datasets_rows section"),
			wantHint:    true,
			wantContain: "Add a `datasets_rows` block",
		},
		{
			name:        "unrelated error passes through",
			err:         errors.New("Group not found"),
			wantHint:    false,
			wantContain: "Group not found",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := enrichScopeError(tc.err)
			if tc.err == nil {
				if got != "" {
					t.Fatalf("expected empty string for nil error, got %q", got)
				}
				return
			}
			if !strings.Contains(got, tc.err.Error()) {
				t.Fatalf("enriched message must preserve the original error; got %q", got)
			}
			hintPresent := strings.Contains(got, "Hint:")
			if hintPresent != tc.wantHint {
				t.Fatalf("wantHint=%v but got hintPresent=%v (msg=%q)", tc.wantHint, hintPresent, got)
			}
			if tc.wantContain != "" && !strings.Contains(got, tc.wantContain) {
				t.Fatalf("expected message to contain %q, got %q", tc.wantContain, got)
			}
		})
	}
}
