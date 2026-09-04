// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package version

import (
	"testing"
)

// TestVersionInfo verifies that version information can be set via ldflags
func TestVersionInfo(t *testing.T) {
	t.Run("should have default values when not built with ldflags", func(t *testing.T) {
		// When running tests without ldflags, we expect default values
		if GitCommit == "" {
			t.Error("GitCommit should have a default value")
		}
		if BuildDate == "" {
			t.Error("BuildDate should have a default value")
		}
	})

	t.Run("should include version info in Info map", func(t *testing.T) {
		info := Info()

		if info["git_commit"] == "" {
			t.Error("Info map should include git_commit")
		}
		if info["build_date"] == "" {
			t.Error("Info map should include build_date")
		}
		if info["cortex_server_version"] == "" {
			t.Error("Info map should include cortex_server_version")
		}
		if info["cortex_papi_version"] == "" {
			t.Error("Info map should include cortex_papi_version")
		}
	})
}
