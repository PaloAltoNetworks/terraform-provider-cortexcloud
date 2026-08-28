// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package version

import (
	"runtime"
	"strings"
	"testing"
)

func TestUserAgent(t *testing.T) {
	t.Run("should format User-Agent correctly", func(t *testing.T) {
		ua := UserAgent("platform")

		// Should contain SDK name and version
		if !strings.Contains(ua, "cortex-cloud-go/") {
			t.Errorf("Expected SDK name in User-Agent, got: %s", ua)
		}

		// Should contain module name (without version)
		if !strings.Contains(ua, "(platform;") {
			t.Errorf("Expected module info in User-Agent, got: %s", ua)
		}

		// Should contain Go version
		if !strings.Contains(ua, "go") {
			t.Errorf("Expected Go version in User-Agent, got: %s", ua)
		}

		// Should contain OS and arch
		expectedOS := runtime.GOOS
		expectedArch := runtime.GOARCH
		if !strings.Contains(ua, expectedOS) || !strings.Contains(ua, expectedArch) {
			t.Errorf("Expected OS/arch in User-Agent, got: %s", ua)
		}
	})

	t.Run("should handle custom suffix", func(t *testing.T) {
		ua := UserAgentWithCustom("platform", "terraform-provider/2.1.0")

		if !strings.Contains(ua, "terraform-provider/2.1.0") {
			t.Errorf("Expected custom suffix in User-Agent, got: %s", ua)
		}
	})

	t.Run("should handle empty custom suffix", func(t *testing.T) {
		ua := UserAgentWithCustom("platform", "")
		uaBase := UserAgent("platform")

		if ua != uaBase {
			t.Errorf("Expected same User-Agent when custom is empty, got: %s vs %s", ua, uaBase)
		}
	})

	t.Run("should return info map", func(t *testing.T) {
		info := Info()

		requiredKeys := []string{
			"sdk_version", "sdk_name", "git_commit", "build_date",
			"cortex_server_version", "cortex_papi_version",
			"go_version", "os", "arch",
		}

		for _, key := range requiredKeys {
			if _, ok := info[key]; !ok {
				t.Errorf("Expected key %s in info map", key)
			}
		}
	})

	t.Run("should have correct SDK constants", func(t *testing.T) {
		if SDKName != "cortex-cloud-go" {
			t.Errorf("Expected SDKName to be 'cortex-cloud-go', got: %s", SDKName)
		}

		if SDKVersion == "" {
			t.Error("Expected SDKVersion to be non-empty")
		}
	})
}
