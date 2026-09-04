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
		ua := UserAgent()

		expected := "terraform-provider-cortexcloud/" + ProductVersion +
			" (" + runtime.GOOS + "/" + runtime.GOARCH + ")"
		if ua != expected {
			t.Errorf("Expected %q, got %q", expected, ua)
		}
	})

	t.Run("should not carry retired tokens", func(t *testing.T) {
		ua := UserAgent()

		// The SDK is absorbed into the provider; its old identity must not persist.
		if strings.Contains(ua, "cortex-cloud-go") {
			t.Errorf("Retired SDK token present in %q", ua)
		}
		// The API module is derivable from the request path, so it is not repeated here.
		if strings.Contains(ua, "(platform;") {
			t.Errorf("Redundant module token present in %q", ua)
		}
		// The Go runtime version was dropped as non-actionable.
		if strings.Contains(ua, "go"+strings.TrimPrefix(runtime.Version(), "go")) {
			t.Errorf("Retired go version token present in %q", ua)
		}
	})

	t.Run("should fold custom detail into the detail section", func(t *testing.T) {
		ua := UserAgentWithCustom("terraform/1.9.5")

		expected := "terraform-provider-cortexcloud/" + ProductVersion +
			" (terraform/1.9.5; " + runtime.GOOS + "/" + runtime.GOARCH + ")"
		if ua != expected {
			t.Errorf("Expected %q, got %q", expected, ua)
		}
	})

	t.Run("should emit exactly one product token", func(t *testing.T) {
		ua := UserAgentWithCustom("terraform/1.9.5")

		if n := strings.Count(ua, ProductName); n != 1 {
			t.Errorf("Expected product name exactly once, found %d times in %q", n, ua)
		}
	})

	t.Run("should handle empty custom detail", func(t *testing.T) {
		ua := UserAgentWithCustom("")
		uaBase := UserAgent()

		if ua != uaBase {
			t.Errorf("Expected same User-Agent when custom is empty, got: %s vs %s", ua, uaBase)
		}
	})

	t.Run("should return info map", func(t *testing.T) {
		info := Info()

		requiredKeys := []string{
			"product_version", "product_name", "git_commit", "build_date",
			"cortex_server_version", "cortex_papi_version",
			"go_version", "os", "arch",
		}

		for _, key := range requiredKeys {
			if _, ok := info[key]; !ok {
				t.Errorf("Expected key %s in info map", key)
			}
		}
	})

	t.Run("should have correct product constants", func(t *testing.T) {
		if ProductName != "terraform-provider-cortexcloud" {
			t.Errorf("Expected ProductName to be 'terraform-provider-cortexcloud', got: %s", ProductName)
		}

		if ProductVersion == "" {
			t.Error("Expected ProductVersion to be non-empty")
		}
	})
}
