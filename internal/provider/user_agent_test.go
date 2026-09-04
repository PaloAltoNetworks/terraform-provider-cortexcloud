// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"

	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/platform"
	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/version"
	"github.com/stretchr/testify/require"
)

func TestTerraformUserAgentDetail(t *testing.T) {
	t.Run("should format the terraform CLI version", func(t *testing.T) {
		detail := terraformUserAgentDetail("1.9.5")

		if detail != "terraform/1.9.5" {
			t.Errorf("Expected %q, got %q", "terraform/1.9.5", detail)
		}
	})

	t.Run("should handle prerelease version strings", func(t *testing.T) {
		detail := terraformUserAgentDetail("1.10.0-beta1")

		if detail != "terraform/1.10.0-beta1" {
			t.Errorf("Expected %q, got %q", "terraform/1.10.0-beta1", detail)
		}
	})

	t.Run("should default empty terraform version to unknown", func(t *testing.T) {
		detail := terraformUserAgentDetail("")

		if detail != "terraform/unknown" {
			t.Errorf("Expected %q, got %q", "terraform/unknown", detail)
		}
	})
}

func TestFullUserAgentComposition(t *testing.T) {
	t.Run("should produce a single product token with terraform detail", func(t *testing.T) {
		detail := terraformUserAgentDetail("1.9.5")
		fullUA := version.UserAgentWithCustom(detail)

		expected := "terraform-provider-cortexcloud/" + version.ProductVersion +
			" (terraform/1.9.5; " + runtime.GOOS + "/" + runtime.GOARCH + ")"
		if fullUA != expected {
			t.Errorf("Expected %q, got %q", expected, fullUA)
		}
	})

	t.Run("should not repeat the product token", func(t *testing.T) {
		fullUA := version.UserAgentWithCustom(terraformUserAgentDetail("1.9.5"))

		if n := strings.Count(fullUA, version.ProductName); n != 1 {
			t.Errorf("Expected product name exactly once, found %d times in %q", n, fullUA)
		}
	})

	t.Run("should not carry the retired SDK or module tokens", func(t *testing.T) {
		fullUA := version.UserAgentWithCustom(terraformUserAgentDetail("1.9.5"))

		if strings.Contains(fullUA, "cortex-cloud-go") {
			t.Errorf("Retired SDK token present in %q", fullUA)
		}
		if strings.Contains(fullUA, "(platform;") {
			t.Errorf("Redundant module token present in %q", fullUA)
		}
		if strings.Contains(fullUA, "go"+strings.TrimPrefix(runtime.Version(), "go")) {
			t.Errorf("Retired go version token present in %q", fullUA)
		}
	})
}

func TestUserAgentHeaderOnWire(t *testing.T) {
	var capturedUA string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedUA = r.Header.Get("User-Agent")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	detail := terraformUserAgentDetail("1.9.5")
	client, err := platform.NewClient(
		platform.WithCortexAPIURL(srv.URL),
		platform.WithCortexAPIKey("dummy"),
		platform.WithCortexAPIKeyID(1),
		platform.WithCortexAPIKeyType("standard"),
		platform.WithAgent(version.UserAgentWithCustom(detail)),
	)
	require.NoError(t, err)

	_, _ = client.ValidateAPIKey(context.Background())

	require.Contains(t, capturedUA, "terraform-provider-cortexcloud/")
	require.Contains(t, capturedUA, "terraform/1.9.5")
	require.NotContains(t, capturedUA, "cortex-cloud-go")
	require.Equal(t, 1, strings.Count(capturedUA, version.ProductName),
		"product token must appear exactly once: %q", capturedUA)
}
