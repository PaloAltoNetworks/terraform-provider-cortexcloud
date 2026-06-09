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

	"github.com/PaloAltoNetworks/cortex-cloud-go/platform"
	"github.com/PaloAltoNetworks/cortex-cloud-go/version"
	"github.com/stretchr/testify/require"
)

func TestAppendTerraformUserAgentSuffix(t *testing.T) {
	t.Run("should format suffix with provider and terraform versions", func(t *testing.T) {
		suffix := appendTerraformUserAgentSuffix("0.7.0", "1.9.5")

		expected := "terraform-provider-cortexcloud/0.7.0 (terraform/1.9.5; " + runtime.GOOS + "_" + runtime.GOARCH + ")"
		if suffix != expected {
			t.Errorf("Expected %q, got %q", expected, suffix)
		}
	})

	t.Run("should handle dev version strings", func(t *testing.T) {
		suffix := appendTerraformUserAgentSuffix("dev", "1.10.0-beta1")

		if !strings.HasPrefix(suffix, "terraform-provider-cortexcloud/dev") {
			t.Errorf("Expected prefix 'terraform-provider-cortexcloud/dev', got %q", suffix)
		}
		if !strings.Contains(suffix, "terraform/1.10.0-beta1") {
			t.Errorf("Expected terraform version in suffix, got %q", suffix)
		}
	})

	t.Run("should produce valid full User-Agent when combined with SDK", func(t *testing.T) {
		suffix := appendTerraformUserAgentSuffix("0.7.0", "1.9.5")
		fullUA := version.UserAgentWithCustom("platform", suffix)

		// Must contain the SDK base
		if !strings.Contains(fullUA, "cortex-cloud-go/") {
			t.Errorf("Expected SDK name in full User-Agent, got %q", fullUA)
		}
		if !strings.Contains(fullUA, "(platform;") {
			t.Errorf("Expected module name in full User-Agent, got %q", fullUA)
		}

		// Must contain the Terraform suffix
		if !strings.Contains(fullUA, "terraform-provider-cortexcloud/0.7.0") {
			t.Errorf("Expected provider version in full User-Agent, got %q", fullUA)
		}
		if !strings.Contains(fullUA, "terraform/1.9.5") {
			t.Errorf("Expected terraform CLI version in full User-Agent, got %q", fullUA)
		}

		// Must have exactly two space-separated product tokens
		parts := strings.SplitN(fullUA, " terraform-provider-cortexcloud/", 2)
		if len(parts) != 2 {
			t.Errorf("Expected two product tokens separated by space, got %q", fullUA)
		}
	})

	t.Run("should default empty provider version to unknown", func(t *testing.T) {
		suffix := appendTerraformUserAgentSuffix("", "1.9.5")

		if !strings.Contains(suffix, "terraform-provider-cortexcloud/unknown") {
			t.Errorf("Expected 'unknown' for empty provider version, got %q", suffix)
		}
	})

	t.Run("should default empty terraform version to unknown", func(t *testing.T) {
		suffix := appendTerraformUserAgentSuffix("0.7.0", "")

		if !strings.Contains(suffix, "terraform/unknown") {
			t.Errorf("Expected 'unknown' for empty terraform version, got %q", suffix)
		}
	})

	t.Run("should default both empty versions to unknown", func(t *testing.T) {
		suffix := appendTerraformUserAgentSuffix("", "")

		if !strings.Contains(suffix, "terraform-provider-cortexcloud/unknown") {
			t.Errorf("Expected 'unknown' for empty provider version, got %q", suffix)
		}
		if !strings.Contains(suffix, "terraform/unknown") {
			t.Errorf("Expected 'unknown' for empty terraform version, got %q", suffix)
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

	suffix := appendTerraformUserAgentSuffix("0.7.0", "1.9.5")
	client, err := platform.NewClient(
		platform.WithCortexAPIURL(srv.URL),
		platform.WithCortexAPIKey("dummy"),
		platform.WithCortexAPIKeyID(1),
		platform.WithCortexAPIKeyType("standard"),
		platform.WithAgent(version.UserAgentWithCustom(platform.ModuleName, suffix)),
	)
	require.NoError(t, err)

	_, _ = client.ValidateAPIKey(context.Background())

	require.Contains(t, capturedUA, "cortex-cloud-go/")
	require.Contains(t, capturedUA, "(platform;")
	require.Contains(t, capturedUA, "terraform-provider-cortexcloud/0.7.0")
	require.Contains(t, capturedUA, "terraform/1.9.5")
}
