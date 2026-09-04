// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package version

import (
	"fmt"
	"runtime"
)

const (
	// ProductName is the canonical product name reported in the User-Agent.
	ProductName = "terraform-provider-cortexcloud"
)

var (
	// ProductVersion is the released provider version, injected at build time
	// via ldflags. Defaults to "dev" for non-release builds.
	ProductVersion = "dev"

	// GitCommit is the git commit hash (set via ldflags)
	GitCommit = "dev"

	// BuildDate is the build timestamp (set via ldflags)
	BuildDate = "unknown"

	// CortexServerVersion is the target Cortex server version (set via ldflags)
	CortexServerVersion = "unknown"

	// CortexPAPIVersion is the target PAPI version (set via ldflags)
	CortexPAPIVersion = "unknown"
)

// UserAgent returns the base User-Agent string.
//
// Format: terraform-provider-cortexcloud/<version> (<os>/<arch>)
//
// The API module is deliberately omitted: the request path already identifies
// it (e.g. public_api/appsec/v1/policies), so repeating it here adds no
// information the server cannot already derive.
func UserAgent() string {
	return fmt.Sprintf("%s/%s (%s/%s)",
		ProductName, ProductVersion, runtime.GOOS, runtime.GOARCH)
}

// UserAgentWithCustom returns the User-Agent with a custom suffix folded into
// the detail section.
//
// Format: terraform-provider-cortexcloud/<version> (<custom>; <os>/<arch>)
func UserAgentWithCustom(custom string) string {
	if custom == "" {
		return UserAgent()
	}
	return fmt.Sprintf("%s/%s (%s; %s/%s)",
		ProductName, ProductVersion, custom, runtime.GOOS, runtime.GOARCH)
}

// Info returns version information as a map.
func Info() map[string]string {
	return map[string]string{
		"product_name":          ProductName,
		"product_version":       ProductVersion,
		"git_commit":            GitCommit,
		"build_date":            BuildDate,
		"cortex_server_version": CortexServerVersion,
		"cortex_papi_version":   CortexPAPIVersion,
		"go_version":            runtime.Version(),
		"os":                    runtime.GOOS,
		"arch":                  runtime.GOARCH,
	}
}
