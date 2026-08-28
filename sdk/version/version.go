// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package version

import (
	"fmt"
	"runtime"
)

const (
	// SDKVersion is the semantic version of the SDK
	SDKVersion = "1.0.0"

	// SDKName is the canonical name of the SDK
	SDKName = "cortex-cloud-go"
)

var (
	// GitCommit is the git commit hash (set via ldflags)
	GitCommit = "dev"

	// BuildDate is the build timestamp (set via ldflags)
	BuildDate = "unknown"

	// CortexServerVersion is the target Cortex server version
	CortexServerVersion = "unknown"

	// CortexPAPIVersion is the target PAPI version
	CortexPAPIVersion = "unknown"
)

// UserAgent returns a formatted User-Agent string
// Format: cortex-cloud-go/<sdk-version> (<module>; go<go-version>; <os>/<arch>)
func UserAgent(module string) string {
	goVersion := runtime.Version()
	if len(goVersion) > 2 && goVersion[:2] == "go" {
		goVersion = goVersion[2:] // Remove "go" prefix
	}

	return fmt.Sprintf("%s/%s (%s; go%s; %s/%s)",
		SDKName,
		SDKVersion,
		module,
		goVersion,
		runtime.GOOS,
		runtime.GOARCH,
	)
}

// UserAgentWithCustom returns a User-Agent with custom suffix
func UserAgentWithCustom(module, custom string) string {
	base := UserAgent(module)
	if custom != "" {
		return fmt.Sprintf("%s %s", base, custom)
	}
	return base
}

// Info returns version information as a map
func Info() map[string]string {
	return map[string]string{
		"sdk_version":           SDKVersion,
		"sdk_name":              SDKName,
		"git_commit":            GitCommit,
		"build_date":            BuildDate,
		"cortex_server_version": CortexServerVersion,
		"cortex_papi_version":   CortexPAPIVersion,
		"go_version":            runtime.Version(),
		"os":                    runtime.GOOS,
		"arch":                  runtime.GOARCH,
	}
}
