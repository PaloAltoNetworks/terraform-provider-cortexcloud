// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"fmt"
	"runtime"
)

// cortexCloudAgentEnvVar is the environment variable that allows users to
// override the User-Agent string sent by the SDK. When set, the provider must
// not override it with its own User-Agent suffix.
const cortexCloudAgentEnvVar = "CORTEXCLOUD_AGENT"

// appendTerraformUserAgentSuffix builds the Terraform-specific User-Agent suffix
// appended to the SDK's base User-Agent string on every API call.
//
// Format: terraform-provider-cortexcloud/<providerVersion> (terraform/<tfVersion>; <os>_<arch>)
//
// Example: terraform-provider-cortexcloud/0.7.0 (terraform/1.9.5; linux_amd64)
//
// Note: <os>_<arch> reflects the provider plugin binary's runtime, not the
// Terraform CLI host. These are usually identical, but can differ when
// running under remote operators (Terraform Cloud, Spacelift, etc.) where
// the provider binary is downloaded for a target arch independent of the
// orchestrator's arch.
func appendTerraformUserAgentSuffix(providerVersion, terraformVersion string) string {
	if providerVersion == "" {
		providerVersion = "unknown"
	}
	if terraformVersion == "" {
		terraformVersion = "unknown"
	}
	return fmt.Sprintf("terraform-provider-cortexcloud/%s (terraform/%s; %s_%s)",
		providerVersion, terraformVersion, runtime.GOOS, runtime.GOARCH)
}
