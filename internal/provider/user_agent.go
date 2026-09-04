// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"fmt"
)

// cortexCloudAgentEnvVar is the environment variable that allows users to
// override the User-Agent string sent by the SDK. When set, the provider must
// not override it with its own User-Agent suffix.
const cortexCloudAgentEnvVar = "CORTEXCLOUD_AGENT"

// terraformUserAgentDetail builds the Terraform-specific detail folded into
// the User-Agent on every API call.
//
// Format: terraform/<tfVersion>
//
// The Terraform CLI version is the one fact the server cannot reconstruct
// from the request itself: it is supplied by the CLI to the plugin over
// gRPC and appears nowhere else in the HTTP call.
func terraformUserAgentDetail(terraformVersion string) string {
	if terraformVersion == "" {
		terraformVersion = "unknown"
	}
	return fmt.Sprintf("terraform/%s", terraformVersion)
}
