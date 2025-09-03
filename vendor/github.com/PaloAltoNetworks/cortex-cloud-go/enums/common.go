// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package enums

// ==============================================================================
// ModuleEnums
// ==============================================================================

// Module represents the API module types.
type Module string

const (
	ModuleAppSec          Module = "APPSEC"
	ModuleCloudOnboarding Module = "CLOUDONBOARDING"
)

// allModules holds all valid Module values.
var allModules = []Module{
	ModuleAppSec,
	ModuleCloudOnboarding,
}

// String returns the string representation of a Module.
func (s Module) String() string {
	return string(s)
}

// AllModules returns a slice of all valid Module string values.
func AllModules() []string {
	result := make([]string, len(allModules))
	for i, s := range allModules {
		result[i] = string(s)
	}
	return result
}

// ContainsModule checks if the given string is a valid Module.
func ContainsModule(s string) bool {
	for _, scanner := range allModules {
		if string(scanner) == s {
			return true
		}
	}
	return false
}
