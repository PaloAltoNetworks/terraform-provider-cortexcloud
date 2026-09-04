// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

// Package enums contains enumerated types used across the SDK.
package enums

// ==============================================================================
// Module
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

// ==============================================================================
// API Key Type
// ==============================================================================

// APIKeyType represents the type of an API key.
type APIKeyType string

const (
	APIKeyTypeStandard APIKeyType = "standard"
	APIKeyTypeAdvanced APIKeyType = "advanced"
)

// allAPIKeyTypes holds all valid APIKeyType values.
var allAPIKeyTypes = []APIKeyType{
	APIKeyTypeStandard,
	APIKeyTypeAdvanced,
}

// String returns the string representation of a APIKeyType.
func (s APIKeyType) String() string {
	return string(s)
}

// AllAPIKeyTypes returns a slice of all valid APIKeyType string values.
func AllAPIKeyTypes() []string {
	result := make([]string, len(allAPIKeyTypes))
	for i, s := range allAPIKeyTypes {
		result[i] = string(s)
	}
	return result
}

// ContainsAPIKeyType checks if the given string is a valid APIKeyType.
func ContainsAPIKeyType(s string) bool {
	for _, scanner := range allAPIKeyTypes {
		if string(scanner) == s {
			return true
		}
	}
	return false
}
