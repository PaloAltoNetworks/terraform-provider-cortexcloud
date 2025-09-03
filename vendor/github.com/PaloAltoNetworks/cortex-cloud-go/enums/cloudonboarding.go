// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package enums

// ==============================================================================
// ScopeEnums
// ==============================================================================

// Scope represents the scope for a resource.
type Scope string

const (
	ScopeAccount      Scope = "ACCOUNT"
	ScopeAccountGroup Scope = "ACCOUNT_GROUP"
	ScopeOrganization Scope = "ORGANIZATION"
)

// allScopes holds all valid Scope values.
var allScopes = []Scope{
	ScopeAccount,
	ScopeAccountGroup,
	ScopeOrganization,
}

// String returns the string representation of a Scope.
func (s Scope) String() string {
	return string(s)
}

// AllScopes returns a slice of all valid Scope string values.
func AllScopes() []string {
	result := make([]string, len(allScopes))
	for i, s := range allScopes {
		result[i] = string(s)
	}
	return result
}

// ContainsScope checks if the given string is a valid Scope.
func ContainsScope(s string) bool {
	for _, scope := range allScopes {
		if string(scope) == s {
			return true
		}
	}
	return false
}

// ==============================================================================
// ScanModeEnums
// ==============================================================================

// ScanMode represents the scanning mode.
type ScanMode string

const (
	ScanModeManaged ScanMode = "MANAGED"
	ScanModeOutpost ScanMode = "OUTPOST"
)

// allScanModes holds all valid ScanMode values.
var allScanModes = []ScanMode{
	ScanModeManaged,
	ScanModeOutpost,
}

// String returns the string representation of a ScanMode.
func (s ScanMode) String() string {
	return string(s)
}

// AllScanModes returns a slice of all valid ScanMode string values.
func AllScanModes() []string {
	result := make([]string, len(allScanModes))
	for i, s := range allScanModes {
		result[i] = string(s)
	}
	return result
}

// ContainsScanMode checks if the given string is a valid ScanMode.
func ContainsScanMode(s string) bool {
	for _, mode := range allScanModes {
		if string(mode) == s {
			return true
		}
	}
	return false
}

// ==============================================================================
// CloudProviderEnums
// ==============================================================================

// CloudProvider represents the cloud provider.
type CloudProvider string

const (
	CloudProviderAWS   CloudProvider = "AWS"
	CloudProviderAzure CloudProvider = "AZURE"
	CloudProviderGCP   CloudProvider = "GCP"
)

// allCloudProviders holds all valid CloudProvider values.
var allCloudProviders = []CloudProvider{
	CloudProviderAWS,
	CloudProviderAzure,
	CloudProviderGCP,
}

// String returns the string representation of a CloudProvider.
func (cp CloudProvider) String() string {
	return string(cp)
}

// AllCloudProviders returns a slice of all valid CloudProvider string values.
func AllCloudProviders() []string {
	result := make([]string, len(allCloudProviders))
	for i, cp := range allCloudProviders {
		result[i] = string(cp)
	}
	return result
}

// ContainsCloudProvider checks if the given string is a valid CloudProvider.
func ContainsCloudProvider(s string) bool {
	for _, provider := range allCloudProviders {
		if string(provider) == s {
			return true
		}
	}
	return false
}

// ==============================================================================
// ScopeModificationTypeEnums
// ==============================================================================

// ScopeModificationType represents the type of scope modification.
type ScopeModificationType string

const (
	ScopeModificationTypeInclude ScopeModificationType = "INCLUDE"
	ScopeModificationTypeExclude ScopeModificationType = "EXCLUDE"
)

// allScopeModificationTypes holds all valid ScopeModificationType values.
var allScopeModificationTypes = []ScopeModificationType{
	ScopeModificationTypeInclude,
	ScopeModificationTypeExclude,
}

// String returns the string representation of a ScopeModificationType.
func (smt ScopeModificationType) String() string {
	return string(smt)
}

// AllScopeModificationTypes returns a slice of all valid ScopeModificationType string values.
func AllScopeModificationTypes() []string {
	result := make([]string, len(allScopeModificationTypes))
	for i, smt := range allScopeModificationTypes {
		result[i] = string(smt)
	}
	return result
}

// ContainsScopeModificationType checks if the given string is a valid ScopeModificationType.
func ContainsScopeModificationType(s string) bool {
	for _, smt := range allScopeModificationTypes {
		if string(smt) == s {
			return true
		}
	}
	return false
}

// ==============================================================================
// RegistryScanningTypeEnums
// ==============================================================================

// RegistryScanningType represents the type of registry scanning.
type RegistryScanningType string

const (
	RegistryScanningTypeAll              RegistryScanningType = "ALL"
	RegistryScanningTypeLatestTag        RegistryScanningType = "LATEST_TAG"
	RegistryScanningTypeTagsModifiedDays RegistryScanningType = "TAGS_MODIFIED_DAYS"
)

// allRegistryScanningTypes holds all valid RegistryScanningType values.
var allRegistryScanningTypes = []RegistryScanningType{
	RegistryScanningTypeAll,
	RegistryScanningTypeLatestTag,
	RegistryScanningTypeTagsModifiedDays,
}

// String returns the string representation of a RegistryScanningType.
func (rst RegistryScanningType) String() string {
	return string(rst)
}

// AllRegistryScanningTypes returns a slice of all valid RegistryScanningType string values.
func AllRegistryScanningTypes() []string {
	result := make([]string, len(allRegistryScanningTypes))
	for i, rst := range allRegistryScanningTypes {
		result[i] = string(rst)
	}
	return result
}

// ContainsRegistryScanningType checks if the given string is a valid RegistryScanningType.
func ContainsRegistryScanningType(s string) bool {
	for _, rst := range allRegistryScanningTypes {
		if string(rst) == s {
			return true
		}
	}
	return false
}
