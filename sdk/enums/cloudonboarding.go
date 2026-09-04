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

// CloudProvider represents a Cloud Service Provider.
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
// OutpostCloudServiceProviderEnums
// ==============================================================================

// OutpostCloudServiceProvider represents the supported Cloud Service Providers
// for outposts.
type OutpostCloudServiceProvider string

const (
	OutpostCloudServiceProviderAWS   OutpostCloudServiceProvider = "AWS"
	OutpostCloudServiceProviderAzure OutpostCloudServiceProvider = "AZURE"
	OutpostCloudServiceProviderGCP   OutpostCloudServiceProvider = "GCP"
)

// allOutpostCloudServiceProviders holds all valid OutpostCloudServiceProvider values.
var allOutpostCloudServiceProviders = []OutpostCloudServiceProvider{
	OutpostCloudServiceProviderAWS,
	OutpostCloudServiceProviderAzure,
	OutpostCloudServiceProviderGCP,
}

// String returns the string representation of an OutpostCloudServiceProvider.
func (cp OutpostCloudServiceProvider) String() string {
	return string(cp)
}

// AllOutpostCloudServiceProviders returns a slice of all valid OutpostCloudServiceProvider string values.
func AllOutpostCloudServiceProviders() []string {
	result := make([]string, len(allOutpostCloudServiceProviders))
	for i, cp := range allOutpostCloudServiceProviders {
		result[i] = string(cp)
	}
	return result
}

// ContainsOutpostCloudServiceProvider checks if the given string is a valid OutpostCloudServiceProvider.
func ContainsOutpostCloudServiceProvider(s string) bool {
	for _, provider := range allOutpostCloudServiceProviders {
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

// ==============================================================================
// SearchFieldEnums
// ==============================================================================

// SearchField represents the search field for filtering.
type SearchField string

const (
	SearchFieldStatus               SearchField = "STATUS"
	SearchFieldProvider             SearchField = "CLOUD_PROVIDER"
	SearchFieldInstanceName         SearchField = "INSTANCE_NAME"
	SearchFieldScope                SearchField = "SCOPE"
	SearchFieldScanMode             SearchField = "SCAN_MODE"
	SearchFieldCreationTime         SearchField = "CREATION_TIME"
	SearchFieldOutpostID            SearchField = "OUTPOST_ID"
	SearchFieldOutpostAccountName   SearchField = "OUTPOST_ACCOUNT_NAME"
	SearchFieldOutpostAccountID     SearchField = "OUTPOST_ACCOUNT_ID"
	SearchFieldAuthenticationMethod SearchField = "AUTHENTICATION_METHOD"
	SearchFieldID                   SearchField = "ID"
)

// allSearchFields holds all valid SearchField values.
var allSearchFields = []SearchField{
	SearchFieldStatus,
	SearchFieldProvider,
	SearchFieldInstanceName,
	SearchFieldScope,
	SearchFieldScanMode,
	SearchFieldCreationTime,
	SearchFieldOutpostID,
	SearchFieldOutpostAccountName,
	SearchFieldOutpostAccountID,
	SearchFieldAuthenticationMethod,
	SearchFieldID,
}

// String returns the string representation of a SearchField.
func (sf SearchField) String() string {
	return string(sf)
}

// AllSearchFields returns a slice of all valid SearchField string values.
func AllSearchFields() []string {
	result := make([]string, len(allSearchFields))
	for i, sf := range allSearchFields {
		result[i] = string(sf)
	}
	return result
}

// ContainsSearchField checks if the given string is a valid SearchField.
func ContainsSearchField(s string) bool {
	for _, sf := range allSearchFields {
		if string(sf) == s {
			return true
		}
	}
	return false
}

// ==============================================================================
// SearchTypeEnums
// ==============================================================================

// SearchType represents the search type for filtering.
type SearchType string

const (
	SearchTypeEqualTo              SearchType = "EQ"
	SearchTypeNotEqualTo           SearchType = "NEQ"
	SearchTypeGreaterThan          SearchType = "GT"
	SearchTypeLessThan             SearchType = "LT"
	SearchTypeGreaterThanOrEqual   SearchType = "GTE"
	SearchTypeLessThanOrEqual      SearchType = "LTE"
	SearchTypeIn                   SearchType = "IN"
	SearchTypeNotIn                SearchType = "NIN"
	SearchTypeRLIKE                SearchType = "RLIKE"
	SearchTypeNRLIKE               SearchType = "NRLIKE"
	SearchTypeWildcard             SearchType = "WILDCARD"
	SearchTypeWildcardNot          SearchType = "WILDCARD_NOT"
	SearchTypeContains             SearchType = "CONTAINS"
	SearchTypeNotContains          SearchType = "NCONTAINS"
	SearchTypeIPMatch              SearchType = "IP_MATCH"
	SearchTypeIPNotMatch           SearchType = "NIP_MATCH"
	SearchTypeArrayContains        SearchType = "ARRAY_CONTAINS"
	SearchTypeArrayNotContains     SearchType = "ARRAY_NOT_CONTAINS"
	SearchTypeIsEmpty              SearchType = "IS_EMPTY"
	SearchTypeIsNotEmpty           SearchType = "NIS_EMPTY"
	SearchTypeRegex                SearchType = "REGEX"
	SearchTypeRegexNot             SearchType = "REGEX_NOT"
	SearchTypeRegexMatch           SearchType = "REGEX_MATCH"
	SearchTypeRegexNotMatch        SearchType = "REGEX_NOT_MATCH"
	SearchTypeIPListMatch          SearchType = "IPLIST_MATCH"
	SearchTypeListNotIPMatch       SearchType = "NLISTIP_MATCH"
	SearchTypeInCIDR               SearchType = "INCIDR"
	SearchTypeNotInCIDR            SearchType = "NINCIDR"
	SearchTypeInCIDR6              SearchType = "INCIDR6"
	SearchTypeNotInCIDR6           SearchType = "NINCIDR6"
	SearchTypeRange                SearchType = "RANGE"
	SearchTypeRelativeTimestamp    SearchType = "RELATIVE_TIMESTAMP"
	SearchTypeJSONOverlaps         SearchType = "JSON_OVERLAPS"
	SearchTypeJSONArrayContainedIn SearchType = "JSON_ARRAY_CONTAINED_IN"
	SearchTypeJSONIsNotEmpty       SearchType = "JSON_IS_NOT_EMPTY"
)

// allSearchTypes holds all valid SearchType values.
var allSearchTypes = []SearchType{
	SearchTypeEqualTo,
	SearchTypeNotEqualTo,
	SearchTypeGreaterThan,
	SearchTypeLessThan,
	SearchTypeGreaterThanOrEqual,
	SearchTypeLessThanOrEqual,
	SearchTypeIn,
	SearchTypeNotIn,
	SearchTypeRLIKE,
	SearchTypeNRLIKE,
	SearchTypeWildcard,
	SearchTypeWildcardNot,
	SearchTypeContains,
	SearchTypeNotContains,
	SearchTypeIPMatch,
	SearchTypeIPNotMatch,
	SearchTypeArrayContains,
	SearchTypeArrayNotContains,
	SearchTypeIsEmpty,
	SearchTypeIsNotEmpty,
	SearchTypeRegex,
	SearchTypeRegexNot,
	SearchTypeRegexMatch,
	SearchTypeRegexNotMatch,
	SearchTypeIPListMatch,
	SearchTypeListNotIPMatch,
	SearchTypeInCIDR,
	SearchTypeNotInCIDR,
	SearchTypeInCIDR6,
	SearchTypeNotInCIDR6,
	SearchTypeRange,
	SearchTypeRelativeTimestamp,
	SearchTypeJSONOverlaps,
	SearchTypeJSONArrayContainedIn,
	SearchTypeJSONIsNotEmpty,
}

// String returns the string representation of a SearchType.
func (st SearchType) String() string {
	return string(st)
}

// AllSearchTypes returns a slice of all valid SearchType string values.
func AllSearchTypes() []string {
	result := make([]string, len(allSearchTypes))
	for i, st := range allSearchTypes {
		result[i] = string(st)
	}
	return result
}

// ContainsSearchType checks if the given string is a valid SearchType.
func ContainsSearchType(s string) bool {
	for _, st := range allSearchTypes {
		if string(st) == s {
			return true
		}
	}
	return false
}

// ==============================================================================
// IntegrationInstanceStatusEnums
// ==============================================================================

// IntegrationInstanceStatus represents the status of an integration instance.
type IntegrationInstanceStatus string

const (
	IntegrationInstanceStatusPending   IntegrationInstanceStatus = "PENDING"
	IntegrationInstanceStatusConnected IntegrationInstanceStatus = "CONNECTED"
	IntegrationInstanceStatusWarning   IntegrationInstanceStatus = "WARNING"
	IntegrationInstanceStatusError     IntegrationInstanceStatus = "ERROR"
	IntegrationInstanceStatusDisabled  IntegrationInstanceStatus = "DISABLED"
)

// allIntegrationInstanceStatuses holds all valid IntegrationInstanceStatus values.
var allIntegrationInstanceStatuses = []IntegrationInstanceStatus{
	IntegrationInstanceStatusPending,
	IntegrationInstanceStatusConnected,
	IntegrationInstanceStatusWarning,
	IntegrationInstanceStatusError,
	IntegrationInstanceStatusDisabled,
}

// String returns the string representation of a IntegrationInstanceStatus.
func (sf IntegrationInstanceStatus) String() string {
	return string(sf)
}

// AllIntegrationInstanceStatuses returns a slice of all valid IntegrationInstanceStatus string values.
func AllIntegrationInstanceStatuses() []string {
	result := make([]string, len(allIntegrationInstanceStatuses))
	for i, sf := range allIntegrationInstanceStatuses {
		result[i] = string(sf)
	}
	return result
}

// ContainsIntegrationInstanceStatus checks if the given string is a valid IntegrationInstanceStatus.
func ContainsIntegrationInstanceStatus(s string) bool {
	for _, sf := range allIntegrationInstanceStatuses {
		if string(sf) == s {
			return true
		}
	}
	return false
}

// ==============================================================================
// AuditLogCollectionMethodEnums
// ==============================================================================

// AuditLogCollectionMethod represents the method of audit log collection.
type AuditLogCollectionMethod string

const (
	AuditLogCollectionMethodAutomated AuditLogCollectionMethod = "AUTOMATED"
	AuditLogCollectionMethodCustom    AuditLogCollectionMethod = "CUSTOM"
)

// allAuditLogCollectionMethods holds all valid AuditLogCollectionMethod values.
var allAuditLogCollectionMethods = []AuditLogCollectionMethod{
	AuditLogCollectionMethodAutomated,
	AuditLogCollectionMethodCustom,
}

// String returns the string representation of a AuditLogCollectionMethod.
func (sf AuditLogCollectionMethod) String() string {
	return string(sf)
}

// AllAuditLogCollectionMethods returns a slice of all valid AuditLogCollectionMethod string values.
func AllAuditLogCollectionMethods() []string {
	result := make([]string, len(allAuditLogCollectionMethods))
	for i, sf := range allAuditLogCollectionMethods {
		result[i] = string(sf)
	}
	return result
}

// ContainsAuditLogCollectionMethod checks if the given string is a valid AuditLogCollectionMethod.
func ContainsAuditLogCollectionMethod(s string) bool {
	for _, sf := range allAuditLogCollectionMethods {
		if string(sf) == s {
			return true
		}
	}
	return false
}
