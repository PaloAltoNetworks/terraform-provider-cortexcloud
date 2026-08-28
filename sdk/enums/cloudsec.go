// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package enums

// ==============================================================================
// CloudSecSeverity
// ==============================================================================

// CloudSecSeverity represents the severity levels for CloudSec rules.
// Note: CloudSec uses lowercase severity values, different from AppSec's uppercase values.
type CloudSecSeverity string

const (
	CloudSecSeverityInformational CloudSecSeverity = "informational"
	CloudSecSeverityLow           CloudSecSeverity = "low"
	CloudSecSeverityMedium        CloudSecSeverity = "medium"
	CloudSecSeverityHigh          CloudSecSeverity = "high"
	CloudSecSeverityCritical      CloudSecSeverity = "critical"
)

// allCloudSecSeverities holds all valid CloudSecSeverity values.
var allCloudSecSeverities = []CloudSecSeverity{
	CloudSecSeverityInformational,
	CloudSecSeverityLow,
	CloudSecSeverityMedium,
	CloudSecSeverityHigh,
	CloudSecSeverityCritical,
}

// String returns the string representation of a CloudSecSeverity.
func (s CloudSecSeverity) String() string {
	return string(s)
}

// AllCloudSecSeverities returns a slice of all valid CloudSecSeverity string values.
func AllCloudSecSeverities() []string {
	result := make([]string, len(allCloudSecSeverities))
	for i, s := range allCloudSecSeverities {
		result[i] = string(s)
	}
	return result
}

// ContainsCloudSecSeverity checks if the given string is a valid CloudSecSeverity.
func ContainsCloudSecSeverity(s string) bool {
	for _, severity := range allCloudSecSeverities {
		if string(severity) == s {
			return true
		}
	}
	return false
}

// ==============================================================================
// SortOrder
// ==============================================================================

// SortOrder represents the sort order for search results.
type SortOrder string

const (
	SortOrderASC  SortOrder = "ASC"  // Ascending
	SortOrderDESC SortOrder = "DESC" // Descending
)

// allSortOrders holds all valid SortOrder values.
var allSortOrders = []SortOrder{
	SortOrderASC,
	SortOrderDESC,
}

// String returns the string representation of a SortOrder.
func (s SortOrder) String() string {
	return string(s)
}

// AllSortOrders returns a slice of all valid SortOrder string values.
func AllSortOrders() []string {
	result := make([]string, len(allSortOrders))
	for i, s := range allSortOrders {
		result[i] = string(s)
	}
	return result
}

// ContainsSortOrder checks if the given string is a valid SortOrder.
func ContainsSortOrder(s string) bool {
	for _, sortOrder := range allSortOrders {
		if string(sortOrder) == s {
			return true
		}
	}
	return false
}

// ==============================================================================
// RuleClass
// ==============================================================================

// RuleClass represents the class of a CloudSec rule.
type RuleClass string

const (
	RuleClassConfig RuleClass = "config" // Configuration-based rule (CSPM)
)

// allRuleClasses holds all valid RuleClass values.
var allRuleClasses = []RuleClass{
	RuleClassConfig,
}

// String returns the string representation of a RuleClass.
func (r RuleClass) String() string {
	return string(r)
}

// AllRuleClasses returns a slice of all valid RuleClass string values.
func AllRuleClasses() []string {
	result := make([]string, len(allRuleClasses))
	for i, r := range allRuleClasses {
		result[i] = string(r)
	}
	return result
}

// ContainsRuleClass checks if the given string is a valid RuleClass.
func ContainsRuleClass(s string) bool {
	for _, ruleClass := range allRuleClasses {
		if string(ruleClass) == s {
			return true
		}
	}
	return false
}

// ==============================================================================
// RuleMatchingType
// ==============================================================================

// RuleMatchingType represents the method of selecting applicable rules for a policy.
type RuleMatchingType string

const (
	RuleMatchingTypeRuleFilter RuleMatchingType = "RULE_FILTER" // Filter-based rule selection
	RuleMatchingTypeRules      RuleMatchingType = "RULES"       // Specific rule IDs
	RuleMatchingTypeAllRules   RuleMatchingType = "ALL_RULES"   // All available rules
)

// allRuleMatchingTypes holds all valid RuleMatchingType values.
var allRuleMatchingTypes = []RuleMatchingType{
	RuleMatchingTypeRuleFilter,
	RuleMatchingTypeRules,
	RuleMatchingTypeAllRules,
}

// String returns the string representation of a RuleMatchingType.
func (r RuleMatchingType) String() string {
	return string(r)
}

// AllRuleMatchingTypes returns a slice of all valid RuleMatchingType string values.
func AllRuleMatchingTypes() []string {
	result := make([]string, len(allRuleMatchingTypes))
	for i, r := range allRuleMatchingTypes {
		result[i] = string(r)
	}
	return result
}

// ContainsRuleMatchingType checks if the given string is a valid RuleMatchingType.
func ContainsRuleMatchingType(s string) bool {
	for _, ruleMatchingType := range allRuleMatchingTypes {
		if string(ruleMatchingType) == s {
			return true
		}
	}
	return false
}

// ==============================================================================
// AssetMatchingType
// ==============================================================================

// AssetMatchingType represents the method of selecting assets in scope for a policy.
type AssetMatchingType string

const (
	AssetMatchingTypeAssetGroups   AssetMatchingType = "ASSET_GROUPS"   // Specific asset groups
	AssetMatchingTypeAllAssets     AssetMatchingType = "ALL_ASSETS"     // All assets
	AssetMatchingTypeCloudAccounts AssetMatchingType = "CLOUD_ACCOUNTS" // Specific cloud accounts
)

// allAssetMatchingTypes holds all valid AssetMatchingType values.
var allAssetMatchingTypes = []AssetMatchingType{
	AssetMatchingTypeAssetGroups,
	AssetMatchingTypeAllAssets,
	AssetMatchingTypeCloudAccounts,
}

// String returns the string representation of an AssetMatchingType.
func (a AssetMatchingType) String() string {
	return string(a)
}

// AllAssetMatchingTypes returns a slice of all valid AssetMatchingType string values.
func AllAssetMatchingTypes() []string {
	result := make([]string, len(allAssetMatchingTypes))
	for i, a := range allAssetMatchingTypes {
		result[i] = string(a)
	}
	return result
}

// ContainsAssetMatchingType checks if the given string is a valid AssetMatchingType.
func ContainsAssetMatchingType(s string) bool {
	for _, assetMatchingType := range allAssetMatchingTypes {
		if string(assetMatchingType) == s {
			return true
		}
	}
	return false
}

// ==============================================================================
// PolicyMode
// ==============================================================================

// PolicyMode represents whether a policy is built-in or user-created.
type PolicyMode string

const (
	PolicyModeDefault PolicyMode = "DEFAULT" // Built-in system policy
	PolicyModeCustom  PolicyMode = "CUSTOM"  // User-created policy
)

// allPolicyModes holds all valid PolicyMode values.
var allPolicyModes = []PolicyMode{
	PolicyModeDefault,
	PolicyModeCustom,
}

// String returns the string representation of a PolicyMode.
func (p PolicyMode) String() string {
	return string(p)
}

// AllPolicyModes returns a slice of all valid PolicyMode string values.
func AllPolicyModes() []string {
	result := make([]string, len(allPolicyModes))
	for i, p := range allPolicyModes {
		result[i] = string(p)
	}
	return result
}

// ContainsPolicyMode checks if the given string is a valid PolicyMode.
func ContainsPolicyMode(s string) bool {
	for _, policyMode := range allPolicyModes {
		if string(policyMode) == s {
			return true
		}
	}
	return false
}
