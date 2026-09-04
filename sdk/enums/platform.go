// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package enums

// ==============================================================================
// Asset Group Type Enums
// ==============================================================================

// AssetGroupType represents the possible types of an asset group.
type AssetGroupType string

const (
	AssetGroupTypeDynamic = "Dynamic"
	AssetGroupTypeStatic  = "Static"
)

// allAssetGroupTypes holds all valid AssetGroupType values.
var allAssetGroupTypes = []AssetGroupType{
	AssetGroupTypeDynamic,
	AssetGroupTypeStatic,
}

// Returns the string representation of a AssetGroupType.
func (pt AssetGroupType) String() string {
	return string(pt)
}

// AllAssetGroupTypes returns a slice of all valid AssetGroupType string values.
func AllAssetGroupTypes() []string {
	result := make([]string, len(allAssetGroupTypes))
	for i, pt := range allAssetGroupTypes {
		result[i] = string(pt)
	}
	return result
}

// ContainsAssetGroupType checks if the given string is a valid AssetGroupType.
func ContainsAssetGroupType(s string) bool {
	for _, assetGroupType := range allAssetGroupTypes {
		if string(assetGroupType) == s {
			return true // Includes empty string check
		}
	}
	return false
}
