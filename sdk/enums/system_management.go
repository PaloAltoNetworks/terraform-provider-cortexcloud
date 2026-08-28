// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package enums

// ==============================================================================
// UserType
// ==============================================================================

// UserType represents the type of an RBAC user.
type UserType string

const (
	UserTypeCSP    UserType = "CSP"
	UserTypeSSO    UserType = "SSO"
	UserTypeCSPSSO UserType = "CSP / SSO"
)

// allUserTypes holds all valid UserType values.
var allUserTypes = []UserType{
	UserTypeCSP,
	UserTypeSSO,
	UserTypeCSPSSO,
}

// String returns the string representation of a UserType.
func (s UserType) String() string {
	return string(s)
}

// AllUserTypes returns a slice of all valid UserType string values.
func AllUserTypes() []string {
	result := make([]string, len(allUserTypes))
	for i, s := range allUserTypes {
		result[i] = string(s)
	}
	return result
}

// ContainsUserType checks if the given string is a valid UserType.
func ContainsUserType(s string) bool {
	for _, item := range allUserTypes {
		if string(item) == s {
			return true
		}
	}
	return false
}
