// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package types

// ToPointer takes any type and returns a pointer for that type.
func ToPointer[T any](d T) *T {
	return &d
}
