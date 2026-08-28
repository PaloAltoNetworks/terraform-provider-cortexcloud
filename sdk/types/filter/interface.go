// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package types

// Filter is a recursive structure that can be used to build complex search filters.
// It can represent both logical groupings (AND/OR) and individual search criteria.
type Filter interface {
	isFilter()
}
