package models

import (
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/types"
)

// eqTFString compares two types.String values case-insensitively.
// Two null/unknown values are considered equal to each other.
// A null/unknown value is never equal to a non-null value.
func eqTFString(a, b types.String) bool {
	aNullish := a.IsNull() || a.IsUnknown()
	bNullish := b.IsNull() || b.IsUnknown()
	if aNullish && bNullish {
		return true
	}
	if aNullish != bNullish {
		return false
	}
	return strings.EqualFold(a.ValueString(), b.ValueString())
}

// eqTFInt64 compares two types.Int64 values.
// Two null/unknown values are considered equal to each other.
// A null/unknown value is never equal to a non-null value.
func eqTFInt64(a, b types.Int64) bool {
	aNullish := a.IsNull() || a.IsUnknown()
	bNullish := b.IsNull() || b.IsUnknown()
	if aNullish && bNullish {
		return true
	}
	if aNullish != bNullish {
		return false
	}
	return a.ValueInt64() == b.ValueInt64()
}

// ---------------------------------------------------------------------------
// FilterRangeInt64Model
// ---------------------------------------------------------------------------

// Equals returns true if all fields of the receiver match the corresponding
// fields of other.
func (m FilterRangeInt64Model) Equals(other FilterRangeInt64Model) bool {
	return eqTFInt64(m.From, other.From) && eqTFInt64(m.To, other.To)
}

// ---------------------------------------------------------------------------
// FilterGreaterOrLessThanInt64Model
// ---------------------------------------------------------------------------

// Equals returns true if all fields of the receiver match the corresponding
// fields of other. The Condition string field is compared case-insensitively.
func (m FilterGreaterOrLessThanInt64Model) Equals(other FilterGreaterOrLessThanInt64Model) bool {
	return eqTFString(m.Condition, other.Condition) && eqTFInt64(m.Value, other.Value)
}

// ---------------------------------------------------------------------------
// NestedFilterModel
// ---------------------------------------------------------------------------

// Equals returns true if all non-nil fields of the receiver match the
// corresponding fields of other. String fields are compared
// case-insensitively. Nested And/Or slices are compared recursively.
func (m NestedFilterModel) Equals(other NestedFilterModel) bool {
	if !eqTFString(m.SearchField, other.SearchField) {
		return false
	}
	if !eqTFString(m.SearchType, other.SearchType) {
		return false
	}
	if !eqTFString(m.SearchValue, other.SearchValue) {
		return false
	}
	if !nestedFilterSliceEquals(m.And, other.And) {
		return false
	}
	if !nestedFilterSliceEquals(m.Or, other.Or) {
		return false
	}
	return true
}

// ---------------------------------------------------------------------------
// RootFilterModel
// ---------------------------------------------------------------------------

// Equals returns true if all non-nil fields of the receiver match the
// corresponding fields of other. Nested And/Or slices are compared
// recursively.
func (m RootFilterModel) Equals(other *RootFilterModel) bool {
	if other == nil {
		return false
	}
	if !nestedFilterSliceEquals(m.And, other.And) {
		return false
	}
	if !nestedFilterSliceEquals(m.Or, other.Or) {
		return false
	}
	return true
}

// nestedFilterSliceEquals compares two slices of NestedFilterModel for
// element-wise deep equality.
func nestedFilterSliceEquals(a, b []NestedFilterModel) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !a[i].Equals(b[i]) {
			return false
		}
	}
	return true
}
