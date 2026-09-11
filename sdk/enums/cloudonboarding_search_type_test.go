// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package enums

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestSearchType_JSONWildcardNotIsRecognised is the regression test for
// JSON_WILDCARD_NOT support. The CAS API contract declares both JSON_WILDCARD and its negated
// form JSON_WILDCARD_NOT, but only the affirmative operator was implemented.
// A predicate using the negated form was therefore rejected as an unknown
// search type and its object-valued SEARCH_VALUE was sent as a JSON-encoded
// string, which the consumers of the scope cannot unmarshal.
func TestSearchType_JSONWildcardNotIsRecognised(t *testing.T) {
	assert.Equal(t, "JSON_WILDCARD_NOT", SearchTypeJSONWildcardNot.String())
	assert.True(t, ContainsSearchType("JSON_WILDCARD_NOT"),
		"JSON_WILDCARD_NOT must be a valid search type")
	assert.Contains(t, AllSearchTypes(), "JSON_WILDCARD_NOT")
}

// TestIsJSONValuedSearchType_JSONWildcardNot asserts that the negated form is
// treated as JSON valued, so that its SEARCH_VALUE is serialized as a native
// JSON object rather than as a quoted string.
func TestIsJSONValuedSearchType_JSONWildcardNot(t *testing.T) {
	assert.True(t, IsJSONValuedSearchType("JSON_WILDCARD_NOT"))
}

// TestIsJSONValuedSearchType covers the full JSON-valued set alongside a few
// negative cases, so that the affirmative/negated pairing cannot regress.
func TestIsJSONValuedSearchType(t *testing.T) {
	tests := []struct {
		searchType string
		want       bool
	}{
		{searchType: "JSON_WILDCARD", want: true},
		{searchType: "JSON_WILDCARD_NOT", want: true},
		{searchType: "JSON_OVERLAPS", want: true},
		{searchType: "JSON_ARRAY_CONTAINED_IN", want: true},
		{searchType: "CONTAINS", want: false},
		{searchType: "NCONTAINS", want: false},
		{searchType: "WILDCARD", want: false},
		{searchType: "WILDCARD_NOT", want: false},
		{searchType: "", want: false},
		{searchType: "NOT_A_SEARCH_TYPE", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.searchType, func(t *testing.T) {
			assert.Equal(t, tt.want, IsJSONValuedSearchType(tt.searchType))
		})
	}
}

// TestAllSearchTypes_NegatedPairsArePresent guards the package-wide convention
// that every operator ships as an affirmative/negated pair. JSON_WILDCARD was
// only half implemented, which is the defect this test locks down.
func TestAllSearchTypes_NegatedPairsArePresent(t *testing.T) {
	pairs := map[string]string{
		"WILDCARD":       "WILDCARD_NOT",
		"CONTAINS":       "NCONTAINS",
		"IN":             "NIN",
		"ARRAY_CONTAINS": "ARRAY_NOT_CONTAINS",
		"JSON_WILDCARD":  "JSON_WILDCARD_NOT",
	}

	for affirmative, negated := range pairs {
		t.Run(affirmative, func(t *testing.T) {
			assert.True(t, ContainsSearchType(affirmative),
				"affirmative operator %q must be a valid search type", affirmative)
			assert.True(t, ContainsSearchType(negated),
				"negated operator %q must be a valid search type", negated)
		})
	}
}

// TestAllSearchTypes_NoDuplicates ensures the enum list stays consistent as
// operators are added.
func TestAllSearchTypes_NoDuplicates(t *testing.T) {
	seen := make(map[string]struct{}, len(allSearchTypes))
	for _, st := range AllSearchTypes() {
		_, duplicate := seen[st]
		assert.False(t, duplicate, "duplicate search type %q", st)
		seen[st] = struct{}{}
	}
}
