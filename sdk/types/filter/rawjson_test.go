// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package types

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFilterRawJSON_MarshalObjectValue asserts that an object-valued
// SEARCH_VALUE is emitted as a native JSON object and not as a JSON-encoded
// string.
func TestFilterRawJSON_MarshalObjectValue(t *testing.T) {
	f, err := NewSearchFilterRawJSON(
		"xdm.asset.tags",
		"JSON_WILDCARD",
		json.RawMessage(`{"key":"application","value":"databricks"}`),
	)
	require.NoError(t, err)

	b, err := json.Marshal(f)
	require.NoError(t, err)

	assert.JSONEq(t, `{
		"SEARCH_FIELD": "xdm.asset.tags",
		"SEARCH_TYPE": "JSON_WILDCARD",
		"SEARCH_VALUE": {"key": "application", "value": "databricks"}
	}`, string(b))

	// The value must not be double-encoded as a string.
	assert.NotContains(t, string(b), `"SEARCH_VALUE":"`)
}

// TestFilterRawJSON_MarshalJSONWildcardNotObjectValue is the regression test
// for JSON_WILDCARD_NOT support. The negated form of JSON_WILDCARD carries the same
// object-valued SEARCH_VALUE as the affirmative form and must be emitted as
// native JSON.
func TestFilterRawJSON_MarshalJSONWildcardNotObjectValue(t *testing.T) {
	f, err := NewSearchFilterRawJSON(
		"xdm.image.labels",
		"JSON_WILDCARD_NOT",
		json.RawMessage(`{"key":"BREAKPRISMA","value":"exception"}`),
	)
	require.NoError(t, err)

	b, err := json.Marshal(f)
	require.NoError(t, err)

	assert.JSONEq(t, `{
		"SEARCH_FIELD": "xdm.image.labels",
		"SEARCH_TYPE": "JSON_WILDCARD_NOT",
		"SEARCH_VALUE": {"key": "BREAKPRISMA", "value": "exception"}
	}`, string(b))

	assert.NotContains(t, string(b), `"SEARCH_VALUE":"`)
}

func TestFilterRawJSON_MarshalArrayValue(t *testing.T) {
	f, err := NewSearchFilterRawJSON("xdm.asset.tags", "JSON_OVERLAPS", json.RawMessage(`["a","b"]`))
	require.NoError(t, err)

	b, err := json.Marshal(f)
	require.NoError(t, err)

	assert.JSONEq(t, `{
		"SEARCH_FIELD": "xdm.asset.tags",
		"SEARCH_TYPE": "JSON_OVERLAPS",
		"SEARCH_VALUE": ["a", "b"]
	}`, string(b))
}

// TestNewSearchFilterRawJSON_InvalidJSON asserts that the constructor rejects
// syntactically invalid JSON instead of silently constructing a filter that
// would later be rejected by the API (or worse, corrupt the payload).
func TestNewSearchFilterRawJSON_InvalidJSON(t *testing.T) {
	f, err := NewSearchFilterRawJSON("xdm.asset.tags", "JSON_WILDCARD", json.RawMessage(`{not valid json`))
	require.Error(t, err)
	assert.Nil(t, f)
}

// TestNewSearchFilterRawJSON_EmptyValue asserts that the constructor rejects
// a nil/empty SEARCH_VALUE, since a search criterion without a value is
// meaningless and would previously have been silently accepted.
func TestNewSearchFilterRawJSON_EmptyValue(t *testing.T) {
	f, err := NewSearchFilterRawJSON("xdm.asset.tags", "JSON_WILDCARD", nil)
	require.Error(t, err)
	assert.Nil(t, f)

	f, err = NewSearchFilterRawJSON("xdm.asset.tags", "JSON_WILDCARD", json.RawMessage(``))
	require.Error(t, err)
	assert.Nil(t, f)
}

func TestFilterRawJSON_RoundTrip(t *testing.T) {
	original := `{"SEARCH_FIELD":"xdm.asset.tags","SEARCH_TYPE":"JSON_WILDCARD","SEARCH_VALUE":{"key":"application","value":"databricks"}}`

	var f FilterRawJSON
	require.NoError(t, json.Unmarshal([]byte(original), &f))

	assert.JSONEq(t, `{"key":"application","value":"databricks"}`, string(f.SearchValue()))

	b, err := json.Marshal(f)
	require.NoError(t, err)
	assert.JSONEq(t, original, string(b))
}

func TestFilterRawJSON_NestedInRootFilter(t *testing.T) {
	rawFilter, err := NewSearchFilterRawJSON(
		"xdm.asset.tags",
		"JSON_WILDCARD",
		json.RawMessage(`{"key":"Owner","value":"farhan ahmed"}`),
	)
	require.NoError(t, err)

	root := NewRootFilter(
		[]Filter{rawFilter},
		nil,
	)

	b, err := json.Marshal(root)
	require.NoError(t, err)

	assert.JSONEq(t, `{
		"AND": [
			{
				"SEARCH_FIELD": "xdm.asset.tags",
				"SEARCH_TYPE": "JSON_WILDCARD",
				"SEARCH_VALUE": {"key": "Owner", "value": "farhan ahmed"}
			}
		]
	}`, string(b))

	var decoded FilterRoot
	require.NoError(t, json.Unmarshal(b, &decoded))

	reencoded, err := json.Marshal(decoded)
	require.NoError(t, err)
	assert.JSONEq(t, string(b), string(reencoded), "root filter must survive a round trip")
}

// TestUnmarshalFilter_Dispatch verifies that unmarshalFilter routes each
// SEARCH_VALUE shape to the correct concrete Filter implementation.
func TestUnmarshalFilter_Dispatch(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected Filter
	}{
		{
			name:     "timespan object dispatches to FilterTimespan",
			input:    `{"SEARCH_FIELD":"time","SEARCH_TYPE":"RANGE","SEARCH_VALUE":{"from":1,"to":2}}`,
			expected: FilterTimespan{},
		},
		{
			name:     "timespan object with only from dispatches to FilterTimespan",
			input:    `{"SEARCH_FIELD":"time","SEARCH_TYPE":"RANGE","SEARCH_VALUE":{"from":1}}`,
			expected: FilterTimespan{},
		},
		{
			name:     "non-timespan object dispatches to FilterRawJSON",
			input:    `{"SEARCH_FIELD":"xdm.asset.tags","SEARCH_TYPE":"JSON_WILDCARD","SEARCH_VALUE":{"key":"a","value":"b"}}`,
			expected: FilterRawJSON{},
		},
		{
			name:     "negated json wildcard object dispatches to FilterRawJSON",
			input:    `{"SEARCH_FIELD":"xdm.image.labels","SEARCH_TYPE":"JSON_WILDCARD_NOT","SEARCH_VALUE":{"key":"BREAKPRISMA","value":"exception"}}`,
			expected: FilterRawJSON{},
		},
		{
			name:     "array dispatches to FilterRawJSON",
			input:    `{"SEARCH_FIELD":"xdm.asset.tags","SEARCH_TYPE":"JSON_OVERLAPS","SEARCH_VALUE":["a","b"]}`,
			expected: FilterRawJSON{},
		},
		{
			name:     "bool dispatches to FilterBoolValue",
			input:    `{"SEARCH_FIELD":"enabled","SEARCH_TYPE":"EQ","SEARCH_VALUE":true}`,
			expected: FilterBoolValue{},
		},
		{
			name:     "string dispatches to FilterGeneric",
			input:    `{"SEARCH_FIELD":"xdm.asset.name","SEARCH_TYPE":"CONTAINS","SEARCH_VALUE":"prod"}`,
			expected: FilterGeneric{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := unmarshalFilter([]byte(tt.input))
			require.NoError(t, err)
			assert.IsType(t, tt.expected, got)

			// Whatever the concrete type, the payload must round trip intact.
			b, err := json.Marshal(got)
			require.NoError(t, err)
			assert.JSONEq(t, tt.input, string(b))
		})
	}
}

// TestUnmarshalFilter_TimespanRegression guards the pre-existing timespan
// behaviour that the dispatch fix must not alter.
func TestUnmarshalFilter_TimespanRegression(t *testing.T) {
	input := `{"SEARCH_FIELD":"time","SEARCH_TYPE":"RANGE","SEARCH_VALUE":{"from":100,"to":200}}`

	got, err := unmarshalFilter([]byte(input))
	require.NoError(t, err)

	ts, ok := got.(FilterTimespan)
	require.True(t, ok, "expected FilterTimespan, got %T", got)
	assert.Equal(t, 100, ts.searchValue.From)
	assert.Equal(t, 200, ts.searchValue.To)
}
