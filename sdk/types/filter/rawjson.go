// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package types

import (
	"encoding/json"
	"fmt"
)

// FilterRawJSON represents a search criterion whose SEARCH_VALUE is a native
// JSON value (an object or an array) rather than a string.
//
// Some search types - notably JSON_WILDCARD and its negated form
// JSON_WILDCARD_NOT, which back tag-based dynamic asset groups - require the
// API to receive SEARCH_VALUE as a real JSON object:
//
//	{"SEARCH_FIELD": "xdm.asset.tags", "SEARCH_TYPE": "JSON_WILDCARD",
//	 "SEARCH_VALUE": {"key": "application", "value": "databricks"}}
//
// Using FilterGeneric for these search types produces a JSON-encoded string
// instead ("{\"key\":...}"), which the API rejects.
//
// Its fields are unexported to enforce creation via constructors.
type FilterRawJSON struct {
	and         []Filter
	or          []Filter
	searchField string
	searchType  string
	searchValue json.RawMessage
}

// Marker method for Filter interface compliance.
func (FilterRawJSON) isFilter() {}

// NewSearchFilterRawJSON returns a new search filter criterion whose
// SEARCH_VALUE is serialized as native JSON rather than as a string.
//
// value must be syntactically valid JSON (a JSON object, array, string,
// number, boolean, or null); it is validated internally via json.Valid, and
// an error is returned if validation fails. A nil or empty value is also
// rejected, since SEARCH_VALUE must always be present for a search filter.
func NewSearchFilterRawJSON(field, searchType string, value json.RawMessage) (Filter, error) {
	if len(value) == 0 {
		return nil, fmt.Errorf("search value for field %q, search type %q must not be empty", field, searchType)
	}
	if !json.Valid(value) {
		return nil, fmt.Errorf("search value for field %q, search type %q is not valid JSON: %s", field, searchType, value)
	}

	return FilterRawJSON{
		searchField: field,
		searchType:  searchType,
		searchValue: value,
	}, nil
}

// AddAnd appends filters to the And slice of a FilterRawJSON.
func (f *FilterRawJSON) AddAnd(filters ...Filter) {
	f.and = append(f.and, filters...)
}

// AddOr appends filters to the Or slice of a FilterRawJSON.
func (f *FilterRawJSON) AddOr(filters ...Filter) {
	f.or = append(f.or, filters...)
}

// SearchValue returns the raw JSON search value of the filter.
func (f FilterRawJSON) SearchValue() json.RawMessage {
	return f.searchValue
}

func (f FilterRawJSON) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		And         []Filter        `json:"AND,omitempty"`
		Or          []Filter        `json:"OR,omitempty"`
		SearchField string          `json:"SEARCH_FIELD,omitempty"`
		SearchType  string          `json:"SEARCH_TYPE,omitempty"`
		SearchValue json.RawMessage `json:"SEARCH_VALUE,omitempty"`
	}{
		And:         f.and,
		Or:          f.or,
		SearchField: f.searchField,
		SearchType:  f.searchType,
		SearchValue: f.searchValue,
	})
}

func (f *FilterRawJSON) UnmarshalJSON(b []byte) error {
	var raw struct {
		And         []json.RawMessage `json:"AND,omitempty"`
		Or          []json.RawMessage `json:"OR,omitempty"`
		SearchField string            `json:"SEARCH_FIELD,omitempty"`
		SearchType  string            `json:"SEARCH_TYPE,omitempty"`
		SearchValue json.RawMessage   `json:"SEARCH_VALUE,omitempty"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return fmt.Errorf("failed to unmarshal raw json filter: %w", err)
	}

	f.searchField = raw.SearchField
	f.searchType = raw.SearchType
	f.searchValue = raw.SearchValue

	if len(raw.And) > 0 {
		f.and = make([]Filter, len(raw.And))
		for i, filterJSON := range raw.And {
			filter, err := unmarshalFilter(filterJSON)
			if err != nil {
				return err
			}
			f.and[i] = filter
		}
	} else {
		f.and = nil
	}

	if len(raw.Or) > 0 {
		f.or = make([]Filter, len(raw.Or))
		for i, filterJSON := range raw.Or {
			filter, err := unmarshalFilter(filterJSON)
			if err != nil {
				return err
			}
			f.or[i] = filter
		}
	} else {
		f.or = nil
	}

	return nil
}
