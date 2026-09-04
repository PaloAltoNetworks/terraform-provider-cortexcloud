// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package types

import (
	"encoding/json"
	"fmt"
)

// FilterBoolValue represents a search criterion or a nested logical block with a boolean value parameter.
type FilterBoolValue struct {
	and         []Filter
	or          []Filter
	searchField string
	searchType  string
	searchValue bool
}

// Marker method for Filter interface compliance.
func (FilterBoolValue) isFilter() {}

// NewAndFilterBoolValue returns a new FilterBoolValue that represents a logical AND of the provided filters.
func NewAndFilterBoolValue(filters ...Filter) FilterBoolValue {
	fg := FilterBoolValue{
		and: filters,
	}
	if len(fg.and) == 0 {
		fg.and = nil
	}
	return fg
}

// NewOrFilterBoolValue returns a new FilterBoolValue that represents a logical OR of the provided filters.
func NewOrFilterBoolValue(filters ...Filter) FilterBoolValue {
	fg := FilterBoolValue{
		or: filters,
	}
	if len(fg.or) == 0 {
		fg.or = nil
	}
	return fg
}

// NewSearchFilterBoolValue )returns a new search filter criterion with a boolean type search value.
func NewSearchFilterBoolValue(field, searchType string, value bool) Filter {
	return FilterBoolValue{
		searchField: field,
		searchType:  searchType,
		searchValue: value,
	}
}

// AddAnd appends filters to the And slice of a FilterBoolValue.
func (f *FilterBoolValue) AddAnd(filters ...Filter) {
	f.and = append(f.and, filters...)
}

// AddOr appends filters to the Or slice of a FilterBoolValue.
func (f *FilterBoolValue) AddOr(filters ...Filter) {
	f.or = append(f.or, filters...)
}

func (f FilterBoolValue) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		And         []Filter `json:"AND,omitempty"`
		Or          []Filter `json:"OR,omitempty"`
		SearchField string   `json:"SEARCH_FIELD,omitempty"`
		SearchType  string   `json:"SEARCH_TYPE,omitempty"`
		SearchValue bool     `json:"SEARCH_VALUE,omitempty"`
	}{
		And:         f.and,
		Or:          f.or,
		SearchField: f.searchField,
		SearchType:  f.searchType,
		SearchValue: f.searchValue,
	})
}

func (f *FilterBoolValue) UnmarshalJSON(b []byte) error {
	var raw struct {
		And         []json.RawMessage `json:"AND,omitempty"`
		Or          []json.RawMessage `json:"OR,omitempty"`
		SearchField string            `json:"SEARCH_FIELD,omitempty"`
		SearchType  string            `json:"SEARCH_TYPE,omitempty"`
		SearchValue bool              `json:"SEARCH_VALUE,omitempty"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return fmt.Errorf("failed to unmarshal raw generic filter: %w", err)
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
