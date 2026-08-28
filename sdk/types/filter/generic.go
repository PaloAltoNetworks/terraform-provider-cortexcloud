// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package types

import (
	"encoding/json"
	"fmt"
)

// FilterGeneric represents a generic search criterion or a nested logical block.
// Its fields are unexported to enforce creation via constructors.
type FilterGeneric struct {
	and         []Filter
	or          []Filter
	searchField string
	searchType  string
	searchValue string
}

// Marker method for Filter interface compliance.
func (FilterGeneric) isFilter() {}

// NewAndFilter returns a new FilterGeneric that represents a logical AND of the provided filters.
func NewAndFilter(filters ...Filter) FilterGeneric {
	fg := FilterGeneric{
		and: filters,
	}
	if len(fg.and) == 0 {
		fg.and = nil
	}
	return fg
}

// NewOrFilter returns a new FilterGeneric that represents a logical OR of the provided filters.
func NewOrFilter(filters ...Filter) FilterGeneric {
	fg := FilterGeneric{
		or: filters,
	}
	if len(fg.or) == 0 {
		fg.or = nil
	}
	return fg
}

// NewSearchFilter returns a new search filter criterion.
func NewSearchFilter(field, searchType, value string) Filter {
	return FilterGeneric{
		searchField: field,
		searchType:  searchType,
		searchValue: value,
	}
}

// AddAnd appends filters to the And slice of a FilterGeneric.
func (f *FilterGeneric) AddAnd(filters ...Filter) {
	f.and = append(f.and, filters...)
}

// AddOr appends filters to the Or slice of a FilterGeneric.
func (f *FilterGeneric) AddOr(filters ...Filter) {
	f.or = append(f.or, filters...)
}

func (f FilterGeneric) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		And         []Filter `json:"AND,omitempty"`
		Or          []Filter `json:"OR,omitempty"`
		SearchField string   `json:"SEARCH_FIELD,omitempty"`
		SearchType  string   `json:"SEARCH_TYPE,omitempty"`
		SearchValue string   `json:"SEARCH_VALUE,omitempty"`
	}{
		And:         f.and,
		Or:          f.or,
		SearchField: f.searchField,
		SearchType:  f.searchType,
		SearchValue: f.searchValue,
	})
}

func (f *FilterGeneric) UnmarshalJSON(b []byte) error {
	var raw struct {
		And         []json.RawMessage `json:"AND,omitempty"`
		Or          []json.RawMessage `json:"OR,omitempty"`
		SearchField string            `json:"SEARCH_FIELD,omitempty"`
		SearchType  string            `json:"SEARCH_TYPE,omitempty"`
		SearchValue string            `json:"SEARCH_VALUE,omitempty"`
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
