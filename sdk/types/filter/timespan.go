// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package types

import (
	"encoding/json"
	"fmt"
)

// FilterTimespan represents a time-based search criterion.
// Its fields are unexported to enforce creation via constructors.
type FilterTimespan struct {
	and         []Filter
	or          []Filter
	searchField string
	searchType  string
	searchValue SearchValueTimespan
}

type SearchValueTimespan struct {
	From int `json:"from,omitempty"`
	To   int `json:"to,omitempty"`
}

// Marker method for Filter interface compliance.
func (FilterTimespan) isFilter() {}

// NewTimespanFilter returns a new timespan filter criterion.
func NewTimespanFilter(field, searchType string, from, to int) Filter {
	return FilterTimespan{
		searchField: field,
		searchType:  searchType,
		searchValue: SearchValueTimespan{
			From: from,
			To:   to,
		},
	}
}

// AddAnd appends filters to the And slice of a FilterTimespan.
func (f *FilterTimespan) AddAnd(filters ...Filter) {
	f.and = append(f.and, filters...)
}

// AddOr appends filters to the Or slice of a FilterTimespan.
func (f *FilterTimespan) AddOr(filters ...Filter) {
	f.or = append(f.or, filters...)
}

func (f FilterTimespan) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		And         []Filter            `json:"AND,omitempty"`
		Or          []Filter            `json:"OR,omitempty"`
		SearchField string              `json:"SEARCH_FIELD,omitempty"`
		SearchType  string              `json:"SEARCH_TYPE,omitempty"`
		SearchValue SearchValueTimespan `json:"SEARCH_VALUE"`
	}{
		And:         f.and,
		Or:          f.or,
		SearchField: f.searchField,
		SearchType:  f.searchType,
		SearchValue: f.searchValue,
	})
}

func (f *FilterTimespan) UnmarshalJSON(b []byte) error {
	var raw struct {
		And         []json.RawMessage   `json:"AND,omitempty"`
		Or          []json.RawMessage   `json:"OR,omitempty"`
		SearchField string              `json:"SEARCH_FIELD,omitempty"`
		SearchType  string              `json:"SEARCH_TYPE,omitempty"`
		SearchValue SearchValueTimespan `json:"SEARCH_VALUE"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return fmt.Errorf("failed to unmarshal raw timespan filter: %w", err)
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
