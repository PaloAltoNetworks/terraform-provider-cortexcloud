// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package types

import (
	"encoding/json"
	"fmt"
)

// FilterRoot represents the root of a filter tree.
// Its fields are unexported to enforce creation via constructors.
type FilterRoot struct {
	and []Filter
	or  []Filter
}

// Marker method for Filter interface compliance.
func (FilterRoot) isFilter() {}

// NewRootFilter returns a new FilterRoot that represents the root of a nested
// collection of filters.
func NewRootFilter(and []Filter, or []Filter) FilterRoot {
	fr := FilterRoot{
		and: and,
		or:  or,
	}
	if len(fr.and) == 0 {
		fr.and = nil
	}
	if len(fr.or) == 0 {
		fr.or = nil
	}
	return fr
}

// AddAnd appends filters to the And slice of a FilterRoot.
func (f *FilterRoot) AddAnd(filters ...Filter) {
	f.and = append(f.and, filters...)
}

// AddOr appends filters to the Or slice of a FilterRoot.
func (f *FilterRoot) AddOr(filters ...Filter) {
	f.or = append(f.or, filters...)
}

func (f FilterRoot) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		And []Filter `json:"AND,omitempty"`
		Or  []Filter `json:"OR,omitempty"`
	}{
		And: f.and,
		Or:  f.or,
	})
}

func (f *FilterRoot) UnmarshalJSON(b []byte) error {
	var raw struct {
		And []json.RawMessage `json:"AND,omitempty"`
		Or  []json.RawMessage `json:"OR,omitempty"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return fmt.Errorf("failed to unmarshal raw filter root: %w", err)
	}

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
