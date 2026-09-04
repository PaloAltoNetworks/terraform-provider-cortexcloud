// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package types

import (
	"encoding/json"
	"fmt"
)

type FilterData struct {
	Sort   []SortFilter `json:"sort,omitempty"`
	Paging PagingFilter `json:"paging"`
	Filter Filter       `json:"filter"`
}

type SortFilter struct {
	Field string `json:"FIELD"`
	Order string `json:"ORDER"`
}

type PagingFilter struct {
	From int `json:"from"`
	To   int `json:"to"`
}

func (fd *FilterData) UnmarshalJSON(b []byte) error {
	type alias FilterData
	var raw struct {
		Filter json.RawMessage `json:"filter"`
		alias
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return fmt.Errorf("failed to unmarshal raw filter data: %w", err)
	}

	*fd = FilterData(raw.alias)
	if raw.Filter != nil {
		var err error
		fd.Filter, err = unmarshalFilter(raw.Filter)
		if err != nil {
			return fmt.Errorf("failed to unmarshal nested filter: %w", err)
		}
	}
	return nil
}
