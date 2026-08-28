// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package types

import (
	"encoding/json"
	"fmt"
)

// unmarshalFilter determines the concrete type of a Filter from its JSON representation and unmarshals it.
func unmarshalFilter(b []byte) (Filter, error) {
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(b, &probe); err != nil {
		return nil, fmt.Errorf("failed to probe filter type: %w", err)
	}

	if _, ok := probe["SEARCH_FIELD"]; ok {
		if val, ok := probe["SEARCH_VALUE"]; ok && len(val) > 0 {
			if val[0] == '{' {
				var f FilterTimespan
				if err := json.Unmarshal(b, &f); err != nil {
					return nil, err
				}
				return f, nil
			} else if string(val) == "true" || string(val) == "false" {
				var f FilterBoolValue
				if err := json.Unmarshal(b, &f); err != nil {
					return nil, err
				}
				return f, nil
			}
		}
		var f FilterGeneric
		if err := json.Unmarshal(b, &f); err != nil {
			return nil, err
		}
		return f, nil
	}

	_, andOk := probe["AND"]
	_, orOk := probe["OR"]
	if andOk || orOk {
		var f FilterGeneric
		if err := json.Unmarshal(b, &f); err != nil {
			return nil, err
		}
		return f, nil
	}

	// Default to an empty generic filter.
	var f FilterGeneric
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, err
	}
	return f, nil
}
