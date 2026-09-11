// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package types

import (
	"encoding/json"
	"fmt"
)

// isTimespanValue reports whether an object-valued SEARCH_VALUE represents a
// timespan, i.e. an object whose only keys are "from" and/or "to".
//
// Other object shapes (for example the {"key": ..., "value": ...} payload used
// by JSON_WILDCARD and JSON_WILDCARD_NOT) must not be decoded as
// FilterTimespan, since doing so silently discards the value.
func isTimespanValue(val []byte) bool {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(val, &obj); err != nil {
		return false
	}
	if len(obj) == 0 {
		return false
	}
	for k := range obj {
		if k != "from" && k != "to" {
			return false
		}
	}
	return true
}

// unmarshalFilter determines the concrete type of a Filter from its JSON representation and unmarshals it.
func unmarshalFilter(b []byte) (Filter, error) {
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(b, &probe); err != nil {
		return nil, fmt.Errorf("failed to probe filter type: %w", err)
	}

	if _, ok := probe["SEARCH_FIELD"]; ok {
		if val, ok := probe["SEARCH_VALUE"]; ok && len(val) > 0 {
			switch {
			case val[0] == '{' && isTimespanValue(val):
				var f FilterTimespan
				if err := json.Unmarshal(b, &f); err != nil {
					return nil, err
				}
				return f, nil
			case val[0] == '{' || val[0] == '[':
				// Any other JSON object, plus JSON arrays, are preserved
				// verbatim so that native-JSON search values such as
				// JSON_WILDCARD and JSON_WILDCARD_NOT survive a round trip.
				var f FilterRawJSON
				if err := json.Unmarshal(b, &f); err != nil {
					return nil, err
				}
				return f, nil
			case string(val) == "true" || string(val) == "false":
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
