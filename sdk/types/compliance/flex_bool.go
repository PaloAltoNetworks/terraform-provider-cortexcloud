// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package types

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// FlexBool is a boolean that can be unmarshaled from JSON booleans, strings ("true", "TRUE", "false", "FALSE", "1", "0"), or numbers.
type FlexBool bool

// Bool returns the underlying bool value.
func (b FlexBool) Bool() bool {
	return bool(b)
}

// UnmarshalJSON implements json.Unmarshaler.
func (b *FlexBool) UnmarshalJSON(data []byte) error {
	// Try standard bool first
	var boolVal bool
	if err := json.Unmarshal(data, &boolVal); err == nil {
		*b = FlexBool(boolVal)
		return nil
	}

	// Try string
	var strVal string
	if err := json.Unmarshal(data, &strVal); err == nil {
		strVal = strings.TrimSpace(strings.ToLower(strVal))
		switch strVal {
		case "true", "yes", "1", "t", "y":
			*b = true
			return nil
		case "false", "no", "0", "f", "n", "":
			*b = false
			return nil
		default:
			parsed, err := strconv.ParseBool(strVal)
			if err != nil {
				return fmt.Errorf("cannot unmarshal string %q into FlexBool: %w", strVal, err)
			}
			*b = FlexBool(parsed)
			return nil
		}
	}

	// Try integer/number (e.g. 1 or 0)
	var intVal int
	if err := json.Unmarshal(data, &intVal); err == nil {
		*b = FlexBool(intVal != 0)
		return nil
	}

	return fmt.Errorf("cannot unmarshal %s into FlexBool", string(data))
}

// MarshalJSON implements json.Marshaler.
func (b FlexBool) MarshalJSON() ([]byte, error) {
	return json.Marshal(bool(b))
}
