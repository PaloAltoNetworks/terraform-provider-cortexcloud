// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package types

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFlexBool_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name     string
		json     string
		expected bool
	}{
		{"bool true", `true`, true},
		{"bool false", `false`, false},
		{"string true", `"true"`, true},
		{"string TRUE uppercase", `"TRUE"`, true},
		{"string false", `"false"`, false},
		{"string FALSE uppercase", `"FALSE"`, false},
		{"string yes", `"yes"`, true},
		{"string no", `"no"`, false},
		{"string 1", `"1"`, true},
		{"string 0", `"0"`, false},
		{"int 1", `1`, true},
		{"int 0", `0`, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var b FlexBool
			err := json.Unmarshal([]byte(tt.json), &b)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, b.Bool())
		})
	}
}
