// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package util

import (
	"strings"
	"unicode"
)

// NormalizeControlLabel mirrors the normalization the Cortex Cloud API applies
// to the category and subcategory of a compliance control before storing it:
// leading and trailing whitespace is stripped, and every whitespace-delimited
// word is Title Cased (first letter upper case, remaining letters lower case).
//
// For example "  my custom CATEGORY " becomes "My Custom Category".
// Whitespace between words is preserved as-is.
func NormalizeControlLabel(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}

	var b strings.Builder
	b.Grow(len(s))

	startOfWord := true
	for _, r := range s {
		if unicode.IsSpace(r) {
			startOfWord = true
			b.WriteRune(r)
			continue
		}

		if startOfWord {
			b.WriteRune(unicode.ToUpper(r))
			startOfWord = false
			continue
		}

		b.WriteRune(unicode.ToLower(r))
	}

	return b.String()
}

// EqualControlLabel reports whether a and b refer to the same compliance
// control category or subcategory once the API's normalization is applied to
// both.
func EqualControlLabel(a, b string) bool {
	return NormalizeControlLabel(a) == NormalizeControlLabel(b)
}
