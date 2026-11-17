// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package util

import "testing"

func TestNormalizeControlLabel(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "empty", input: "", want: ""},
		{name: "whitespace only", input: "   \t ", want: ""},
		{name: "lower case words", input: "my custom category", want: "My Custom Category"},
		{name: "upper case words", input: "ACCESS CONTROL", want: "Access Control"},
		{name: "mixed case words", input: "aCcEsS cOnTrOl", want: "Access Control"},
		{name: "already normalized", input: "Access Control", want: "Access Control"},
		{name: "leading and trailing whitespace", input: "  padded value \n", want: "Padded Value"},
		{name: "inner whitespace preserved", input: "two  spaces", want: "Two  Spaces"},
		{name: "leading digits", input: "01.0 - access control", want: "01.0 - Access Control"},
		{name: "digits only", input: "5.1", want: "5.1"},
		{name: "single word", input: "iam", want: "Iam"},
		{name: "non ascii", input: "über sicherheit", want: "Über Sicherheit"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NormalizeControlLabel(tt.input); got != tt.want {
				t.Errorf("NormalizeControlLabel(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestNormalizeControlLabel_Idempotent(t *testing.T) {
	for _, in := range []string{"my custom category", "  PADDED  ", "01.0 - access control", ""} {
		once := NormalizeControlLabel(in)
		if twice := NormalizeControlLabel(once); twice != once {
			t.Errorf("not idempotent for %q: %q then %q", in, once, twice)
		}
	}
}

func TestEqualControlLabel(t *testing.T) {
	tests := []struct {
		name string
		a, b string
		want bool
	}{
		{name: "identical", a: "Access Control", b: "Access Control", want: true},
		{name: "case differs", a: "access control", b: "Access Control", want: true},
		{name: "whitespace differs", a: "  access control ", b: "Access Control", want: true},
		{name: "both empty", a: "", b: "", want: true},
		{name: "different text", a: "access control", b: "Network Security", want: false},
		{name: "empty vs value", a: "", b: "Access Control", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := EqualControlLabel(tt.a, tt.b); got != tt.want {
				t.Errorf("EqualControlLabel(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.want)
			}
		})
	}
}
