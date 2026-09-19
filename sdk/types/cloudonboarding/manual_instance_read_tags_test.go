// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package types

import (
	"encoding/json"
	"strings"
	"testing"
)

// The read endpoint reports custom_resources_tags in two different JSON shapes
// depending on whether the connector has any tags: an array when it does, and
// the object {} when it does not. Both were observed on a live tenant.
//
// These tests pin both shapes, and -- just as importantly -- pin that nothing
// else is tolerated. A decoder that accepted {} by accepting anything would
// pass every positive case here while silently swallowing a real change in the
// reply's shape.

func TestReadTagListDecodesThePopulatedArrayShape(t *testing.T) {
	t.Parallel()

	// Deliberately not in sorted order: the decoder must preserve what the
	// endpoint sent rather than impose an order of its own.
	const body = `[{"key":"zeta","value":"z"},{"key":"alpha","value":"a"}]`

	var got ReadTagList
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatalf("decoding a populated tag array failed: %v", err)
	}

	want := ReadTagList{
		{Key: "zeta", Value: "z"},
		{Key: "alpha", Value: "a"},
	}

	if len(got) != len(want) {
		t.Fatalf("decoded %d tags, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("tag %d is %+v, want %+v", i, got[i], want[i])
		}
	}
}

// TestReadTagListDecodesTheClearedObjectShape is the case the whole type exists
// for. A connector whose tags have been cleared reports an object where the
// array would be; a plain []Tag cannot decode it, and the connector becomes
// unreadable.
func TestReadTagListDecodesTheClearedObjectShape(t *testing.T) {
	t.Parallel()

	for _, body := range []string{`{}`, `null`, `  {}  `} {
		t.Run(strings.TrimSpace(body), func(t *testing.T) {
			var got ReadTagList
			if err := json.Unmarshal([]byte(body), &got); err != nil {
				t.Fatalf("decoding %s failed, so a cleared connector cannot be read: %v", body, err)
			}
			if len(got) != 0 {
				t.Errorf("decoded %s as %d tags, want none: %+v", body, len(got), got)
			}
		})
	}
}

// TestReadTagListStillRejectsUnexpectedShapes is the control.
//
// Without it, a decoder that returned nil for everything would satisfy every
// other test in this file. Tolerating {} must not widen into tolerating
// anything: a reply that changes shape for some other reason has to be
// reported, not read as "this connector has no tags".
func TestReadTagListStillRejectsUnexpectedShapes(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"a populated object":  `{"key":"env","value":"prod"}`,
		"a bare string":       `"managed_by=paloaltonetworks"`,
		"a number":            `42`,
		"a boolean":           `true`,
		"an array of strings": `["env","owner"]`,
		"malformed json":      `[{"key":`,
	}

	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			var got ReadTagList
			err := json.Unmarshal([]byte(body), &got)
			if err == nil {
				t.Errorf("decoding %s was accepted as %+v; an unexpected shape "+
					"must be reported rather than read as an absence of tags",
					body, got)
			}
		})
	}
}

// TestInstanceEditFieldsDecodesBothTagShapes exercises the field in the
// position it is actually used, rather than the type in isolation.
//
// The unit above could pass while the struct field kept a type that cannot
// decode {} -- this is what ties the two together.
func TestInstanceEditFieldsDecodesBothTagShapes(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		tagsJSON string
		wantTags int
	}{
		{"connector with tags", `[{"key":"env","value":"prod"}]`, 1},
		{"connector whose tags were cleared", `{}`, 0},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := `{"fields":{"instance_name":"probe","cloud_provider":"AWS",` +
				`"custom_resources_tags":` + tc.tagsJSON + `}}`

			var got GetEditInstanceDetailsResponse
			if err := json.Unmarshal([]byte(body), &got); err != nil {
				t.Fatalf("decoding the read reply failed: %v", err)
			}

			if len(got.Fields.CustomResourcesTags) != tc.wantTags {
				t.Errorf("decoded %d tags, want %d",
					len(got.Fields.CustomResourcesTags), tc.wantTags)
			}
			// A field decoded alongside the tags, to prove the reply was
			// actually parsed rather than silently left at its zero value.
			if got.Fields.InstanceName != "probe" {
				t.Errorf("instance_name is %q, want %q; the reply did not decode",
					got.Fields.InstanceName, "probe")
			}
		})
	}
}
