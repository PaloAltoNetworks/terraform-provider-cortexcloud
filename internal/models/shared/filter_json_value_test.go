// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package models

import (
	"context"
	"encoding/json"
	"testing"

	filterTypes "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/types/filter"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// jsonWildcardModel builds the following JSON wildcard configuration:
//
//	search_field = "xdm.asset.tags"
//	search_type  = "JSON_WILDCARD"
//	search_value = jsonencode({ key = "application", value = "databricks" })
func jsonWildcardModel() *RootFilterModel {
	return &RootFilterModel{
		And: []NestedFilterModel{
			{
				SearchField: types.StringValue("xdm.asset.tags"),
				SearchType:  types.StringValue("JSON_WILDCARD"),
				SearchValue: types.StringValue(`{"key":"application","value":"databricks"}`),
			},
		},
	}
}

// TestRootModelToSDKFilter_JSONWildcardSendsObject is the regression test for
// a JSON_WILDCARD search value must reach the API as a native JSON
// object, not as a JSON-encoded string.
func TestRootModelToSDKFilter_JSONWildcardSendsObject(t *testing.T) {
	sdkFilter := RootModelToSDKFilter(context.Background(), jsonWildcardModel())

	b, err := json.Marshal(sdkFilter)
	if err != nil {
		t.Fatalf("failed to marshal SDK filter: %v", err)
	}

	var got struct {
		And []struct {
			SearchField string          `json:"SEARCH_FIELD"`
			SearchType  string          `json:"SEARCH_TYPE"`
			SearchValue json.RawMessage `json:"SEARCH_VALUE"`
		} `json:"AND"`
	}
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("failed to unmarshal marshalled filter: %v", err)
	}

	if len(got.And) != 1 {
		t.Fatalf("expected 1 AND criterion, got %d (payload: %s)", len(got.And), b)
	}

	raw := got.And[0].SearchValue
	if len(raw) == 0 || raw[0] != '{' {
		t.Fatalf("expected SEARCH_VALUE to be a JSON object, got %s (payload: %s)", raw, b)
	}

	var value map[string]string
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatalf("SEARCH_VALUE is not a JSON object: %v (payload: %s)", err, b)
	}
	if value["key"] != "application" || value["value"] != "databricks" {
		t.Errorf("unexpected SEARCH_VALUE contents: %v", value)
	}
}

// jsonWildcardNotModel builds the negated JSON wildcard configuration:
//
//	search_field = "xdm.image.labels"
//	search_type  = "JSON_WILDCARD_NOT"
//	search_value = jsonencode({ key = "BREAKPRISMA", value = "exception" })
func jsonWildcardNotModel() *RootFilterModel {
	return &RootFilterModel{
		And: []NestedFilterModel{
			{
				SearchField: types.StringValue("xdm.image.labels"),
				SearchType:  types.StringValue("JSON_WILDCARD_NOT"),
				SearchValue: types.StringValue(`{"key":"BREAKPRISMA","value":"exception"}`),
			},
		},
	}
}

// TestRootModelToSDKFilter_JSONWildcardNotSendsObject is the regression test
// for JSON_WILDCARD_NOT support. JSON_WILDCARD_NOT was missing from the JSON-valued search
// type set, so its object-valued SEARCH_VALUE was sent as a JSON-encoded
// string. Consumers of the resulting scope, such as the CWP policy evaluator,
// then failed to unmarshal it and skipped issue creation entirely.
func TestRootModelToSDKFilter_JSONWildcardNotSendsObject(t *testing.T) {
	sdkFilter := RootModelToSDKFilter(context.Background(), jsonWildcardNotModel())

	b, err := json.Marshal(sdkFilter)
	if err != nil {
		t.Fatalf("failed to marshal SDK filter: %v", err)
	}

	var got struct {
		And []struct {
			SearchField string          `json:"SEARCH_FIELD"`
			SearchType  string          `json:"SEARCH_TYPE"`
			SearchValue json.RawMessage `json:"SEARCH_VALUE"`
		} `json:"AND"`
	}
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("failed to unmarshal marshalled filter: %v", err)
	}

	if len(got.And) != 1 {
		t.Fatalf("expected 1 AND criterion, got %d (payload: %s)", len(got.And), b)
	}
	if got.And[0].SearchType != "JSON_WILDCARD_NOT" {
		t.Fatalf("expected SEARCH_TYPE JSON_WILDCARD_NOT, got %s", got.And[0].SearchType)
	}

	raw := got.And[0].SearchValue
	if len(raw) == 0 || raw[0] != '{' {
		t.Fatalf("expected SEARCH_VALUE to be a JSON object, got %s (payload: %s)", raw, b)
	}

	var value map[string]string
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatalf("SEARCH_VALUE is not a JSON object: %v (payload: %s)", err, b)
	}
	if value["key"] != "BREAKPRISMA" || value["value"] != "exception" {
		t.Errorf("unexpected SEARCH_VALUE contents: %v", value)
	}
}

// TestSDKToModel_JSONWildcardNotRoundTrip verifies that a negated JSON wildcard
// predicate is read back into an equal model, so no permanent diff is produced.
func TestSDKToModel_JSONWildcardNotRoundTrip(t *testing.T) {
	ctx := context.Background()
	original := jsonWildcardNotModel()

	b, err := json.Marshal(RootModelToSDKFilter(ctx, original))
	if err != nil {
		t.Fatalf("failed to marshal SDK filter: %v", err)
	}
	var remote filterTypes.FilterRoot
	if err := json.Unmarshal(b, &remote); err != nil {
		t.Fatalf("failed to unmarshal SDK filter: %v", err)
	}

	roundTripped := SDKToModel(ctx, remote)
	if roundTripped == nil {
		t.Fatal("SDKToModel returned nil; the predicate would be dropped from state")
	}
	if !original.Equals(roundTripped) {
		t.Error("round-tripped model does not equal the original; this would cause a permanent diff")
	}
}

// TestRootModelToSDKFilter_PlainStringUnchanged guards against behaviour
// changes for ordinary (non JSON-valued) search types.
func TestRootModelToSDKFilter_PlainStringUnchanged(t *testing.T) {
	model := &RootFilterModel{
		And: []NestedFilterModel{
			{
				SearchField: types.StringValue("xdm.asset.name"),
				SearchType:  types.StringValue("CONTAINS"),
				SearchValue: types.StringValue("prod"),
			},
		},
	}

	b, err := json.Marshal(RootModelToSDKFilter(context.Background(), model))
	if err != nil {
		t.Fatalf("failed to marshal SDK filter: %v", err)
	}

	expected := `{"AND":[{"SEARCH_FIELD":"xdm.asset.name","SEARCH_TYPE":"CONTAINS","SEARCH_VALUE":"prod"}]}`
	if string(b) != expected {
		t.Errorf("expected %s, got %s", expected, b)
	}
}

// TestRootModelToSDKFilter_JSONStringValueForPlainTypeStaysString ensures the
// constructor is chosen by search type, not by whether the value happens to
// look like JSON. A CONTAINS search for the literal text "{}" must stay a
// string.
func TestRootModelToSDKFilter_JSONStringValueForPlainTypeStaysString(t *testing.T) {
	model := &RootFilterModel{
		And: []NestedFilterModel{
			{
				SearchField: types.StringValue("xdm.asset.name"),
				SearchType:  types.StringValue("CONTAINS"),
				SearchValue: types.StringValue(`{"looks":"like json"}`),
			},
		},
	}

	b, err := json.Marshal(RootModelToSDKFilter(context.Background(), model))
	if err != nil {
		t.Fatalf("failed to marshal SDK filter: %v", err)
	}

	var got struct {
		And []struct {
			SearchValue json.RawMessage `json:"SEARCH_VALUE"`
		} `json:"AND"`
	}
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("failed to unmarshal marshalled filter: %v", err)
	}
	if got.And[0].SearchValue[0] != '"' {
		t.Errorf("expected SEARCH_VALUE to remain a JSON string, got %s", got.And[0].SearchValue)
	}
}

// TestRootModelToSDKFilter_InvalidJSONFallsBackToString ensures a malformed
// JSON search value degrades to the previous string behaviour rather than
// producing an invalid request body.
func TestRootModelToSDKFilter_InvalidJSONFallsBackToString(t *testing.T) {
	model := &RootFilterModel{
		And: []NestedFilterModel{
			{
				SearchField: types.StringValue("xdm.asset.tags"),
				SearchType:  types.StringValue("JSON_WILDCARD"),
				SearchValue: types.StringValue(`{not valid json`),
			},
		},
	}

	b, err := json.Marshal(RootModelToSDKFilter(context.Background(), model))
	if err != nil {
		t.Fatalf("failed to marshal SDK filter: %v", err)
	}
	if !json.Valid(b) {
		t.Fatalf("produced invalid JSON: %s", b)
	}

	var got struct {
		And []struct {
			SearchValue json.RawMessage `json:"SEARCH_VALUE"`
		} `json:"AND"`
	}
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("failed to unmarshal marshalled filter: %v", err)
	}
	if got.And[0].SearchValue[0] != '"' {
		t.Errorf("expected fallback to a JSON string, got %s", got.And[0].SearchValue)
	}
}

// TestSDKToModel_JSONWildcardRoundTrip verifies that a predicate written with
// an object-valued SEARCH_VALUE is read back into an equal model, so no
// permanent diff is produced.
func TestSDKToModel_JSONWildcardRoundTrip(t *testing.T) {
	ctx := context.Background()
	original := jsonWildcardModel()

	sdkFilter := RootModelToSDKFilter(ctx, original)

	// Simulate the API response by round-tripping the request body through the
	// SDK's own decoder.
	b, err := json.Marshal(sdkFilter)
	if err != nil {
		t.Fatalf("failed to marshal SDK filter: %v", err)
	}
	var remote filterTypes.FilterRoot
	if err := json.Unmarshal(b, &remote); err != nil {
		t.Fatalf("failed to unmarshal SDK filter: %v", err)
	}

	roundTripped := SDKToModel(ctx, remote)
	if roundTripped == nil {
		t.Fatal("SDKToModel returned nil; the predicate would be dropped from state")
	}
	if len(roundTripped.And) != 1 {
		t.Fatalf("expected 1 AND criterion, got %d", len(roundTripped.And))
	}

	got := roundTripped.And[0].SearchValue.ValueString()
	if got != `{"key":"application","value":"databricks"}` {
		t.Errorf("unexpected round-tripped search_value: %s", got)
	}

	if !original.Equals(roundTripped) {
		t.Error("round-tripped model does not equal the original; this would cause a permanent diff")
	}
}

// TestSDKToModel_TimespanRoundTrip guards the pre-existing timespan behaviour.
func TestSDKToModel_TimespanRoundTrip(t *testing.T) {
	ctx := context.Background()

	sdkFilter := filterTypes.NewRootFilter(
		[]filterTypes.Filter{filterTypes.NewTimespanFilter("time", "RANGE", 100, 200)},
		nil,
	)

	b, err := json.Marshal(sdkFilter)
	if err != nil {
		t.Fatalf("failed to marshal SDK filter: %v", err)
	}
	var remote filterTypes.FilterRoot
	if err := json.Unmarshal(b, &remote); err != nil {
		t.Fatalf("failed to unmarshal SDK filter: %v", err)
	}

	model := SDKToModel(ctx, remote)
	if model == nil {
		t.Fatal("SDKToModel returned nil for a timespan filter")
	}
	if len(model.And) != 1 {
		t.Fatalf("expected 1 AND criterion, got %d", len(model.And))
	}
	if got := model.And[0].SearchValue.ValueString(); got != `{"from":100,"to":200}` {
		t.Errorf("unexpected timespan search_value: %s", got)
	}
}

func TestSearchValueToString(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "json string is unquoted", input: `"prod"`, want: "prod"},
		{name: "object is compacted", input: `{ "key" : "a" , "value" : "b" }`, want: `{"key":"a","value":"b"}`},
		{name: "array is compacted", input: `[ "a" , "b" ]`, want: `["a","b"]`},
		{name: "number is preserved", input: `42`, want: "42"},
		{name: "bool is preserved", input: `true`, want: "true"},
		{name: "empty input", input: "", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := searchValueToString(json.RawMessage(tt.input))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("expected %q, got %q", tt.want, got)
			}
		})
	}
}

func TestEqTFJSONOrString(t *testing.T) {
	tests := []struct {
		name       string
		searchType types.String
		a          types.String
		b          types.String
		want       bool
	}{
		{
			name:       "identical json objects for JSON-valued search type",
			searchType: types.StringValue("JSON_WILDCARD"),
			a:          types.StringValue(`{"key":"a","value":"b"}`),
			b:          types.StringValue(`{"key":"a","value":"b"}`),
			want:       true,
		},
		{
			name:       "json objects differing only in key order for JSON-valued search type",
			searchType: types.StringValue("JSON_WILDCARD"),
			a:          types.StringValue(`{"key":"a","value":"b"}`),
			b:          types.StringValue(`{"value":"b","key":"a"}`),
			want:       true,
		},
		{
			name:       "json objects differing only in whitespace for JSON-valued search type",
			searchType: types.StringValue("JSON_WILDCARD"),
			a:          types.StringValue(`{"key":"a"}`),
			b:          types.StringValue(`{ "key" : "a" }`),
			want:       true,
		},
		{
			name:       "json objects with different values for JSON-valued search type",
			searchType: types.StringValue("JSON_WILDCARD"),
			a:          types.StringValue(`{"key":"a"}`),
			b:          types.StringValue(`{"key":"z"}`),
			want:       false,
		},
		{
			name:       "plain strings remain case insensitive",
			searchType: types.StringValue("CONTAINS"),
			a:          types.StringValue("PROD"),
			b:          types.StringValue("prod"),
			want:       true,
		},
		{
			name:       "different plain strings",
			searchType: types.StringValue("CONTAINS"),
			a:          types.StringValue("prod"),
			b:          types.StringValue("dev"),
			want:       false,
		},
		{
			name:       "quoted values for non-JSON-valued search type stay case-insensitive strings",
			searchType: types.StringValue("CONTAINS"),
			a:          types.StringValue(`"PROD"`),
			b:          types.StringValue(`"prod"`),
			want:       true,
		},
		{
			name:       "large integers for non-JSON-valued search type are not compared as float64",
			searchType: types.StringValue("EQUALS"),
			a:          types.StringValue("9223372036854775807"),
			b:          types.StringValue("9223372036854775806"),
			want:       false,
		},
		{
			name:       "both null",
			searchType: types.StringValue("CONTAINS"),
			a:          types.StringNull(),
			b:          types.StringNull(),
			want:       true,
		},
		{
			name:       "null versus value",
			searchType: types.StringValue("JSON_WILDCARD"),
			a:          types.StringNull(),
			b:          types.StringValue(`{"key":"a"}`),
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := eqTFJSONOrString(tt.searchType, tt.a, tt.b); got != tt.want {
				t.Errorf("expected %v, got %v", tt.want, got)
			}
		})
	}
}
