// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package models

import (
	"context"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func TestCoerceFilterValue(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected interface{}
	}{
		{
			name:     "positive integer",
			input:    "42",
			expected: int64(42),
		},
		{
			name:     "zero",
			input:    "0",
			expected: int64(0),
		},
		{
			name:     "negative integer",
			input:    "-1",
			expected: int64(-1),
		},
		{
			name:     "large epoch timestamp",
			input:    "1770000000000",
			expected: int64(1770000000000),
		},
		{
			name:     "plain string",
			input:    "hello",
			expected: "hello",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "float value stays as string",
			input:    "3.14",
			expected: "3.14",
		},
		{
			name:     "string with leading zeros",
			input:    "007",
			expected: int64(7),
		},
		{
			name:     "string with spaces",
			input:    " 42 ",
			expected: " 42 ",
		},
		{
			name:     "boolean-like string",
			input:    "true",
			expected: "true",
		},
		{
			name:     "uuid string",
			input:    "550e8400-e29b-41d4-a716-446655440000",
			expected: "550e8400-e29b-41d4-a716-446655440000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := coerceFilterValue(tt.input)
			if result != tt.expected {
				t.Errorf("coerceFilterValue(%q) = %v (%T), want %v (%T)",
					tt.input, result, result, tt.expected, tt.expected)
			}
		})
	}
}

// --- ToListRequest tests for all 3 data source models ---

// TestControlsToListRequest_NilFilter verifies that when no filter block is
// provided (Filter is nil), ToListRequest produces no filters and no errors.
func TestControlsToListRequest_NilFilter(t *testing.T) {
	ctx := context.Background()
	diags := diag.Diagnostics{}

	model := ControlsDataSourceModel{
		Filter: nil, // no filter block
	}

	req := model.ToListRequest(ctx, &diags)

	if diags.HasError() {
		t.Fatalf("expected no errors, got: %v", diags.Errors())
	}
	if len(req.Filters) != 0 {
		t.Errorf("expected 0 filters, got %d", len(req.Filters))
	}
}

// TestControlsToListRequest_CompleteFilter verifies that when all 3 filter
// fields are provided, ToListRequest produces the correct filter.
func TestControlsToListRequest_CompleteFilter(t *testing.T) {
	ctx := context.Background()
	diags := diag.Diagnostics{}

	model := ControlsDataSourceModel{
		Filter: &FilterModel{
			Field:    types.StringValue("name"),
			Operator: types.StringValue("eq"),
			Value:    types.StringValue("test-control"),
		},
	}

	req := model.ToListRequest(ctx, &diags)

	if diags.HasError() {
		t.Fatalf("expected no errors, got: %v", diags.Errors())
	}
	if len(req.Filters) != 1 {
		t.Fatalf("expected 1 filter, got %d", len(req.Filters))
	}
	if req.Filters[0].Field != "name" {
		t.Errorf("expected field 'name', got %q", req.Filters[0].Field)
	}
	if req.Filters[0].Operator != "eq" {
		t.Errorf("expected operator 'eq', got %q", req.Filters[0].Operator)
	}
	if req.Filters[0].Value != "test-control" {
		t.Errorf("expected value 'test-control', got %v", req.Filters[0].Value)
	}
}

// TestControlsToListRequest_PartialFilter verifies that when the filter block
// is present but only some fields are set, ToListRequest produces a diagnostic
// error that lists the missing fields.
func TestControlsToListRequest_PartialFilter(t *testing.T) {
	ctx := context.Background()
	diags := diag.Diagnostics{}

	model := ControlsDataSourceModel{
		Filter: &FilterModel{
			Field:    types.StringValue("name"),
			Operator: types.StringNull(),
			Value:    types.StringNull(),
		},
	}

	_ = model.ToListRequest(ctx, &diags)

	if !diags.HasError() {
		t.Fatal("expected a diagnostic error for partial filter, got none")
	}

	errDetail := diags.Errors()[0].Detail()
	if !strings.Contains(errDetail, "operator") {
		t.Errorf("expected error to mention missing 'operator', got: %s", errDetail)
	}
	if !strings.Contains(errDetail, "value") {
		t.Errorf("expected error to mention missing 'value', got: %s", errDetail)
	}
}

// TestStandardsToListRequest_NilFilter verifies that when no filter block is
// provided (Filter is nil), ToListRequest produces no filters and no errors.
func TestStandardsToListRequest_NilFilter(t *testing.T) {
	ctx := context.Background()
	diags := diag.Diagnostics{}

	model := StandardsDataSourceModel{
		Filter: nil,
	}

	req := model.ToListRequest(ctx, &diags)

	if diags.HasError() {
		t.Fatalf("expected no errors, got: %v", diags.Errors())
	}
	if len(req.Filters) != 0 {
		t.Errorf("expected 0 filters, got %d", len(req.Filters))
	}
}

// TestStandardsToListRequest_CompleteFilter verifies that when all 3 filter
// fields are provided, ToListRequest produces the correct filter.
func TestStandardsToListRequest_CompleteFilter(t *testing.T) {
	ctx := context.Background()
	diags := diag.Diagnostics{}

	model := StandardsDataSourceModel{
		Filter: &FilterModel{
			Field:    types.StringValue("name"),
			Operator: types.StringValue("contains"),
			Value:    types.StringValue("PCI"),
		},
	}

	req := model.ToListRequest(ctx, &diags)

	if diags.HasError() {
		t.Fatalf("expected no errors, got: %v", diags.Errors())
	}
	if len(req.Filters) != 1 {
		t.Fatalf("expected 1 filter, got %d", len(req.Filters))
	}
	if req.Filters[0].Field != "name" {
		t.Errorf("expected field 'name', got %q", req.Filters[0].Field)
	}
	if req.Filters[0].Operator != "contains" {
		t.Errorf("expected operator 'contains', got %q", req.Filters[0].Operator)
	}
	if req.Filters[0].Value != "PCI" {
		t.Errorf("expected value 'PCI', got %v", req.Filters[0].Value)
	}
}

// TestStandardsToListRequest_PartialFilter verifies that when the filter block
// is present but only some fields are set, ToListRequest produces a diagnostic
// error that lists the missing fields.
func TestStandardsToListRequest_PartialFilter(t *testing.T) {
	ctx := context.Background()
	diags := diag.Diagnostics{}

	model := StandardsDataSourceModel{
		Filter: &FilterModel{
			Field:    types.StringNull(),
			Operator: types.StringValue("eq"),
			Value:    types.StringNull(),
		},
	}

	_ = model.ToListRequest(ctx, &diags)

	if !diags.HasError() {
		t.Fatal("expected a diagnostic error for partial filter, got none")
	}

	errDetail := diags.Errors()[0].Detail()
	if !strings.Contains(errDetail, "field") {
		t.Errorf("expected error to mention missing 'field', got: %s", errDetail)
	}
	if !strings.Contains(errDetail, "value") {
		t.Errorf("expected error to mention missing 'value', got: %s", errDetail)
	}
}

// TestAssessmentProfilesToListRequest_NilFilter verifies that when no filter
// block is provided (Filter is nil), ToListRequest produces no filters and no errors.
func TestAssessmentProfilesToListRequest_NilFilter(t *testing.T) {
	ctx := context.Background()
	diags := diag.Diagnostics{}

	model := AssessmentProfilesDataSourceModel{
		Filter: nil,
	}

	req := model.ToListRequest(ctx, &diags)

	if diags.HasError() {
		t.Fatalf("expected no errors, got: %v", diags.Errors())
	}
	if len(req.Filters) != 0 {
		t.Errorf("expected 0 filters, got %d", len(req.Filters))
	}
}

// TestAssessmentProfilesToListRequest_CompleteFilter verifies that when all 3
// filter fields are provided, ToListRequest produces the correct filter.
func TestAssessmentProfilesToListRequest_CompleteFilter(t *testing.T) {
	ctx := context.Background()
	diags := diag.Diagnostics{}

	model := AssessmentProfilesDataSourceModel{
		Filter: &FilterModel{
			Field:    types.StringValue("name"),
			Operator: types.StringValue("eq"),
			Value:    types.StringValue("my-profile"),
		},
	}

	req := model.ToListRequest(ctx, &diags)

	if diags.HasError() {
		t.Fatalf("expected no errors, got: %v", diags.Errors())
	}
	if len(req.Filters) != 1 {
		t.Fatalf("expected 1 filter, got %d", len(req.Filters))
	}
	if req.Filters[0].Field != "name" {
		t.Errorf("expected field 'name', got %q", req.Filters[0].Field)
	}
	if req.Filters[0].Operator != "eq" {
		t.Errorf("expected operator 'eq', got %q", req.Filters[0].Operator)
	}
	if req.Filters[0].Value != "my-profile" {
		t.Errorf("expected value 'my-profile', got %v", req.Filters[0].Value)
	}
}

// TestAssessmentProfilesToListRequest_PartialFilter verifies that when the
// filter block is present but only some fields are set, ToListRequest produces
// a diagnostic error that lists the missing fields.
func TestAssessmentProfilesToListRequest_PartialFilter(t *testing.T) {
	ctx := context.Background()
	diags := diag.Diagnostics{}

	model := AssessmentProfilesDataSourceModel{
		Filter: &FilterModel{
			Field:    types.StringValue("name"),
			Operator: types.StringValue("eq"),
			Value:    types.StringNull(),
		},
	}

	_ = model.ToListRequest(ctx, &diags)

	if !diags.HasError() {
		t.Fatal("expected a diagnostic error for partial filter, got none")
	}

	errDetail := diags.Errors()[0].Detail()
	if !strings.Contains(errDetail, "value") {
		t.Errorf("expected error to mention missing 'value', got: %s", errDetail)
	}
}

// TestControlsToListRequest_AllFieldsNull verifies that when the filter block
// exists but all fields are null, it's treated as no filter (no error).
func TestControlsToListRequest_AllFieldsNull(t *testing.T) {
	ctx := context.Background()
	diags := diag.Diagnostics{}

	model := ControlsDataSourceModel{
		Filter: &FilterModel{
			Field:    types.StringNull(),
			Operator: types.StringNull(),
			Value:    types.StringNull(),
		},
	}

	req := model.ToListRequest(ctx, &diags)

	if diags.HasError() {
		t.Fatalf("expected no errors when all filter fields are null, got: %v", diags.Errors())
	}
	if len(req.Filters) != 0 {
		t.Errorf("expected 0 filters when all fields are null, got %d", len(req.Filters))
	}
}

// TestStandardsToListRequest_AllFieldsNull verifies that when the filter block
// exists but all fields are null, it's treated as no filter (no error).
func TestStandardsToListRequest_AllFieldsNull(t *testing.T) {
	ctx := context.Background()
	diags := diag.Diagnostics{}

	model := StandardsDataSourceModel{
		Filter: &FilterModel{
			Field:    types.StringNull(),
			Operator: types.StringNull(),
			Value:    types.StringNull(),
		},
	}

	req := model.ToListRequest(ctx, &diags)

	if diags.HasError() {
		t.Fatalf("expected no errors when all filter fields are null, got: %v", diags.Errors())
	}
	if len(req.Filters) != 0 {
		t.Errorf("expected 0 filters when all fields are null, got %d", len(req.Filters))
	}
}

// TestAssessmentProfilesToListRequest_AllFieldsNull verifies that when the
// filter block exists but all fields are null, it's treated as no filter (no error).
func TestAssessmentProfilesToListRequest_AllFieldsNull(t *testing.T) {
	ctx := context.Background()
	diags := diag.Diagnostics{}

	model := AssessmentProfilesDataSourceModel{
		Filter: &FilterModel{
			Field:    types.StringNull(),
			Operator: types.StringNull(),
			Value:    types.StringNull(),
		},
	}

	req := model.ToListRequest(ctx, &diags)

	if diags.HasError() {
		t.Fatalf("expected no errors when all filter fields are null, got: %v", diags.Errors())
	}
	if len(req.Filters) != 0 {
		t.Errorf("expected 0 filters when all fields are null, got %d", len(req.Filters))
	}
}

// Tests for is_custom field eq→in auto-conversion

func TestBuildFilters_IsCustomEqAutoConvertsToIn(t *testing.T) {
	ctx := context.Background()
	diags := diag.Diagnostics{}

	filter := &FilterModel{
		Field:    types.StringValue("is_custom"),
		Operator: types.StringValue("eq"),
		Value:    types.StringValue("true"),
	}

	filters := buildFilters(ctx, filter, &diags)

	// Should produce a warning but no error
	if diags.HasError() {
		t.Fatalf("expected no errors, got: %v", diags.Errors())
	}
	if len(diags.Warnings()) != 1 {
		t.Fatalf("expected 1 warning about auto-conversion, got %d", len(diags.Warnings()))
	}
	if !strings.Contains(diags.Warnings()[0].Detail(), "automatically changed to 'in'") {
		t.Errorf("expected warning about eq→in conversion, got: %s", diags.Warnings()[0].Detail())
	}

	if len(filters) != 1 {
		t.Fatalf("expected 1 filter, got %d", len(filters))
	}
	if filters[0].Operator != "in" {
		t.Errorf("expected operator 'in', got %q", filters[0].Operator)
	}
	// "in" operator should wrap value in array
	if arr, ok := filters[0].Value.([]string); !ok || len(arr) != 1 || arr[0] != "true" {
		t.Errorf("expected value []string{\"true\"}, got %v (%T)", filters[0].Value, filters[0].Value)
	}
}

func TestBuildFilters_IsCustomUpperCaseEqAutoConvertsToIn(t *testing.T) {
	ctx := context.Background()
	diags := diag.Diagnostics{}

	filter := &FilterModel{
		Field:    types.StringValue("IS_CUSTOM"),
		Operator: types.StringValue("eq"),
		Value:    types.StringValue("true"),
	}

	filters := buildFilters(ctx, filter, &diags)

	if diags.HasError() {
		t.Fatalf("expected no errors, got: %v", diags.Errors())
	}
	if len(filters) != 1 {
		t.Fatalf("expected 1 filter, got %d", len(filters))
	}
	if filters[0].Operator != "in" {
		t.Errorf("expected operator 'in' (auto-converted from 'eq'), got %q", filters[0].Operator)
	}
}

func TestBuildFilters_IsCustomInOperatorPassesThrough(t *testing.T) {
	ctx := context.Background()
	diags := diag.Diagnostics{}

	filter := &FilterModel{
		Field:    types.StringValue("is_custom"),
		Operator: types.StringValue("in"),
		Value:    types.StringValue("true"),
	}

	filters := buildFilters(ctx, filter, &diags)

	if diags.HasError() {
		t.Fatalf("expected no errors, got: %v", diags.Errors())
	}
	// No warning when user already uses "in"
	if len(diags.Warnings()) != 0 {
		t.Errorf("expected no warnings when using 'in' directly, got %d", len(diags.Warnings()))
	}
	if len(filters) != 1 {
		t.Fatalf("expected 1 filter, got %d", len(filters))
	}
	if filters[0].Operator != "in" {
		t.Errorf("expected operator 'in', got %q", filters[0].Operator)
	}
	if arr, ok := filters[0].Value.([]string); !ok || len(arr) != 1 || arr[0] != "true" {
		t.Errorf("expected value []string{\"true\"}, got %v (%T)", filters[0].Value, filters[0].Value)
	}
}

func TestStandardsToListRequest_IsCustomEqAutoConvertsToIn(t *testing.T) {
	ctx := context.Background()
	diags := diag.Diagnostics{}

	model := StandardsDataSourceModel{
		Filter: &FilterModel{
			Field:    types.StringValue("is_custom"),
			Operator: types.StringValue("eq"),
			Value:    types.StringValue("true"),
		},
	}

	req := model.ToListRequest(ctx, &diags)

	if diags.HasError() {
		t.Fatalf("expected no errors, got: %v", diags.Errors())
	}
	if len(req.Filters) != 1 {
		t.Fatalf("expected 1 filter, got %d", len(req.Filters))
	}
	if req.Filters[0].Operator != "in" {
		t.Errorf("expected operator 'in' (auto-converted from 'eq'), got %q", req.Filters[0].Operator)
	}
}

func TestControlsToListRequest_IsCustomEqAutoConvertsToIn(t *testing.T) {
	ctx := context.Background()
	diags := diag.Diagnostics{}

	model := ControlsDataSourceModel{
		Filter: &FilterModel{
			Field:    types.StringValue("is_custom"),
			Operator: types.StringValue("eq"),
			Value:    types.StringValue("true"),
		},
	}

	req := model.ToListRequest(ctx, &diags)

	if diags.HasError() {
		t.Fatalf("expected no errors, got: %v", diags.Errors())
	}
	if len(req.Filters) != 1 {
		t.Fatalf("expected 1 filter, got %d", len(req.Filters))
	}
	if req.Filters[0].Operator != "in" {
		t.Errorf("expected operator 'in' (auto-converted from 'eq'), got %q", req.Filters[0].Operator)
	}
}

func TestAssessmentProfilesToListRequest_IsCustomEqAutoConvertsToIn(t *testing.T) {
	ctx := context.Background()
	diags := diag.Diagnostics{}

	model := AssessmentProfilesDataSourceModel{
		Filter: &FilterModel{
			Field:    types.StringValue("is_custom"),
			Operator: types.StringValue("eq"),
			Value:    types.StringValue("true"),
		},
	}

	req := model.ToListRequest(ctx, &diags)

	if diags.HasError() {
		t.Fatalf("expected no errors, got: %v", diags.Errors())
	}
	if len(req.Filters) != 1 {
		t.Fatalf("expected 1 filter, got %d", len(req.Filters))
	}
	if req.Filters[0].Operator != "in" {
		t.Errorf("expected operator 'in' (auto-converted from 'eq'), got %q", req.Filters[0].Operator)
	}
}
