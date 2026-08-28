// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package errors

import (
	"encoding/json"
	"testing"
)

// TestErrorExtraField_UnmarshalJSON_StringFormat tests unmarshaling when err_extra is a string
func TestErrorExtraField_UnmarshalJSON_StringFormat(t *testing.T) {
	tests := []struct {
		name        string
		jsonData    string
		wantLen     int
		wantMessage string
		wantType    string
	}{
		{
			name:        "non-empty string",
			jsonData:    `{"err_code": 400, "err_msg": "Bad Request", "err_extra": "Missing at least one required parameter: ['evaluation_frequency']."}`,
			wantLen:     1,
			wantMessage: "Missing at least one required parameter: ['evaluation_frequency'].",
			wantType:    "string_error",
		},
		{
			name:     "empty string",
			jsonData: `{"err_code": 400, "err_msg": "Bad Request", "err_extra": ""}`,
			wantLen:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var reply CortexCloudAPIErrorReply
			err := json.Unmarshal([]byte(tt.jsonData), &reply)
			if err != nil {
				t.Fatalf("Unmarshal failed: %v", err)
			}

			values := reply.Extra.Values()
			if len(values) != tt.wantLen {
				t.Errorf("Expected %d error extra values, got %d", tt.wantLen, len(values))
			}

			if tt.wantLen > 0 {
				if values[0].Message != tt.wantMessage {
					t.Errorf("Expected message %q, got %q", tt.wantMessage, values[0].Message)
				}
				if values[0].Type != tt.wantType {
					t.Errorf("Expected type %q, got %q", tt.wantType, values[0].Type)
				}
			}
		})
	}
}

// TestErrorExtraField_UnmarshalJSON_ArrayFormat tests unmarshaling when err_extra is an array
func TestErrorExtraField_UnmarshalJSON_ArrayFormat(t *testing.T) {
	tests := []struct {
		name     string
		jsonData string
		wantLen  int
	}{
		{
			name: "array with single object",
			jsonData: `{
				"err_code": 400,
				"err_msg": "Validation Error",
				"err_extra": [
					{
						"type": "missing",
						"loc": ["body", "name"],
						"msg": "Field required",
						"input": null
					}
				]
			}`,
			wantLen: 1,
		},
		{
			name: "array with multiple objects",
			jsonData: `{
				"err_code": 400,
				"err_msg": "Validation Error",
				"err_extra": [
					{
						"type": "missing",
						"loc": ["body", "name"],
						"msg": "Field required",
						"input": null
					},
					{
						"type": "string_too_short",
						"loc": ["body", "description"],
						"msg": "String should have at least 1 character",
						"input": "",
						"ctx": {"min_length": 1}
					}
				]
			}`,
			wantLen: 2,
		},
		{
			name:     "empty array",
			jsonData: `{"err_code": 400, "err_msg": "Bad Request", "err_extra": []}`,
			wantLen:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var reply CortexCloudAPIErrorReply
			err := json.Unmarshal([]byte(tt.jsonData), &reply)
			if err != nil {
				t.Fatalf("Unmarshal failed: %v", err)
			}

			values := reply.Extra.Values()
			if len(values) != tt.wantLen {
				t.Errorf("Expected %d error extra values, got %d", tt.wantLen, len(values))
			}
		})
	}
}

// TestErrorExtraField_UnmarshalJSON_ArrayFormatDetails tests array format with detailed validation
func TestErrorExtraField_UnmarshalJSON_ArrayFormatDetails(t *testing.T) {
	jsonData := `{
		"err_code": 400,
		"err_msg": "Validation Error",
		"err_extra": [
			{
				"type": "missing",
				"loc": ["body", "name"],
				"msg": "Field required",
				"input": null
			}
		]
	}`

	var reply CortexCloudAPIErrorReply
	err := json.Unmarshal([]byte(jsonData), &reply)
	if err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	values := reply.Extra.Values()
	if len(values) != 1 {
		t.Fatalf("Expected 1 error extra value, got %d", len(values))
	}

	extra := values[0]
	if extra.Type != "missing" {
		t.Errorf("Expected type 'missing', got %q", extra.Type)
	}
	if extra.Message != "Field required" {
		t.Errorf("Expected message 'Field required', got %q", extra.Message)
	}
	if len(extra.Location) != 2 {
		t.Errorf("Expected 2 location elements, got %d", len(extra.Location))
	}
}

// TestErrorExtraField_UnmarshalJSON_IntegerField tests array format with integer field
func TestErrorExtraField_UnmarshalJSON_IntegerField(t *testing.T) {
	jsonData := `{
		"err_msg": "The request contains invalid parameters",
		"metadata": {
			"err_extra": [
				{
					"field": 0,
					"message": "Input should be a valid UUID"
				},
				{
					"field": 1,
					"message": "Input should be a valid UUID"
				}
			]
		}
	}`

	var apiErr CortexCloudAPIError
	err := json.Unmarshal([]byte(jsonData), &apiErr)
	if err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if apiErr.Data == nil || apiErr.Data.Metadata == nil {
		// The structure might be parsed differently depending on how CortexCloudAPIError unmarshals.
		// Let's check if we can access the extra values via the Metadata field if it was populated directly
		// or if we need to check how it was unmarshaled.
		// Wait, CortexCloudAPIError has Data *CortexCloudAPIErrorData.
		// The JSON above matches the structure for Data/Metadata if we look at api.go:
		// type CortexCloudAPIErrorData struct { Message string; Metadata *CortexCloudAPIErrorMetadata }
		// But the JSON has "err_msg" and "metadata" at the top level, which matches CortexCloudAPIError struct fields:
		// ErrMsg *string `json:"err_msg,omitempty"`
		// Metadata *CortexCloudAPIErrorMetadata `json:"metadata,omitempty"`
	}

	if apiErr.Metadata == nil {
		t.Fatal("Expected Metadata to be populated")
	}

	values := apiErr.Metadata.Extra.Values()
	if len(values) != 2 {
		t.Fatalf("Expected 2 error extra values, got %d", len(values))
	}

	// Field is now 'any', so it should hold the float64 (default for JSON numbers) or int
	// We can check the string representation via appendExtraError logic or direct type assertion
	// json.Unmarshal unmarshals numbers to float64 by default for interface{}

	// Let's verify the Error() string output contains the field info
	errStr := apiErr.Error()
	if !contains(errStr, "Field: \"0\"") {
		t.Errorf("Error string should contain 'Field: \"0\"', got: %s", errStr)
	}
	if !contains(errStr, "Input should be a valid UUID") {
		t.Errorf("Error string should contain message, got: %s", errStr)
	}
}

// TestErrorExtraField_UnmarshalJSON_InvalidFormat tests error handling for invalid formats
func TestErrorExtraField_UnmarshalJSON_InvalidFormat(t *testing.T) {
	tests := []struct {
		name     string
		jsonData string
	}{
		{
			name:     "number format",
			jsonData: `{"err_code": 400, "err_msg": "Bad Request", "err_extra": 123}`,
		},
		{
			name:     "boolean format",
			jsonData: `{"err_code": 400, "err_msg": "Bad Request", "err_extra": true}`,
		},
		{
			name:     "object format",
			jsonData: `{"err_code": 400, "err_msg": "Bad Request", "err_extra": {"key": "value"}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var reply CortexCloudAPIErrorReply
			err := json.Unmarshal([]byte(tt.jsonData), &reply)
			if err == nil {
				t.Error("Expected unmarshal to fail for invalid format, but it succeeded")
			}
		})
	}
}

// TestErrorExtraField_MarshalJSON tests marshaling back to JSON
func TestErrorExtraField_MarshalJSON(t *testing.T) {
	tests := []struct {
		name     string
		field    ErrorExtraField
		wantJSON string
	}{
		{
			name: "array format",
			field: ErrorExtraField{
				values: []CortexCloudAPIErrorExtra{
					{
						Type:    "missing",
						Message: "Field required",
					},
				},
			},
			wantJSON: `[{"type":"missing","msg":"Field required","ctx":{}}]`,
		},
		{
			name: "empty array",
			field: ErrorExtraField{
				values: []CortexCloudAPIErrorExtra{},
			},
			wantJSON: `[]`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.field)
			if err != nil {
				t.Fatalf("Marshal failed: %v", err)
			}

			if string(data) != tt.wantJSON {
				t.Errorf("Expected JSON %q, got %q", tt.wantJSON, string(data))
			}
		})
	}
}

// TestCortexCloudAPIError_Error_StringFormat tests Error() method with string err_extra
func TestCortexCloudAPIError_Error_StringFormat(t *testing.T) {
	jsonData := `{
		"reply": {
			"err_code": 400,
			"err_msg": "The request contains invalid or missing parameters.",
			"err_extra": "Missing at least one required parameter: ['evaluation_frequency']."
		}
	}`

	var apiErr CortexCloudAPIError
	err := json.Unmarshal([]byte(jsonData), &apiErr)
	if err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	errStr := apiErr.Error()
	if errStr == "" {
		t.Error("Error() returned empty string")
	}

	// Verify the error string contains key information
	if !contains(errStr, "Error Code: 400") {
		t.Error("Error string should contain error code")
	}
	if !contains(errStr, "The request contains invalid or missing parameters.") {
		t.Error("Error string should contain error message")
	}
	if !contains(errStr, "Missing at least one required parameter") {
		t.Error("Error string should contain err_extra message")
	}
}

// TestCortexCloudAPIError_Error_ArrayFormat tests Error() method with array err_extra
func TestCortexCloudAPIError_Error_ArrayFormat(t *testing.T) {
	jsonData := `{
		"reply": {
			"err_code": 400,
			"err_msg": "Validation Error",
			"err_extra": [
				{
					"type": "missing",
					"loc": ["body", "name"],
					"msg": "Field required",
					"input": null
				}
			]
		}
	}`

	var apiErr CortexCloudAPIError
	err := json.Unmarshal([]byte(jsonData), &apiErr)
	if err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	errStr := apiErr.Error()
	if errStr == "" {
		t.Error("Error() returned empty string")
	}

	// Verify the error string contains key information
	if !contains(errStr, "Error Code: 400") {
		t.Error("Error string should contain error code")
	}
	if !contains(errStr, "Validation Error") {
		t.Error("Error string should contain error message")
	}
	if !contains(errStr, "Field required") {
		t.Error("Error string should contain validation message")
	}
}

// TestErrorExtraField_NullValue tests handling of null err_extra
func TestErrorExtraField_NullValue(t *testing.T) {
	jsonData := `{"err_code": 400, "err_msg": "Bad Request", "err_extra": null}`

	var reply CortexCloudAPIErrorReply
	err := json.Unmarshal([]byte(jsonData), &reply)
	if err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	values := reply.Extra.Values()
	if values != nil && len(values) != 0 {
		t.Errorf("Expected nil or empty slice for null err_extra, got %d values", len(values))
	}
}

// TestBackwardCompatibility tests that existing code patterns still work
func TestBackwardCompatibility(t *testing.T) {
	// Test that the Values() method returns a slice that can be ranged over
	jsonData := `{
		"err_code": 400,
		"err_msg": "Validation Error",
		"err_extra": [
			{
				"type": "missing",
				"loc": ["body", "name"],
				"msg": "Field required",
				"input": null
			}
		]
	}`

	var reply CortexCloudAPIErrorReply
	err := json.Unmarshal([]byte(jsonData), &reply)
	if err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	// This is the pattern used in the Error() method
	count := 0
	for _, extra := range reply.Extra.Values() {
		count++
		if extra.Type == "" {
			t.Error("Expected non-empty type")
		}
	}

	if count != 1 {
		t.Errorf("Expected to iterate over 1 item, got %d", count)
	}
}

// TestCortexCloudAPIError_Error_FallbackFormat tests Error() method with fallback format
func TestCortexCloudAPIError_Error_FallbackFormat(t *testing.T) {
	jsonData := `{
		"errorCode": "404",
		"message": "Resource not found",
		"details": {
			"params": {
				"message": "Policy ID not found"
			}
		}
	}`

	var apiErr CortexCloudAPIError
	err := json.Unmarshal([]byte(jsonData), &apiErr)
	if err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	errStr := apiErr.Error()
	if errStr == "" {
		t.Error("Error() returned empty string")
	}

	// Verify the error string contains key information
	if !contains(errStr, "Error Code: 404") {
		t.Error("Error string should contain error code")
	}
	if !contains(errStr, "Error Message: Resource not found") {
		t.Error("Error string should contain error message")
	}
	if !contains(errStr, "Policy ID not found") {
		t.Error("Error string should contain details message")
	}
}

// TestCortexCloudAPIError_Details_PerFieldMapShape exercises the AppSec-style
// 422 response where details is a map of "field path" -> { message: "..." }.
//
// Real example from POST /public_api/appsec/v1/policies on JP:
//
//	{
//	  "errorCode": "ValidateError",
//	  "message":   "Validation Failed",
//	  "details": {
//	    "policy.triggers.ciImage":       { "message": "'ciImage' is required" },
//	    "policy.triggers.imageRegistry": { "message": "'imageRegistry' is required" }
//	  }
//	}
func TestCortexCloudAPIError_Details_PerFieldMapShape(t *testing.T) {
	jsonData := `{
		"errorCode": "ValidateError",
		"message": "Validation Failed",
		"details": {
			"policy.triggers.ciImage":       { "message": "'ciImage' is required" },
			"policy.triggers.imageRegistry": { "message": "'imageRegistry' is required" }
		}
	}`

	var apiErr CortexCloudAPIError
	if err := json.Unmarshal([]byte(jsonData), &apiErr); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if apiErr.Details == nil {
		t.Fatal("Details was nil; expected populated Fields map")
	}
	if len(apiErr.Details.Fields) != 2 {
		t.Fatalf("expected 2 field entries, got %d", len(apiErr.Details.Fields))
	}
	if got := apiErr.Details.Fields["policy.triggers.ciImage"].Message; got != "'ciImage' is required" {
		t.Errorf("ciImage message: expected %q, got %q", "'ciImage' is required", got)
	}
	if got := apiErr.Details.Fields["policy.triggers.imageRegistry"].Message; got != "'imageRegistry' is required" {
		t.Errorf("imageRegistry message: expected %q, got %q", "'imageRegistry' is required", got)
	}

	errStr := apiErr.Error()
	for _, want := range []string{
		"Error Code: ValidateError",
		"Error Message: Validation Failed",
		"policy.triggers.ciImage",
		"'ciImage' is required",
		"policy.triggers.imageRegistry",
		"'imageRegistry' is required",
	} {
		if !contains(errStr, want) {
			t.Errorf("Error() missing %q in:\n%s", want, errStr)
		}
	}
}

// TestCortexCloudAPIErrorDetails_RoundTrip ensures both shapes survive marshal+unmarshal.
func TestCortexCloudAPIErrorDetails_RoundTrip(t *testing.T) {
	t.Run("params shape", func(t *testing.T) {
		original := CortexCloudAPIErrorDetails{
			Params: CortexCloudAPIErrorParams{Message: "foo"},
		}
		data, err := json.Marshal(original)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		var rt CortexCloudAPIErrorDetails
		if err := json.Unmarshal(data, &rt); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if rt.Params.Message != "foo" {
			t.Errorf("Params.Message: expected 'foo', got %q", rt.Params.Message)
		}
	})

	t.Run("fields map shape", func(t *testing.T) {
		original := CortexCloudAPIErrorDetails{
			Fields: map[string]CortexCloudAPIErrorParams{
				"a.b.c": {Message: "msg-1"},
				"x.y":   {Message: "msg-2"},
			},
		}
		data, err := json.Marshal(original)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		var rt CortexCloudAPIErrorDetails
		if err := json.Unmarshal(data, &rt); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if rt.Fields["a.b.c"].Message != "msg-1" {
			t.Errorf("Fields[a.b.c]: expected 'msg-1', got %q", rt.Fields["a.b.c"].Message)
		}
		if rt.Fields["x.y"].Message != "msg-2" {
			t.Errorf("Fields[x.y]: expected 'msg-2', got %q", rt.Fields["x.y"].Message)
		}
	})
}

// Helper function to check if a string contains a substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// TestHasContent verifies that HasContent correctly detects whether any
// known error field was populated during JSON unmarshaling.
func TestHasContent(t *testing.T) {
	t.Run("empty struct has no content", func(t *testing.T) {
		var e CortexCloudAPIError
		if e.HasContent() {
			t.Error("expected HasContent() == false for zero-value struct")
		}
	})

	t.Run("unrecognised JSON keys produce no content", func(t *testing.T) {
		// This is the exact scenario that caused the empty-error bug: the API
		// returns valid JSON with keys we don't map to any struct field.
		var e CortexCloudAPIError
		err := json.Unmarshal([]byte(`{"error":"something went wrong","status":400}`), &e)
		if err != nil {
			t.Fatalf("Unmarshal should succeed on valid JSON: %v", err)
		}
		if e.HasContent() {
			t.Error("expected HasContent() == false when JSON keys don't match struct fields")
		}
	})

	t.Run("empty JSON object produces no content", func(t *testing.T) {
		var e CortexCloudAPIError
		err := json.Unmarshal([]byte(`{}`), &e)
		if err != nil {
			t.Fatalf("Unmarshal should succeed on empty object: %v", err)
		}
		if e.HasContent() {
			t.Error("expected HasContent() == false for empty JSON object")
		}
	})

	t.Run("errorCode field produces content", func(t *testing.T) {
		var e CortexCloudAPIError
		_ = json.Unmarshal([]byte(`{"errorCode":"ValidateError","message":"Validation Failed"}`), &e)
		if !e.HasContent() {
			t.Error("expected HasContent() == true when errorCode is present")
		}
	})

	t.Run("reply field produces content", func(t *testing.T) {
		var e CortexCloudAPIError
		_ = json.Unmarshal([]byte(`{"reply":{"err_code":500,"err_msg":"Internal error"}}`), &e)
		if !e.HasContent() {
			t.Error("expected HasContent() == true when reply is present")
		}
	})

	t.Run("err_code field produces content", func(t *testing.T) {
		var e CortexCloudAPIError
		_ = json.Unmarshal([]byte(`{"err_code":400,"err_msg":"Bad Request"}`), &e)
		if !e.HasContent() {
			t.Error("expected HasContent() == true when err_code is present")
		}
	})

	t.Run("data field produces content", func(t *testing.T) {
		var e CortexCloudAPIError
		_ = json.Unmarshal([]byte(`{"data":{"err_msg":"something"}}`), &e)
		if !e.HasContent() {
			t.Error("expected HasContent() == true when data is present")
		}
	})
}
