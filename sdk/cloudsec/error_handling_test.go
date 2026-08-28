// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package cloudsec

//import (
//	"encoding/json"
//	"fmt"
//	"strings"
//	"testing"
//
//	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/errors"
//)

//// TestMapError_NilError tests that mapError returns nil for nil input
//func TestMapError_NilError(t *testing.T) {
//	result := mapError(nil)
//	if result != nil {
//		t.Errorf("mapError(nil) = %v, want nil", result)
//	}
//}
//
//// TestMapError_NonAPIError tests that mapError passes through non-API errors unchanged
//func TestMapError_NonAPIError(t *testing.T) {
//	originalErr := errors.NewInternalSDKError("TEST_ERROR", "test error", nil)
//	result := mapError(originalErr)
//
//	if result != originalErr {
//		t.Errorf("mapError should return original error for non-API errors")
//	}
//}
//
//// TestMapError_ReplyBasedError tests error conversion for reply-based API errors
//// This matches the error format from the OpenAPI spec with err_code, err_msg, err_extra
//func TestMapError_ReplyBasedError(t *testing.T) {
//	tests := []struct {
//		name            string
//		jsonError       string
//		wantContains    []string
//		wantNotContains []string
//	}{
//		{
//			name: "validation error with array format",
//			jsonError: `{
//				"reply": {
//					"err_code": 400,
//					"err_msg": "The request contains invalid or missing parameters",
//					"err_extra": [
//						{
//							"type": "missing",
//							"loc": ["body", "name"],
//							"msg": "Field cannot be empty",
//							"input": null
//						},
//						{
//							"type": "value_error",
//							"loc": ["body", "severity"],
//							"msg": "Invalid severity value. Must be one of: low, medium, high, critical, informational",
//							"input": "invalid"
//						}
//					]
//				}
//			}`,
//			wantContains: []string{
//				"Error Code: 400",
//				"Error Message: The request contains invalid or missing parameters",
//				"Error Details:",
//				"Type: \"missing\"",
//				"Location: [\"body\", \"name\"]",
//				"Message: \"Field cannot be empty\"",
//				"Type: \"value_error\"",
//				"Invalid severity value",
//			},
//		},
//		{
//			name: "validation error with string format",
//			jsonError: `{
//				"reply": {
//					"err_code": 400,
//					"err_msg": "The request contains invalid or missing parameters",
//					"err_extra": "Missing at least one required parameter: ['query.xql']"
//				}
//			}`,
//			wantContains: []string{
//				"Error Code: 400",
//				"Error Message: The request contains invalid or missing parameters",
//				"Error Details:",
//				"Missing at least one required parameter",
//			},
//		},
//		{
//			name: "conflict error - duplicate rule name",
//			jsonError: `{
//				"reply": {
//					"err_code": 409,
//					"err_msg": "A detection rule with the same name already exists",
//					"err_extra": [
//						{
//							"type": "conflict",
//							"loc": ["body", "name"],
//							"msg": "Rule name must be unique",
//							"input": "Duplicate Rule Name"
//						}
//					]
//				}
//			}`,
//			wantContains: []string{
//				"Error Code: 409",
//				"A detection rule with the same name already exists",
//				"Rule name must be unique",
//			},
//		},
//		{
//			name: "not found error",
//			jsonError: `{
//				"reply": {
//					"err_code": 404,
//					"err_msg": "Detection rule not found",
//					"err_extra": [
//						{
//							"type": "not_found",
//							"loc": ["path", "id"],
//							"msg": "No rule found with the specified ID",
//							"input": "invalid-uuid"
//						}
//					]
//				}
//			}`,
//			wantContains: []string{
//				"Error Code: 404",
//				"Detection rule not found",
//				"No rule found with the specified ID",
//			},
//		},
//	}
//
//	for _, tt := range tests {
//		t.Run(tt.name, func(t *testing.T) {
//			var apiErr errors.CortexCloudAPIError
//			if err := json.Unmarshal([]byte(tt.jsonError), &apiErr); err != nil {
//				t.Fatalf("Failed to unmarshal test error: %v", err)
//			}
//
//			result := mapError(&apiErr)
//			if result == nil {
//				t.Fatal("mapError returned nil for API error")
//			}
//
//			errStr := result.Error()
//
//			// Check that all expected strings are present
//			for _, want := range tt.wantContains {
//				if !strings.Contains(errStr, want) {
//					t.Errorf("Error string missing expected content:\nWant: %q\nGot: %s", want, errStr)
//				}
//			}
//
//			// Check that unwanted strings are not present
//			for _, notWant := range tt.wantNotContains {
//				if strings.Contains(errStr, notWant) {
//					t.Errorf("Error string contains unexpected content:\nDon't want: %q\nGot: %s", notWant, errStr)
//				}
//			}
//		})
//	}
//}
//
//// TestMapError_DataMetadataError tests error conversion for data+metadata format
//// This is the newer CloudSec error format with err_msg at data level and metadata
//func TestMapError_DataMetadataError(t *testing.T) {
//	tests := []struct {
//		name         string
//		jsonError    string
//		wantContains []string
//	}{
//		{
//			name: "validation error with metadata",
//			jsonError: `{
//				"data": {
//					"err_msg": "The request contains invalid or missing parameters",
//					"metadata": {
//						"err_code": 400,
//						"err_extra": [
//							{
//								"type": "missing",
//								"loc": ["body", "asset_types"],
//								"msg": "Field required - Only single asset type must be provided",
//								"input": null
//							}
//						]
//					}
//				}
//			}`,
//			wantContains: []string{
//				"Error Code: 400",
//				"Error Message: The request contains invalid or missing parameters",
//				"Field required - Only single asset type must be provided",
//			},
//		},
//		{
//			name: "invalid XQL query syntax",
//			jsonError: `{
//				"data": {
//					"err_msg": "The request contains invalid or missing parameters",
//					"metadata": {
//						"err_code": 400,
//						"err_extra": [
//							{
//								"type": "value_error",
//								"loc": ["body", "query", "xql"],
//								"msg": "Invalid XQL query syntax: Expected 'config from' or 'event from' at the beginning of the query",
//								"input": "invalid query"
//							}
//						]
//					}
//				}
//			}`,
//			wantContains: []string{
//				"Error Code: 400",
//				"Invalid XQL query syntax",
//				"Expected 'config from' or 'event from'",
//			},
//		},
//	}
//
//	for _, tt := range tests {
//		t.Run(tt.name, func(t *testing.T) {
//			var apiErr errors.CortexCloudAPIError
//			if err := json.Unmarshal([]byte(tt.jsonError), &apiErr); err != nil {
//				t.Fatalf("Failed to unmarshal test error: %v", err)
//			}
//
//			result := mapError(&apiErr)
//			if result == nil {
//				t.Fatal("mapError returned nil for API error")
//			}
//
//			errStr := result.Error()
//
//			for _, want := range tt.wantContains {
//				if !strings.Contains(errStr, want) {
//					t.Errorf("Error string missing expected content:\nWant: %q\nGot: %s", want, errStr)
//				}
//			}
//		})
//	}
//}
//
//// TestMapError_MultipleFieldErrors tests handling of multiple validation errors
//func TestMapError_MultipleFieldErrors(t *testing.T) {
//	jsonError := `{
//		"reply": {
//			"err_code": 400,
//			"err_msg": "The request contains invalid or missing parameters",
//			"err_extra": [
//				{
//					"type": "missing",
//					"loc": ["body", "name"],
//					"msg": "Field cannot be empty",
//					"input": null
//				},
//				{
//					"type": "missing",
//					"loc": ["body", "class"],
//					"msg": "Class cannot be empty",
//					"input": null
//				},
//				{
//					"type": "missing",
//					"loc": ["body", "asset_types"],
//					"msg": "Field required - Only single asset type must be provided",
//					"input": null
//				},
//				{
//					"type": "missing",
//					"loc": ["body", "severity"],
//					"msg": "Invalid severity value. Must be one of: low, medium, high, critical, informational",
//					"input": null
//				},
//				{
//					"type": "missing",
//					"loc": ["body", "query", "xql"],
//					"msg": "Field required - XQL query must be provided",
//					"input": null
//				}
//			]
//		}
//	}`
//
//	var apiErr errors.CortexCloudAPIError
//	if err := json.Unmarshal([]byte(jsonError), &apiErr); err != nil {
//		t.Fatalf("Failed to unmarshal test error: %v", err)
//	}
//
//	result := mapError(&apiErr)
//	if result == nil {
//		t.Fatal("mapError returned nil for API error")
//	}
//
//	errStr := result.Error()
//
//	// Verify all 5 field errors are present
//	expectedErrors := []string{
//		"Field cannot be empty",
//		"Class cannot be empty",
//		"Only single asset type must be provided",
//		"Invalid severity value",
//		"XQL query must be provided",
//	}
//
//	for _, expected := range expectedErrors {
//		if !strings.Contains(errStr, expected) {
//			t.Errorf("Error string missing field error: %q\nGot: %s", expected, errStr)
//		}
//	}
//
//	// Verify error count in output
//	errorDetailCount := strings.Count(errStr, "Type: \"missing\"")
//	if errorDetailCount != 5 {
//		t.Errorf("Expected 5 error details, found %d in output", errorDetailCount)
//	}
//}
//
//// TestMapError_ControlIDValidation tests control ID validation errors
//func TestMapError_ControlIDValidation(t *testing.T) {
//	jsonError := `{
//		"reply": {
//			"err_code": 400,
//			"err_msg": "The request contains invalid or missing parameters",
//			"err_extra": [
//				{
//					"type": "value_error",
//					"loc": ["body", "compliance_metadata", "0", "control_id"],
//					"msg": "Control ID does not exist",
//					"input": "INVALID-CONTROL-ID"
//				}
//			]
//		}
//	}`
//
//	var apiErr errors.CortexCloudAPIError
//	if err := json.Unmarshal([]byte(jsonError), &apiErr); err != nil {
//		t.Fatalf("Failed to unmarshal test error: %v", err)
//	}
//
//	result := mapError(&apiErr)
//	if result == nil {
//		t.Fatal("mapError returned nil for API error")
//	}
//
//	errStr := result.Error()
//
//	if !strings.Contains(errStr, "Control ID does not exist") {
//		t.Errorf("Error string should contain control ID validation message\nGot: %s", errStr)
//	}
//
//	if !strings.Contains(errStr, "compliance_metadata") {
//		t.Errorf("Error string should contain field location\nGot: %s", errStr)
//	}
//}
//
//// TestMapError_InternalServerError tests 500 error handling
//func TestMapError_InternalServerError(t *testing.T) {
//	jsonError := `{
//		"data": {
//			"err_msg": "Internal Server Error",
//			"metadata": {
//				"err_code": 500,
//				"err_extra": [
//					{
//						"type": "internal_error",
//						"loc": [],
//						"msg": "Internal Server Error",
//						"input": null
//					}
//				]
//			}
//		}
//	}`
//
//	var apiErr errors.CortexCloudAPIError
//	if err := json.Unmarshal([]byte(jsonError), &apiErr); err != nil {
//		t.Fatalf("Failed to unmarshal test error: %v", err)
//	}
//
//	result := mapError(&apiErr)
//	if result == nil {
//		t.Fatal("mapError returned nil for API error")
//	}
//
//	errStr := result.Error()
//
//	if !strings.Contains(errStr, "Error Code: 500") {
//		t.Errorf("Error string should contain 500 error code\nGot: %s", errStr)
//	}
//
//	if !strings.Contains(errStr, "Internal Server Error") {
//		t.Errorf("Error string should contain internal server error message\nGot: %s", errStr)
//	}
//}
//
//// TestMapError_ValueByReference tests that mapError works with error passed by reference
//func TestMapError_ValueByReference(t *testing.T) {
//	jsonError := `{
//		"reply": {
//			"err_code": 400,
//			"err_msg": "Bad Request",
//			"err_extra": "Test error message"
//		}
//	}`
//
//	var apiErr errors.CortexCloudAPIError
//	if err := json.Unmarshal([]byte(jsonError), &apiErr); err != nil {
//		t.Fatalf("Failed to unmarshal test error: %v", err)
//	}
//
//	// Test with pointer
//	resultPtr := mapError(&apiErr)
//	if resultPtr == nil {
//		t.Error("mapError returned nil for pointer to API error")
//	}
//
//	// Test with value
//	resultVal := mapError(apiErr)
//	if resultVal == nil {
//		t.Error("mapError returned nil for API error value")
//	}
//
//	// Both should produce the same error message
//	if resultPtr.Error() != resultVal.Error() {
//		t.Errorf("Error messages differ:\nPointer: %s\nValue: %s", resultPtr.Error(), resultVal.Error())
//	}
//}
//
//// TestMapError_PolicyAPIErrorFormats tests error handling for policy API specific error formats
//// as defined in openapiv2-policy.json
//func TestMapError_PolicyAPIErrorFormats(t *testing.T) {
//	tests := []struct {
//		name          string
//		inputError    error
//		shouldContain []string
//	}{
//		{
//			name: "Policy API - Data+Metadata format with err_extra array",
//			inputError: func() error {
//				// Create error with array of validation errors
//				errExtra := errors.ErrorExtraField{}
//				data := []byte(`[
//					{"type": "field_error", "msg": "Policy name must be unique", "loc": ["policy_name"]},
//					{"type": "field_error", "msg": "Severity must be one of: low, medium, high, critical", "loc": ["severity"]}
//				]`)
//				_ = errExtra.UnmarshalJSON(data)
//
//				return &errors.CortexCloudAPIError{
//					Data: &errors.CortexCloudAPIErrorData{
//						Message: "Invalid policy configuration",
//						Metadata: &errors.CortexCloudAPIErrorMetadata{
//							Code:  400,
//							Extra: errExtra,
//						},
//					},
//				}
//			}(),
//			shouldContain: []string{
//				"Invalid policy configuration",
//				"400",
//				"Policy name must be unique",
//				"Severity must be one of: low, medium, high, critical",
//			},
//		},
//		{
//			name: "Policy API - Data+Metadata format with err_extra string",
//			inputError: func() error {
//				// Create error with string err_extra
//				errExtra := errors.ErrorExtraField{}
//				data := []byte(`"The specified policy ID does not exist in the system"`)
//				_ = errExtra.UnmarshalJSON(data)
//
//				return &errors.CortexCloudAPIError{
//					Data: &errors.CortexCloudAPIErrorData{
//						Message: "Policy not found",
//						Metadata: &errors.CortexCloudAPIErrorMetadata{
//							Code:  404,
//							Extra: errExtra,
//						},
//					},
//				}
//			}(),
//			shouldContain: []string{
//				"Policy not found",
//				"404",
//				"The specified policy ID does not exist in the system",
//			},
//		},
//		{
//			name: "Policy API - Empty err_extra",
//			inputError: &errors.CortexCloudAPIError{
//				Data: &errors.CortexCloudAPIErrorData{
//					Message: "Operation failed",
//					Metadata: &errors.CortexCloudAPIErrorMetadata{
//						Code: 500,
//					},
//				},
//			},
//			shouldContain: []string{
//				"Operation failed",
//				"500",
//			},
//		},
//	}
//
//	for _, tt := range tests {
//		t.Run(tt.name, func(t *testing.T) {
//			result := mapError(tt.inputError)
//			if result == nil {
//				t.Fatal("Expected error, got nil")
//			}
//
//			errMsg := result.Error()
//			for _, expected := range tt.shouldContain {
//				if !strings.Contains(errMsg, expected) {
//					t.Errorf("Error message should contain %q, got: %s", expected, errMsg)
//				}
//			}
//		})
//	}
//}
//
//// TestMapError_RulesAPIErrorFormats tests error handling for rules API specific error formats
//// as defined in openapi-rule-management.yaml
//func TestMapError_RulesAPIErrorFormats(t *testing.T) {
//	tests := []struct {
//		name          string
//		inputError    error
//		shouldContain []string
//	}{
//		{
//			name: "Rules API - ValidationErrorResponse with field details",
//			inputError: func() error {
//				errExtra := errors.ErrorExtraField{}
//				data := []byte(`[
//					{"type": "value_error", "loc": ["body", "rule", "name"], "msg": "Rule name is required", "input": ""},
//					{"type": "type_error", "loc": ["body", "rule", "severity"], "msg": "Input should be a valid string", "input": 123}
//				]`)
//				_ = errExtra.UnmarshalJSON(data)
//
//				return &errors.CortexCloudAPIError{
//					Data: &errors.CortexCloudAPIErrorData{
//						Message: "Validation failed",
//						Metadata: &errors.CortexCloudAPIErrorMetadata{
//							Code:  400,
//							Extra: errExtra,
//						},
//					},
//				}
//			}(),
//			shouldContain: []string{
//				"Validation failed",
//				"400",
//				"Rule name is required",
//				"Input should be a valid string",
//			},
//		},
//		{
//			name: "Rules API - Control ID validation error",
//			inputError: func() error {
//				errExtra := errors.ErrorExtraField{}
//				data := []byte(`[
//					{"type": "validation_error", "loc": ["control_id"], "msg": "Control ID must match pattern: ^[A-Z0-9_]+$"}
//				]`)
//				_ = errExtra.UnmarshalJSON(data)
//
//				return &errors.CortexCloudAPIError{
//					Data: &errors.CortexCloudAPIErrorData{
//						Message: "Invalid control ID format",
//						Metadata: &errors.CortexCloudAPIErrorMetadata{
//							Code:  400,
//							Extra: errExtra,
//						},
//					},
//				}
//			}(),
//			shouldContain: []string{
//				"Invalid control ID format",
//				"400",
//				"Control ID must match pattern",
//			},
//		},
//		{
//			name: "Rules API - Multiple validation errors",
//			inputError: func() error {
//				errExtra := errors.ErrorExtraField{}
//				data := []byte(`[
//					{"type": "field_error", "loc": ["name"], "msg": "Name cannot be empty"},
//					{"type": "field_error", "loc": ["description"], "msg": "Description exceeds maximum length of 500 characters"},
//					{"type": "field_error", "loc": ["enabled"], "msg": "Enabled must be a boolean value"}
//				]`)
//				_ = errExtra.UnmarshalJSON(data)
//
//				return &errors.CortexCloudAPIError{
//					Data: &errors.CortexCloudAPIErrorData{
//						Message: "Multiple validation errors occurred",
//						Metadata: &errors.CortexCloudAPIErrorMetadata{
//							Code:  400,
//							Extra: errExtra,
//						},
//					},
//				}
//			}(),
//			shouldContain: []string{
//				"Multiple validation errors occurred",
//				"400",
//				"Name cannot be empty",
//				"Description exceeds maximum length",
//				"Enabled must be a boolean value",
//			},
//		},
//	}
//
//	for _, tt := range tests {
//		t.Run(tt.name, func(t *testing.T) {
//			result := mapError(tt.inputError)
//			if result == nil {
//				t.Fatal("Expected error, got nil")
//			}
//
//			errMsg := result.Error()
//			for _, expected := range tt.shouldContain {
//				if !strings.Contains(errMsg, expected) {
//					t.Errorf("Error message should contain %q, got: %s", expected, errMsg)
//				}
//			}
//		})
//	}
//}
//
//// TestMapError_AllThreeFormats tests that mapError handles all three error formats correctly
//func TestMapError_AllThreeFormats(t *testing.T) {
//	tests := []struct {
//		name          string
//		inputError    error
//		shouldContain []string
//		description   string
//	}{
//		{
//			name: "Format 1: Reply-based with err_extra array",
//			inputError: func() error {
//				errExtra := errors.ErrorExtraField{}
//				data := []byte(`[{"type": "auth_error", "msg": "Invalid API key", "loc": ["api_key"]}]`)
//				_ = errExtra.UnmarshalJSON(data)
//
//				return &errors.CortexCloudAPIError{
//					Reply: &errors.CortexCloudAPIErrorReply{
//						Code:    401,
//						Message: "Authentication failed",
//						Extra:   errExtra,
//					},
//				}
//			}(),
//			shouldContain: []string{"Authentication failed", "401", "Invalid API key"},
//			description:   "Reply-based format from legacy APIs",
//		},
//		{
//			name: "Format 2: Data+Metadata with err_extra string",
//			inputError: func() error {
//				errExtra := errors.ErrorExtraField{}
//				data := []byte(`"The requested resource does not exist"`)
//				_ = errExtra.UnmarshalJSON(data)
//
//				return &errors.CortexCloudAPIError{
//					Data: &errors.CortexCloudAPIErrorData{
//						Message: "Resource not found",
//						Metadata: &errors.CortexCloudAPIErrorMetadata{
//							Code:  404,
//							Extra: errExtra,
//						},
//					},
//				}
//			}(),
//			shouldContain: []string{"Resource not found", "404", "The requested resource does not exist"},
//			description:   "Data+Metadata format from modern APIs",
//		},
//		{
//			name: "Format 3: Fallback with Code/Message/Details",
//			inputError: func() error {
//				code := "INTERNAL_ERROR"
//				message := "An internal error occurred"
//				return &errors.CortexCloudAPIError{
//					Code:    &code,
//					Message: &message,
//					Details: &errors.CortexCloudAPIErrorDetails{
//						Params: errors.CortexCloudAPIErrorParams{
//							Message: "Please contact support if this persists",
//						},
//					},
//				}
//			}(),
//			shouldContain: []string{"An internal error occurred", "INTERNAL_ERROR", "Please contact support"},
//			description:   "Fallback format for generic errors",
//		},
//	}
//
//	for _, tt := range tests {
//		t.Run(tt.name, func(t *testing.T) {
//			result := mapError(tt.inputError)
//			if result == nil {
//				t.Fatalf("Expected error for %s, got nil", tt.description)
//			}
//
//			errMsg := result.Error()
//			for _, expected := range tt.shouldContain {
//				if !strings.Contains(errMsg, expected) {
//					t.Errorf("%s: Error message should contain %q, got: %s", tt.description, expected, errMsg)
//				}
//			}
//		})
//	}
//}
//
//// TestMapError_EdgeCases tests edge cases and boundary conditions
//func TestMapError_EdgeCases(t *testing.T) {
//	tests := []struct {
//		name        string
//		inputError  error
//		expectNil   bool
//		description string
//	}{
//		{
//			name:        "Nil error input",
//			inputError:  nil,
//			expectNil:   true,
//			description: "Should return nil for nil input",
//		},
//		{
//			name:        "Standard Go error",
//			inputError:  fmt.Errorf("standard error"),
//			expectNil:   false,
//			description: "Should pass through standard errors unchanged",
//		},
//		{
//			name: "Empty CortexCloudAPIError",
//			inputError: func() error {
//				code := ""
//				message := ""
//				return &errors.CortexCloudAPIError{
//					Code:    &code,
//					Message: &message,
//				}
//			}(),
//			expectNil:   false,
//			description: "Should handle empty API error gracefully",
//		},
//		{
//			name: "CortexCloudAPIError value (not pointer)",
//			inputError: func() error {
//				code := "TEST_ERROR"
//				message := "Test error message"
//				return errors.CortexCloudAPIError{
//					Code:    &code,
//					Message: &message,
//				}
//			}(),
//			expectNil:   false,
//			description: "Should handle value type CortexCloudAPIError",
//		},
//	}
//
//	for _, tt := range tests {
//		t.Run(tt.name, func(t *testing.T) {
//			result := mapError(tt.inputError)
//
//			if tt.expectNil {
//				if result != nil {
//					t.Errorf("%s: Expected nil, got: %v", tt.description, result)
//				}
//			} else {
//				if result == nil {
//					t.Errorf("%s: Expected error, got nil", tt.description)
//				}
//			}
//		})
//	}
//}
//
//// TestMapError_ProductionScenarios tests real-world production error scenarios
//func TestMapError_ProductionScenarios(t *testing.T) {
//	tests := []struct {
//		name          string
//		inputError    error
//		shouldContain []string
//		description   string
//	}{
//		{
//			name: "HTTP 500 Internal Server Error",
//			inputError: func() error {
//				errExtra := errors.ErrorExtraField{}
//				data := []byte(`"An unexpected error occurred. Request ID: req-12345"`)
//				_ = errExtra.UnmarshalJSON(data)
//
//				return &errors.CortexCloudAPIError{
//					Data: &errors.CortexCloudAPIErrorData{
//						Message: "Internal server error",
//						Metadata: &errors.CortexCloudAPIErrorMetadata{
//							Code:  500,
//							Extra: errExtra,
//						},
//					},
//				}
//			}(),
//			shouldContain: []string{"Internal server error", "500", "Request ID: req-12345"},
//			description:   "Server-side error with request tracking",
//		},
//		{
//			name: "HTTP 400 Bad Request with multiple field errors",
//			inputError: func() error {
//				errExtra := errors.ErrorExtraField{}
//				data := []byte(`[
//					{"type": "field_error", "loc": ["name"], "msg": "Name is required"},
//					{"type": "field_error", "loc": ["email"], "msg": "Invalid email format"},
//					{"type": "field_error", "loc": ["age"], "msg": "Age must be a positive integer"}
//				]`)
//				_ = errExtra.UnmarshalJSON(data)
//
//				return &errors.CortexCloudAPIError{
//					Data: &errors.CortexCloudAPIErrorData{
//						Message: "Bad request",
//						Metadata: &errors.CortexCloudAPIErrorMetadata{
//							Code:  400,
//							Extra: errExtra,
//						},
//					},
//				}
//			}(),
//			shouldContain: []string{"Bad request", "400", "Name is required", "Invalid email format", "Age must be a positive integer"},
//			description:   "Client-side validation errors",
//		},
//		{
//			name: "HTTP 403 Forbidden - Insufficient permissions",
//			inputError: func() error {
//				errExtra := errors.ErrorExtraField{}
//				data := []byte(`"User does not have permission to perform this action"`)
//				_ = errExtra.UnmarshalJSON(data)
//
//				return &errors.CortexCloudAPIError{
//					Reply: &errors.CortexCloudAPIErrorReply{
//						Code:    403,
//						Message: "Insufficient permissions",
//						Extra:   errExtra,
//					},
//				}
//			}(),
//			shouldContain: []string{"Insufficient permissions", "403", "User does not have permission"},
//			description:   "Authorization error",
//		},
//		{
//			name: "HTTP 404 Not Found - Resource missing",
//			inputError: func() error {
//				code := "NOT_FOUND"
//				message := "Rule not found"
//				return &errors.CortexCloudAPIError{
//					Code:    &code,
//					Message: &message,
//					Details: &errors.CortexCloudAPIErrorDetails{
//						Params: errors.CortexCloudAPIErrorParams{
//							Message: "Rule with ID 'rule-123' does not exist",
//						},
//					},
//				}
//			}(),
//			shouldContain: []string{"Rule not found", "NOT_FOUND", "rule-123"},
//			description:   "Resource not found error",
//		},
//		{
//			name: "HTTP 409 Conflict - Duplicate resource",
//			inputError: func() error {
//				errExtra := errors.ErrorExtraField{}
//				data := []byte(`"A rule with this name already exists"`)
//				_ = errExtra.UnmarshalJSON(data)
//
//				return &errors.CortexCloudAPIError{
//					Data: &errors.CortexCloudAPIErrorData{
//						Message: "Conflict",
//						Metadata: &errors.CortexCloudAPIErrorMetadata{
//							Code:  409,
//							Extra: errExtra,
//						},
//					},
//				}
//			}(),
//			shouldContain: []string{"Conflict", "409", "already exists"},
//			description:   "Resource conflict error",
//		},
//	}
//
//	for _, tt := range tests {
//		t.Run(tt.name, func(t *testing.T) {
//			result := mapError(tt.inputError)
//			if result == nil {
//				t.Fatalf("%s: Expected error, got nil", tt.description)
//			}
//
//			errMsg := result.Error()
//			for _, expected := range tt.shouldContain {
//				if !strings.Contains(errMsg, expected) {
//					t.Errorf("%s: Error message should contain %q, got: %s", tt.description, expected, errMsg)
//				}
//			}
//		})
//	}
//}
//
//// TestMapError_EmptyErrorExtra tests handling of empty err_extra
//func TestMapError_EmptyErrorExtra(t *testing.T) {
//	jsonError := `{
//		"reply": {
//			"err_code": 400,
//			"err_msg": "Bad Request",
//			"err_extra": []
//		}
//	}`
//
//	var apiErr errors.CortexCloudAPIError
//	if err := json.Unmarshal([]byte(jsonError), &apiErr); err != nil {
//		t.Fatalf("Failed to unmarshal test error: %v", err)
//	}
//
//	result := mapError(&apiErr)
//	if result == nil {
//		t.Fatal("mapError returned nil for API error")
//	}
//
//	errStr := result.Error()
//
//	// Should still contain error code and message even with empty err_extra
//	if !strings.Contains(errStr, "Error Code: 400") {
//		t.Errorf("Error string should contain error code\nGot: %s", errStr)
//	}
//
//	if !strings.Contains(errStr, "Bad Request") {
//		t.Errorf("Error string should contain error message\nGot: %s", errStr)
//	}
//}
