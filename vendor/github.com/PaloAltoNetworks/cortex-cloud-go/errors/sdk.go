// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

// Package errors provides a single, unified custom error type for the CortexCloud SDK,
// designed to encapsulate all error information, whether originating from an upstream API
// or from internal SDK operations.
package errors

import (
	"encoding/json"
	"errors" // Import the standard errors package for errors.As and errors.Unwrap
	"fmt"
	"net/http"
	"strings"
)

// CortexCloudSdkErrorDetail provides granular context about specific error instances,
// often used for validation errors or specific problem details within the main error.
type CortexCloudSdkErrorDetail struct {
	Location string `json:"location"`         // The path or field where the error occurred (e.g., "body.user_id").
	Code     string `json:"code"`             // A specific code for this detail (e.g., "INVALID_FORMAT").
	Message  string `json:"message"`          // A human-readable message for this specific detail.
	Error    error  `json:"underlying_error"` // The underlying Go error.
}

// CortexCloudSdkError represents a structured error within the CortexCloud SDK.
// It can represent errors returned by an upstream API (with HTTPStatus populated)
// or internal SDK errors (with HTTPStatus as nil).
type CortexCloudSdkError struct {
	Code                string                      `json:"code"`                  // A unique, machine-readable error code (e.g., "INVALID_ARGUMENT", "UNAUTHORIZED", "SDK_INIT_FAILED").
	Message             string                      `json:"message"`               // A human-readable message describing the error.
	Details             []CortexCloudSdkErrorDetail `json:"details"`               // Optional, additional context or validation errors.
	InternalErrorsCount int                         `json:"internal_errors_count"` // Total number of internal errors returned.
	HTTPStatus          *int                        `json:"http_status"`           // The HTTP status code associated with this error. This value is nil for internal errors.
	Err                 error                       `json:"underlying_error"`      // The underlying Go error returned by the validation module.
}

// Error implements the error interface for CortexCloudSdkError.
// It returns a formatted string representation of the error.
// TODO: add optional pretty-print logic
// TODO: add optional to toggle including underlying errors (should be off by default)
func (e *CortexCloudSdkError) Error() string {
	if e == nil {
		return "unknown"
	}

	statusStr := ""
	if e.HTTPStatus != nil {
		statusStr = fmt.Sprintf("http_status=%d, ", *e.HTTPStatus)
	}

	var (
		detailsStr string
		err        error
	)
	if detailsStr, err = e.DetailsToJSON(); err != nil {
		// TODO: is there a better way to handle this?
		detailsStr = ""
	}

	var (
		errorBytes []byte
		errorStr   string
	)
	if e.Err != nil {
		// TODO: fix this returning "{}"
		if errorBytes, err = json.Marshal(e.Err.Error()); err != nil {
			errorStr = "unknown"
		}
		errorStr = fmt.Sprintf(", underlying_error=%s", string(errorBytes))
	}

	return fmt.Sprintf("CortexCloudSdkError: code=%s, %smessage='%s', internal_errors_count=%d, details='%s'%s",
		e.Code, statusStr, e.Message, e.InternalErrorsCount, detailsStr, errorStr)
}

// Unwrap returns the underlying Go error, allowing for error chain inspection
// using errors.Unwrap from the standard library.
func (e *CortexCloudSdkError) Unwrap() error {
	return e.Err
}

// NewCortexCloudSdkError creates a new CortexCloudSdkError.
// Use this as the primary constructor for all SDK errors.
//
// Parameters:
//
//	code: A machine-readable error code.
//	message: A human-readable message.
//	details: Optional slice of CortexCloudSdkErrorDetail for more context.
//	httpStatus: Optional HTTP status code (pass nil for internal SDK errors).
//	err: Optional underlying Go error to wrap.
func NewCortexCloudSdkError(
	code string,
	message string,
	details []CortexCloudSdkErrorDetail,
	httpStatus *int,
	err error,
) *CortexCloudSdkError {
	return &CortexCloudSdkError{
		Code:                code,
		Message:             message,
		Details:             details,
		InternalErrorsCount: len(details),
		HTTPStatus:          httpStatus,
		Err:                 err,
	}
}

// IsCortexCloudSdkError checks if the given error is of type *CortexCloudSdkError.
// It uses errors.As to safely perform the type assertion.
func IsCortexCloudSdkError(err error) bool {
	var sdkErr *CortexCloudSdkError
	return errors.As(err, &sdkErr)
}

// AsCortexCloudSdkError attempts to cast the given error to *CortexCloudSdkError.
// It returns true if the conversion is successful, and the sdkErr pointer will
// point to the CortexCloudSdkError instance. This is a wrapper around errors.As.
func AsCortexCloudSdkError(err error, target **CortexCloudSdkError) bool {
	return errors.As(err, target)
}

// --- JSON Serialization Helpers ---

// ToJSON serializes the CortexCloudSdkError into a JSON string without indentation.
// It excludes the `Err` field as it's marked with `json:"-"`.
func (e CortexCloudSdkError) ToJSON() (string, error) {
	data, err := json.Marshal(e)
	if err != nil {
		return "", fmt.Errorf("failed to marshal CortexCloudSdkError to JSON: %w", err)
	}
	return string(data), nil
}

// ToPrettyJSON serializes the CortexCloudSdkError into a JSON string with indentation.
// It excludes the `Err` field.
func (e CortexCloudSdkError) ToPrettyJSON() (string, error) {
	data, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal CortexCloudSdkError to pretty JSON: %w", err)
	}
	return string(data), nil
}

// DetailsToJSON serializes the CortexCloudSdkError.Details into a JSON string without indentation.
// It excludes the `Err` field as it's marked with `json:"-"`.
func (e CortexCloudSdkError) DetailsToJSON() (string, error) {
	data, err := json.Marshal(e.Details)
	if err != nil {
		return "", fmt.Errorf("failed to marshal CortexCloudSdkError.Details to JSON: %w", err)
	}
	return string(data), nil
}

// DetailsToPrettyJSON serializes the CortexCloudSdkErrors.Details into a JSON string with indentation.
// It excludes the `Err` field.
func (e CortexCloudSdkError) DetailsToPrettyJSON() (string, error) {
	data, err := json.MarshalIndent(e.Details, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal CortexCloudSdkError.Details to pretty JSON: %w", err)
	}
	return string(data), nil
}

// --- Convenience Functions for Common Error Scenarios ---

// NewBadRequest creates a CortexCloudSdkError for HTTP 400 Bad Request.
// Use this for client-side input validation errors from an API.
func NewBadRequest(code, message string, details []CortexCloudSdkErrorDetail) *CortexCloudSdkError {
	status := http.StatusBadRequest
	return NewCortexCloudSdkError(code, message, details, &status, nil)
}

// NewUnauthorized creates a CortexCloudSdkError for HTTP 401 Unauthorized.
// Use this when authentication credentials are missing or invalid for API calls.
func NewUnauthorized(code, message string) *CortexCloudSdkError {
	status := http.StatusUnauthorized
	return NewCortexCloudSdkError(code, message, nil, &status, nil)
}

// NewForbidden creates a CortexCloudSdkError for HTTP 403 Forbidden.
// Use this when the client is authenticated but does not have permission to access the resource via API.
func NewForbidden(code, message string) *CortexCloudSdkError {
	status := http.StatusForbidden
	return NewCortexCloudSdkError(code, message, nil, &status, nil)
}

// NewNotFound creates a CortexCloudSdkError for HTTP 404 Not Found.
// Use this when the requested API resource does not exist.
func NewNotFound(code, message string) *CortexCloudSdkError {
	status := http.StatusNotFound
	return NewCortexCloudSdkError(code, message, nil, &status, nil)
}

// NewConflict creates a CortexCloudSdkError for HTTP 409 Conflict.
// Use this when an API request conflicts with the current state of the target resource.
func NewConflict(code, message string, details []CortexCloudSdkErrorDetail) *CortexCloudSdkError {
	status := http.StatusConflict
	return NewCortexCloudSdkError(code, message, details, &status, nil)
}

// NewInternalServerError creates a CortexCloudSdkError for HTTP 500 Internal Server Error.
// Use this for unexpected server-side errors from an API, potentially wrapping an underlying Go error.
func NewInternalServerError(code, message string, err error) *CortexCloudSdkError {
	status := http.StatusInternalServerError
	return NewCortexCloudSdkError(code, message, nil, &status, err)
}

// NewServiceUnavailable creates a CortexCloudSdkError for HTTP 503 Service Unavailable.
// Use this when the upstream API server is not ready to handle the request.
func NewServiceUnavailable(code, message string) *CortexCloudSdkError {
	status := http.StatusServiceUnavailable
	return NewCortexCloudSdkError(code, message, nil, &status, nil)
}

// NewInternalSDKError creates a CortexCloudSdkError for errors originating purely within the SDK's logic.
// These errors will have HTTPStatus as nil.
func NewInternalSDKError(code, message string, err error) *CortexCloudSdkError {
	return NewCortexCloudSdkError(code, message, nil, nil, err)
}

func NewPreRequestValidationError(details []CortexCloudSdkErrorDetail, err error) *CortexCloudSdkError {
	return NewCortexCloudSdkError(CodePreRequestValidationFailure, MsgPreRequestValidationFailure, details, nil, err)
}

// Validation Errors

func NewUnexpectedValidationErrorDetail(err error, location string) CortexCloudSdkErrorDetail {
	return CortexCloudSdkErrorDetail{
		Code:     DetailCodeUnexpectedValidationError,
		Location: location,
		Message:  DetailMsgUnexpectedValidationError,
		Error:    err,
	}
}

func NewUnknownValidationTagErrorDetail(err error, location, tag string) CortexCloudSdkErrorDetail {
	return CortexCloudSdkErrorDetail{
		Code:     DetailCodeUnknownValidationTag,
		Location: location,
		Message:  fmt.Sprintf(DetailMsgUnknownValidationTag, location, tag),
		Error:    err,
	}
}

func NewMinimumNumberOfValuesValidationErrorDetail(err error, location, fieldName string, expected string, actual int) CortexCloudSdkErrorDetail {
	return CortexCloudSdkErrorDetail{
		Code:     DetailCodeMinimumNumberOfValues,
		Location: location,
		Message:  fmt.Sprintf(DetailMsgMinimumNumberOfValues, fieldName, expected, actual),
		Error:    err,
	}
}

func NewRequiredValidationErrorDetail(err error, location, fieldName string) CortexCloudSdkErrorDetail {
	return CortexCloudSdkErrorDetail{
		Code:     DetailCodeMissingRequiredValue,
		Location: location,
		Message:  fmt.Sprintf(DetailMsgMissingRequiredValue, fieldName),
		Error:    err,
	}
}

func NewInvalidEnumValidationErrorDetail(err error, location, fieldName string, value any, enums []string) CortexCloudSdkErrorDetail {
	return CortexCloudSdkErrorDetail{
		Code:     DetailCodeInvalidEnumValue,
		Location: location,
		Message:  fmt.Sprintf(DetailMsgInvalidEnumValue, fieldName, value, strings.Join(enums, ", ")),
		Error:    err,
	}
}
