// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

// Package errors defines custom error types for the SDK.
package errors

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

func convertInterfaceToString(value any) (string, error) {
	switch v := value.(type) {
	case int:
		// Convert int to string using strconv.Itoa
		return strconv.Itoa(v), nil
	case int8:
		// Convert int8 to string using strconv.FormatInt
		return strconv.FormatInt(int64(v), 10), nil
	case int16:
		// Convert int16 to string using strconv.FormatInt
		return strconv.FormatInt(int64(v), 10), nil
	case int32: // rune is an alias for int32
		// Convert int32 to string using strconv.FormatInt
		return strconv.FormatInt(int64(v), 10), nil
	case int64:
		// Convert int64 to string using strconv.FormatInt
		return strconv.FormatInt(v, 10), nil
	case uint:
		// Convert uint to string using strconv.FormatUint
		return strconv.FormatUint(uint64(v), 10), nil
	case uint8: // byte is an alias for uint8
		// Convert uint8 to string using strconv.FormatUint
		return strconv.FormatUint(uint64(v), 10), nil
	case uint16:
		// Convert uint16 to string using strconv.FormatUint
		return strconv.FormatUint(uint64(v), 10), nil
	case uint32:
		// Convert uint32 to string using strconv.FormatUint
		return strconv.FormatUint(uint64(v), 10), nil
	case uint64:
		// Convert uint64 to string using strconv.FormatUint
		return strconv.FormatUint(v, 10), nil
	case float32:
		// Convert float32 to string using strconv.FormatFloat
		// 'f' format, -1 precision (shortest representation), 32-bit float
		return strconv.FormatFloat(float64(v), 'f', -1, 32), nil
	case float64:
		// Convert float64 to string using strconv.FormatFloat
		// 'f' format, -1 precision (shortest representation), 64-bit float
		return strconv.FormatFloat(v, 'f', -1, 64), nil
	case bool:
		// Convert bool to string using strconv.FormatBool
		return strconv.FormatBool(v), nil
	case string:
		// If it's already a string, return it directly
		return v, nil
	default:
		// For unsupported types, return an error
		return "", fmt.Errorf("unsupported type for conversion: %T", value)
	}
}

type CortexCloudAPIError struct {
	Reply   *CortexCloudAPIErrorReply   `json:"reply,omitempty"`
	Data    *CortexCloudAPIErrorData    `json:"data,omitempty"`
	Code    *string                     `json:"errorCode,omitempty"`
	Message *string                     `json:"message,omitempty"`
	Details *CortexCloudAPIErrorDetails `json:"details,omitempty"`
	// Fields for root-level error format (e.g. CloudSec)
	ErrCode  *int                         `json:"err_code,omitempty"`
	ErrMsg   *string                      `json:"err_msg,omitempty"`
	Metadata *CortexCloudAPIErrorMetadata `json:"metadata,omitempty"`
}

type CortexCloudAPIErrorReply struct {
	Code    int             `json:"err_code"`
	Message string          `json:"err_msg"`
	Extra   ErrorExtraField `json:"err_extra"`
}

type CortexCloudAPIErrorData struct {
	Message  string                       `json:"err_msg"`
	Metadata *CortexCloudAPIErrorMetadata `json:"metadata,omitempty"`
}

type CortexCloudAPIErrorMetadata struct {
	Code  int             `json:"err_code"`
	Extra ErrorExtraField `json:"err_extra"`
}

// ErrorExtraField handles both string and array formats for err_extra field
type ErrorExtraField struct {
	values []CortexCloudAPIErrorExtra
}

// UnmarshalJSON implements custom JSON unmarshaling to handle both string and array formats
func (e *ErrorExtraField) UnmarshalJSON(data []byte) error {
	// Try to unmarshal as array of error objects first
	var arr []CortexCloudAPIErrorExtra
	if err := json.Unmarshal(data, &arr); err == nil {
		e.values = arr
		return nil
	}

	// Try to unmarshal as a simple string
	var str string
	if err := json.Unmarshal(data, &str); err == nil {
		// Convert string to a single error extra object with the string as the message
		if str != "" {
			e.values = []CortexCloudAPIErrorExtra{
				{
					Type:    "string_error",
					Message: str,
				},
			}
		} else {
			e.values = []CortexCloudAPIErrorExtra{}
		}
		return nil
	}

	// If both fail, return error
	return fmt.Errorf("err_extra must be either a string or an array of error objects")
}

// MarshalJSON implements custom JSON marshaling
func (e ErrorExtraField) MarshalJSON() ([]byte, error) {
	return json.Marshal(e.values)
}

// Values returns the underlying slice of error extra objects
func (e ErrorExtraField) Values() []CortexCloudAPIErrorExtra {
	return e.values
}

type CortexCloudAPIErrorExtra struct {
	Type        string                     `json:"type,omitempty"`
	Location    []any                      `json:"loc,omitempty"`
	Message     string                     `json:"msg,omitempty"`
	MessageFull string                     `json:"message,omitempty"`
	Field       any                        `json:"field,omitempty"`
	Input       any                        `json:"input,omitempty"`
	Context     CortexCloudAPIErrorContext `json:"ctx,omitempty"`
}

type CortexCloudAPIErrorContext struct {
	Expected  string `json:"expected,omitempty"`
	MinLength int    `json:"min_length,omitempty"`
}

// CortexCloudAPIErrorDetails handles both the legacy "params" shape and the
// AppSec-style per-field map shape returned by HTTP 422 ValidateError responses.
//
// Legacy "params" shape:
//
//	"details": { "params": { "message": "..." } }
//
// AppSec per-field map shape (e.g. policy CREATE/UPDATE 422):
//
//	"details": {
//	  "policy.triggers.ciImage":       { "message": "'ciImage' is required" },
//	  "policy.triggers.imageRegistry": { "message": "'imageRegistry' is required" }
//	}
//
// Fields populated by UnmarshalJSON depend on which shape was returned.
type CortexCloudAPIErrorDetails struct {
	// Params is set when the "params" key is present (legacy shape).
	Params CortexCloudAPIErrorParams `json:"-"`
	// Fields is the parsed per-field validation map. Each entry is
	// "field path" -> { message: "..." }. Empty when no per-field details
	// were returned.
	Fields map[string]CortexCloudAPIErrorParams `json:"-"`
}

type CortexCloudAPIErrorParams struct {
	Message string `json:"message"`
}

// UnmarshalJSON implements custom JSON unmarshaling that accepts:
//   - {"params": {"message": "..."}}                          -> Params
//   - {"<fieldPath>": {"message": "..."}, ...}                -> Fields
//   - mixed (params + arbitrary other keys)                   -> both
func (d *CortexCloudAPIErrorDetails) UnmarshalJSON(data []byte) error {
	var raw map[string]CortexCloudAPIErrorParams
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	for k, v := range raw {
		if k == "params" {
			d.Params = v
			continue
		}
		if d.Fields == nil {
			d.Fields = make(map[string]CortexCloudAPIErrorParams)
		}
		d.Fields[k] = v
	}
	return nil
}

// MarshalJSON implements custom JSON marshaling that round-trips both shapes.
func (d CortexCloudAPIErrorDetails) MarshalJSON() ([]byte, error) {
	out := map[string]CortexCloudAPIErrorParams{}
	if d.Params.Message != "" {
		out["params"] = d.Params
	}
	for k, v := range d.Fields {
		out[k] = v
	}
	return json.Marshal(out)
}

type CortexCloudAPIErrorDetail struct {
	Type     string                     `json:"type"`
	Location []any                      `json:"loc"`
	Message  string                     `json:"msg"`
	Input    any                        `json:"input"`
	Context  CortexCloudAPIErrorContext `json:"ctx"`
}

func (e CortexCloudAPIErrorExtra) locationAsStringSlice() []string {
	result := []string{}
	for _, elem := range e.Location {
		stringElem, err := convertInterfaceToString(elem)
		if err != nil {
			stringElem = "UNKNOWN_TYPE"
		}

		result = append(result, stringElem)
	}

	return result
}

func (e CortexCloudAPIErrorExtra) inputAsString() string {
	stringInput, err := convertInterfaceToString(e.Input)
	if err != nil {
		return "UNKNOWN_TYPE"
	}

	return stringInput
}

func NewCortexCloudAPIError(code string, message string, details CortexCloudAPIErrorDetails) CortexCloudAPIError {
	return CortexCloudAPIError{
		Code:    &code,
		Message: &message,
		Details: &details,
	}
}

// HasContent reports whether at least one of the known error fields was
// populated during JSON unmarshaling.  When json.Unmarshal succeeds on
// valid JSON that uses none of the expected keys (e.g. `{"error":"msg"}`),
// every pointer field stays nil and HasContent returns false.  Callers
// should treat this as "unrecognised error format" and fall back to
// including the raw HTTP response body so the user is never shown an
// empty error.
func (e CortexCloudAPIError) HasContent() bool {
	return e.Reply != nil ||
		e.Data != nil ||
		e.Code != nil ||
		e.Message != nil ||
		e.Details != nil ||
		e.ErrCode != nil ||
		e.ErrMsg != nil ||
		e.Metadata != nil
}

func (e CortexCloudAPIError) Error() string {
	var sb strings.Builder

	//
	// Case 1: CloudSec Reply-based error (err_code / err_msg / err_extra)
	//
	if e.Reply != nil {
		sb.WriteString(fmt.Sprintf("Error Code: %d\n", e.Reply.Code))
		sb.WriteString(fmt.Sprintf("Error Message: %s\n", e.Reply.Message))
		sb.WriteString("Error Details:\n")

		for _, extra := range e.Reply.Extra.Values() {
			appendExtraError(&sb, extra)
		}
		return sb.String()
	}

	//
	// Case 2: Data + Metadata error (newer CloudSec error format)
	//
	if e.Data != nil {
		// Metadata contains err_code + err_extra
		if e.Data.Metadata != nil {
			sb.WriteString(fmt.Sprintf("Error Code: %d\n", e.Data.Metadata.Code))
		}

		// err_msg
		sb.WriteString(fmt.Sprintf("Error Message: %s\n", e.Data.Message))

		if e.Data.Metadata != nil {
			sb.WriteString("Error Details:\n")
			for _, extra := range e.Data.Metadata.Extra.Values() {
				appendExtraError(&sb, extra)
			}
		}
		return sb.String()
	}

	//
	// Case 3: Root-level ErrCode/ErrMsg + Metadata (CloudSec variant)
	//
	if e.ErrCode != nil || e.ErrMsg != nil || e.Metadata != nil {
		// Print error code from root level if present, otherwise from metadata
		if e.ErrCode != nil && *e.ErrCode != 0 {
			sb.WriteString(fmt.Sprintf("Error Code: %d\n", *e.ErrCode))
		} else if e.Metadata != nil && e.Metadata.Code != 0 {
			sb.WriteString(fmt.Sprintf("Error Code: %d\n", e.Metadata.Code))
		}

		if e.ErrMsg != nil {
			sb.WriteString(fmt.Sprintf("Error Message: %s\n", *e.ErrMsg))
		}

		if e.Metadata != nil && len(e.Metadata.Extra.Values()) > 0 {
			sb.WriteString("Error Details:\n")
			for _, extra := range e.Metadata.Extra.Values() {
				appendExtraError(&sb, extra)
			}
		}
		return sb.String()
	}

	//
	// Case 4: Root-level ErrMsg only (CloudSec variant without metadata)
	//
	if e.ErrMsg != nil {
		sb.WriteString(fmt.Sprintf("Error Message: %s\n", *e.ErrMsg))
		return sb.String()
	}

	//
	// Case 4: Fallback error (Code, Message, Details)
	//
	code := ""
	msg := ""
	var details CortexCloudAPIErrorDetails

	if e.Code != nil {
		code = *e.Code
	}
	if e.Message != nil {
		msg = *e.Message
	}
	if e.Details != nil {
		details = *e.Details
	}

	sb.WriteString(fmt.Sprintf("Error Code: %s\n", code))
	sb.WriteString(fmt.Sprintf("Error Message: %s\n", msg))
	if details.Params.Message != "" {
		sb.WriteString(fmt.Sprintf("Error Details: %s\n", details.Params.Message))
	}
	if len(details.Fields) > 0 {
		sb.WriteString("Error Details:\n")
		// Sort keys for deterministic output
		keys := make([]string, 0, len(details.Fields))
		for k := range details.Fields {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			sb.WriteString(fmt.Sprintf("  - %s: %s\n", k, details.Fields[k].Message))
		}
	}
	if details.Params.Message == "" && len(details.Fields) == 0 {
		sb.WriteString("Error Details: \n")
	}

	return sb.String()
}

func appendExtraError(sb *strings.Builder, extra CortexCloudAPIErrorExtra) {
	if extra.Type != "" {
		sb.WriteString(fmt.Sprintf("  - Type: \"%s\"\n", extra.Type))
	}
	if extra.Field != nil {
		fieldStr, err := convertInterfaceToString(extra.Field)
		if err == nil && fieldStr != "" {
			sb.WriteString(fmt.Sprintf("  - Field: \"%s\"\n", fieldStr))
		}
	}
	if len(extra.Location) > 0 {
		sb.WriteString(fmt.Sprintf("    Location: [\"%s\"]\n", strings.Join(extra.locationAsStringSlice(), "\", \"")))
	}

	msg := extra.Message
	if msg == "" {
		msg = extra.MessageFull
	}
	sb.WriteString(fmt.Sprintf("    Message: \"%s\"\n", msg))

	if extra.Input != nil {
		sb.WriteString(fmt.Sprintf("    Input: \"%s\"\n", extra.inputAsString()))
	}

	if extra.Context.Expected != "" {
		sb.WriteString(fmt.Sprintf("    Expected: \"%s\"\n", extra.Context.Expected))
	}
	if extra.Context.MinLength != 0 {
		sb.WriteString(fmt.Sprintf("    MinLength: \"%d\"\n", extra.Context.MinLength))
	}
}

// ToBuiltin converts the CortexCloudAPIError to a standard Go error.
// It ensures that the error message contains all relevant details.
func (e CortexCloudAPIError) ToBuiltin() error {
	// If we have a structured error, use its string representation
	if e.Reply != nil || e.Data != nil || e.Code != nil || e.Message != nil || e.ErrCode != nil || e.ErrMsg != nil || e.Metadata != nil {
		return fmt.Errorf("%s", e.Error())
	}
	// Fallback for empty error objects
	return fmt.Errorf("unknown API error")
}

// Policy API error shape (always).
type policyAPIError struct {
	ErrMsg   string `json:"err_msg"`
	Metadata struct {
		ErrCode  int `json:"err_code,omitempty"`
		ErrExtra []struct {
			Field   string `json:"field"`
			Message string `json:"message"`
		} `json:"err_extra"`
	} `json:"metadata"`
}
