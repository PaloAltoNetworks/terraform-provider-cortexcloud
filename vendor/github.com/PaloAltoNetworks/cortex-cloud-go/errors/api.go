package errors

import (
	//"bytes"
	//"encoding/json"
	"fmt"
	"strings"
	"strconv"
)

// TODO: remove after creating internal/util package
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
	Reply *CortexCloudAPIErrorReply `json:"reply,omitempty"`
	Code *string `json:"errorCode,omitempty"`
	Message *string `json:"message,omitempty"`
	//Details map[string]any `json:"details,omitempty"`
	Details *CortexCloudAPIErrorDetails `json:"details"`
}

type CortexCloudAPIErrorReply struct {
	Code    int                        `json:"err_code"`
	Message string                     `json:"err_msg"`
	Extra   []CortexCloudAPIErrorExtra `json:"err_extra"`
}

type CortexCloudAPIErrorExtra struct {
	Type     string                     `json:"type"`
	Location []any                      `json:"loc"`
	Message  string                     `json:"msg"`
	Input    any                        `json:"input"`
	Context  CortexCloudAPIErrorContext `json:"ctx"`
}

type CortexCloudAPIErrorContext struct {
	Expected  string `json:"expected,omitempty"`
	MinLength int    `json:"min_length,omitempty"`
}

type CortexCloudAPIErrorDetails struct {
	Params CortexCloudAPIErrorParams `json:"params"`
}

type CortexCloudAPIErrorParams struct {
	Message string `json:"message"`
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
		Code: &code,
		Message: &message,
		Details: &details,
	}
}

func (e CortexCloudAPIError) Error() string {
	var sb strings.Builder

	if e.Reply != nil {
		sb.WriteString(fmt.Sprintf("Error Code: %d\n", e.Reply.Code))
		sb.WriteString(fmt.Sprintf("Error Message: %s\n", e.Reply.Message))
		sb.WriteString("Error Details:\n")
		for _, extra := range e.Reply.Extra {
			sb.WriteString(fmt.Sprintf("  - Type: \"%s\"\n", extra.Type))
			sb.WriteString(fmt.Sprintf("    Location: [\"%s\"]\n", strings.Join(extra.locationAsStringSlice(), "\", \"")))
			sb.WriteString(fmt.Sprintf("    Message: \"%s\"\n", extra.Message))
			sb.WriteString(fmt.Sprintf("    Input: \"%s\"\n", extra.inputAsString()))

			if extra.Context.Expected != "" {
				sb.WriteString(fmt.Sprintf("    Expected: \"%s\"\n", extra.Context.Expected))
			}
			if extra.Context.MinLength != 0 {
				sb.WriteString(fmt.Sprintf("    MinLength: \"%d\"\n", extra.Context.MinLength))
			}
		}
	} else {
		var (
			code string
			message string
			details CortexCloudAPIErrorDetails
		)

		if e.Code != nil {
			code = *e.Code
		} else {
			code = ""
		}

		if e.Message != nil {
			message = *e.Message
		} else {
			message = ""
		}

		if e.Details != nil {
			details = *e.Details
		} else {
			details = CortexCloudAPIErrorDetails{}
		}

		sb.WriteString(fmt.Sprintf("Error Code: %s\n", code))
		sb.WriteString(fmt.Sprintf("Error Message: %s\n", message))
		sb.WriteString(fmt.Sprintf("Error Details: %s\n", details))
	}

	return sb.String()
}

func (e CortexCloudAPIError) ToBuiltin() error {
	return fmt.Errorf("%+v", e.Error())
}
