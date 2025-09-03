// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package types

import (
	"fmt"
	"reflect"
	"strconv"
)

// Pointer takes any type and returns a pointer for that type.
func Pointer[T any](d T) *T {
	return &d
}

// ConvertInterfaceToString takes an interface{} as input and attempts to convert it to a string
// using the appropriate function from the strconv package based on its underlying type.
// It returns the converted string and an error if the type is not supported.
func ConvertInterfaceToString(value any) (string, error) {
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

func GetSliceLengthFromInterface(value any) (int, error) {
	v := reflect.ValueOf(value)

	if v.Kind() == reflect.Slice {
		return v.Len(), nil
	} else {
		return -1, fmt.Errorf("attempted to convert non-slice value to slice -- actual type: %T", value)
	}
}
