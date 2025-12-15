// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package util

import (
	"context"
	"fmt"
	"slices"
	"strconv"

	//"regexp"
	"os"
	"reflect"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
)

// GetEnvironmentVariable retrieves the string value of the specified environment
// variable, converts it to the type of the reciever argument, and assigns address
// of the converted value to reciever.
//
// If the environment variable is not set, is set to an empty value, or is unable
// to be converted into the reciever type, the function will exit without
// modifying reciever and return an error.
func GetEnvironmentVariable(name string, reciever any) error {
	value := os.Getenv(name)
	if value == "" {
		return nil
	}

	switch v := reciever.(type) {
	case *int:
		intValue, err := strconv.Atoi(value)
		if err != nil {
			return err
		}
		*v = intValue
		return nil
	case *bool:
		boolValue, err := strconv.ParseBool(value)
		if err != nil {
			return err
		}
		*v = boolValue
		return nil
	default:
		return fmt.Errorf("failed to parse %s value from environment variable: unsupported type", reflect.TypeOf(v).String())
	}
}

func StringPointerIsNilOrEmpty(value *string) bool {
	if value == nil || *value == "" {
		return true
	}

	return false
}

func Int32PointerIsNilOrNegative(value *int32) bool {
	if value == nil || *value < 0 {
		return true
	}

	return false
}

// Converts basetypes.ListValue to string slice and populates it in response
func ListToStringSlice(ctx context.Context, l *basetypes.ListValue, response *[]string) diag.Diagnostics {
	if l == nil || (*l).IsNull() {
		return nil
	}

	diags := l.ElementsAs(ctx, response, false)

	return diags
}

//func StringToInt(str string) (int, diag.Diagnostic) {
//    i, err := strconv.Atoi(str)
//    if err != nil {
//        diag.NewAttributeErrorDiagnostic(
//
//        )
//    }
//}

func StringToInt(str string) (int, error) {
	i, err := strconv.Atoi(str)
	if err != nil {
		return -1, err
	}

	return i, nil
}

// Returns true if s1 shares any elements with s2
func SliceSharesOneOrMoreElements(s1 []string, s2 []string) bool {
	for _, elem := range s1 {
		if slices.Contains(s2, elem) {
			return true
		}
	}

	return false
}

// FindElement searches for an element in a slice and returns it if found,
// along with a boolean indicating if it was found.
// The criteria argument can be either a value to compare directly with elements
// in the slice, or a map[string]any of key-value pairs to match against the
// fields of a struct element.
func FindElement[T any](slice []T, criteria any) (T, bool) {
	if fieldMatcher, ok := criteria.(map[string]any); ok {
		for _, element := range slice {
			val := reflect.ValueOf(element)
			if val.Kind() == reflect.Pointer {
				val = val.Elem()
			}

			if val.Kind() != reflect.Struct {
				continue
			}

			allFieldsMatch := true
			for fieldName, expectedValue := range fieldMatcher {
				field := val.FieldByName(fieldName)
				if !field.IsValid() || !field.CanInterface() {
					allFieldsMatch = false
					break
				}

				if !reflect.DeepEqual(field.Interface(), expectedValue) {
					allFieldsMatch = false
					break
				}
			}

			if allFieldsMatch {
				return element, true
			}
		}
	} else {
		for _, element := range slice {
			if reflect.DeepEqual(element, criteria) {
				return element, true
			}
		}
	}

	var zero T
	return zero, false
}
