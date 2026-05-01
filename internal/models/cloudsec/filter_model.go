// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package models

import (
	"context"
	"fmt"

	cloudsecTypes "github.com/PaloAltoNetworks/cortex-cloud-go/types/cloudsec"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
)

// FilterCriteriaModel represents a recursive filter criteria structure for CloudSec policies.
// Supports both logical operators (AND/OR) and field-based filters.
type FilterCriteriaModel struct {
	Operator types.String `tfsdk:"operator"` // "AND" or "OR"
	Criteria types.List   `tfsdk:"criteria"` // List of nested FilterCriteriaModel
	Field    types.String `tfsdk:"field"`    // SEARCH_FIELD
	Type     types.String `tfsdk:"type"`     // SEARCH_TYPE
	Value    types.String `tfsdk:"value"`    // SEARCH_VALUE (stored as string, converted as needed)
}

// GetFilterCriteriaAttrTypes returns the attribute types for FilterCriteriaModel.
// This is used for creating types.Object values with the correct schema.
func GetFilterCriteriaAttrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"operator": types.StringType,
		"criteria": types.ListType{
			ElemType: types.ObjectType{
				AttrTypes: getNestedFilterCriteriaAttrTypes(),
			},
		},
		"field": types.StringType,
		"type":  types.StringType,
		"value": types.StringType,
	}
}

// getNestedFilterCriteriaAttrTypes returns attribute types for level 1 nested filter criteria.
// This prevents infinite recursion by limiting nesting depth to 3 levels.
func getNestedFilterCriteriaAttrTypes() map[string]attr.Type {
	// Level 1 (returned) - can contain level 2
	return map[string]attr.Type{
		"operator": types.StringType,
		"criteria": types.ListType{
			ElemType: types.ObjectType{AttrTypes: getLevel2FilterCriteriaAttrTypes()},
		},
		"field": types.StringType,
		"type":  types.StringType,
		"value": types.StringType,
	}
}

// ToSDKFilterCriteria converts a Terraform FilterCriteriaModel to SDK FilterCriteria.
// Handles recursive conversion for nested AND/OR operators.
func ToSDKFilterCriteria(ctx context.Context, model types.Object, diags *diag.Diagnostics) *cloudsecTypes.FilterCriteria {
	if model.IsNull() || model.IsUnknown() {
		return nil
	}

	var filterModel FilterCriteriaModel
	diags.Append(model.As(ctx, &filterModel, basetypes.ObjectAsOptions{})...)
	if diags.HasError() {
		return nil
	}

	result := &cloudsecTypes.FilterCriteria{}

	// Handle logical operators (AND/OR)
	if !filterModel.Operator.IsNull() && !filterModel.Operator.IsUnknown() {
		operator := filterModel.Operator.ValueString()

		if !filterModel.Criteria.IsNull() && !filterModel.Criteria.IsUnknown() {
			var criteriaList []types.Object
			diags.Append(filterModel.Criteria.ElementsAs(ctx, &criteriaList, false)...)
			if diags.HasError() {
				return nil
			}

			var nestedCriteria []cloudsecTypes.FilterCriteria
			for _, criteriaObj := range criteriaList {
				if nested := ToSDKFilterCriteria(ctx, criteriaObj, diags); nested != nil {
					nestedCriteria = append(nestedCriteria, *nested)
				}
			}

			if operator == "AND" {
				result.AND = nestedCriteria
			} else if operator == "OR" {
				result.OR = nestedCriteria
			}
		}
	}

	// Handle field-based filters
	if !filterModel.Field.IsNull() && !filterModel.Field.IsUnknown() {
		result.SearchField = filterModel.Field.ValueString()
	}

	if !filterModel.Type.IsNull() && !filterModel.Type.IsUnknown() {
		result.SearchType = filterModel.Type.ValueString()
	}

	if !filterModel.Value.IsNull() && !filterModel.Value.IsUnknown() {
		// Store as interface{} - the API will handle type conversion
		result.SearchValue = filterModel.Value.ValueString()
	}

	return result
}

// FromSDKFilterCriteria converts SDK FilterCriteria to a Terraform types.Object.
// Handles recursive conversion for nested AND/OR operators.
func FromSDKFilterCriteria(ctx context.Context, sdk *cloudsecTypes.FilterCriteria, diags *diag.Diagnostics) types.Object {
	return fromSDKFilterCriteriaWithDepth(ctx, sdk, diags, 0)
}

// fromSDKFilterCriteriaWithDepth converts SDK FilterCriteria to Terraform types.Object with depth tracking.
// depth: 0 = root level, 1 = first nesting, 2 = second nesting, 3+ = deepest (no more nesting)
func fromSDKFilterCriteriaWithDepth(ctx context.Context, sdk *cloudsecTypes.FilterCriteria, diags *diag.Diagnostics, depth int) types.Object {
	// Get the appropriate attribute types for this depth level
	var attrTypes map[string]attr.Type
	switch depth {
	case 0:
		attrTypes = GetFilterCriteriaAttrTypes()
	case 1:
		attrTypes = getNestedFilterCriteriaAttrTypes()
	case 2:
		attrTypes = getLevel2FilterCriteriaAttrTypes()
	default: // depth >= 3
		attrTypes = getLevel3FilterCriteriaAttrTypes()
	}

	if sdk == nil {
		return types.ObjectNull(attrTypes)
	}

	// Initialize all attributes as null with correct types
	attrValues := make(map[string]attr.Value)
	for key, attrType := range attrTypes {
		switch key {
		case "operator", "field", "type", "value":
			attrValues[key] = types.StringNull()
		case "criteria":
			if listType, ok := attrType.(types.ListType); ok {
				attrValues[key] = types.ListNull(listType.ElemType)
			}
		}
	}

	// Handle AND operator
	if len(sdk.AND) > 0 {
		attrValues["operator"] = types.StringValue("AND")

		if depth < 3 { // Only add criteria if we haven't reached max depth
			var criteriaObjs []attr.Value
			for _, nested := range sdk.AND {
				nestedCopy := nested
				criteriaObjs = append(criteriaObjs, fromSDKFilterCriteriaWithDepth(ctx, &nestedCopy, diags, depth+1))
			}

			// Get the element type for the criteria list at this depth
			var elemType attr.Type
			switch depth {
			case 0:
				elemType = types.ObjectType{AttrTypes: getNestedFilterCriteriaAttrTypes()}
			case 1:
				elemType = types.ObjectType{AttrTypes: getLevel2FilterCriteriaAttrTypes()}
			default: // depth >= 2
				elemType = types.ObjectType{AttrTypes: getLevel3FilterCriteriaAttrTypes()}
			}

			listVal, d := types.ListValue(elemType, criteriaObjs)
			diags.Append(d...)
			attrValues["criteria"] = listVal
		}
	}

	// Handle OR operator
	if len(sdk.OR) > 0 {
		attrValues["operator"] = types.StringValue("OR")

		if depth < 3 { // Only add criteria if we haven't reached max depth
			var criteriaObjs []attr.Value
			for _, nested := range sdk.OR {
				nestedCopy := nested
				criteriaObjs = append(criteriaObjs, fromSDKFilterCriteriaWithDepth(ctx, &nestedCopy, diags, depth+1))
			}

			// Get the element type for the criteria list at this depth
			var elemType attr.Type
			switch depth {
			case 0:
				elemType = types.ObjectType{AttrTypes: getNestedFilterCriteriaAttrTypes()}
			case 1:
				elemType = types.ObjectType{AttrTypes: getLevel2FilterCriteriaAttrTypes()}
			default: // depth >= 2
				elemType = types.ObjectType{AttrTypes: getLevel3FilterCriteriaAttrTypes()}
			}

			listVal, d := types.ListValue(elemType, criteriaObjs)
			diags.Append(d...)
			attrValues["criteria"] = listVal
		}
	}

	// Handle field-based filters
	if sdk.SearchField != "" {
		attrValues["field"] = types.StringValue(sdk.SearchField)
	}

	if sdk.SearchType != "" {
		attrValues["type"] = types.StringValue(sdk.SearchType)
	}

	if sdk.SearchValue != nil {
		// Convert interface{} to string representation
		attrValues["value"] = types.StringValue(convertInterfaceToString(sdk.SearchValue))
	}

	objVal, d := types.ObjectValue(attrTypes, attrValues)
	diags.Append(d...)
	return objVal
}

// getLevel2FilterCriteriaAttrTypes returns attribute types for level 2 nesting.
func getLevel2FilterCriteriaAttrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"operator": types.StringType,
		"criteria": types.ListType{
			ElemType: types.ObjectType{AttrTypes: getLevel3FilterCriteriaAttrTypes()},
		},
		"field": types.StringType,
		"type":  types.StringType,
		"value": types.StringType,
	}
}

// getLevel3FilterCriteriaAttrTypes returns attribute types for level 3 (deepest) nesting.
func getLevel3FilterCriteriaAttrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"operator": types.StringType,
		"field":    types.StringType,
		"type":     types.StringType,
		"value":    types.StringType,
	}
}

// convertInterfaceToString converts an interface{} value to its string representation.
// Handles common types returned by the API.
func convertInterfaceToString(val interface{}) string {
	if val == nil {
		return ""
	}

	switch v := val.(type) {
	case string:
		return v
	case bool:
		if v {
			return "true"
		}
		return "false"
	case int:
		return fmt.Sprintf("%d", v)
	case int32:
		return fmt.Sprintf("%d", v)
	case int64:
		return fmt.Sprintf("%d", v)
	case float32:
		return fmt.Sprintf("%f", v)
	case float64:
		return fmt.Sprintf("%f", v)
	default:
		// Fallback to fmt.Sprintf
		return fmt.Sprintf("%v", v)
	}
}
