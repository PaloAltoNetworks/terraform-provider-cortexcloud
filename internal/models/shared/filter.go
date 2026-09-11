package models

import (
	"bytes"
	"context"
	"encoding/json"

	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/enums"
	filterTypes "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/types/filter"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listdefault"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

const (
	MaxFilterDepth int = 10
)

// RootFilterModel represents the root of the membership predicate.
type RootFilterModel struct {
	And []NestedFilterModel `tfsdk:"and" json:"AND,omitempty"`
	Or  []NestedFilterModel `tfsdk:"or" json:"OR,omitempty"`
}

// NestedFilterModel represents a nested filter condition.
type NestedFilterModel struct {
	And         []NestedFilterModel `tfsdk:"and" json:"AND,omitempty"`
	Or          []NestedFilterModel `tfsdk:"or" json:"OR,omitempty"`
	SearchField types.String        `tfsdk:"search_field" json:"SEARCH_FIELD"`
	SearchType  types.String        `tfsdk:"search_type" json:"SEARCH_TYPE"`
	SearchValue types.String        `tfsdk:"search_value" json:"SEARCH_VALUE"`
}

type FilterRangeInt64Model struct {
	From types.Int64 `tfsdk:"from"`
	To   types.Int64 `tfsdk:"to"`
}

type FilterGreaterOrLessThanInt64Model struct {
	Condition types.String `tfsdk:"condition"`
	Value     types.Int64  `tfsdk:"value"`
}

// searchValueToString converts a raw SEARCH_VALUE payload into the string form
// held in Terraform state.
//
// A JSON string is unquoted and stored verbatim, preserving the behaviour for
// ordinary search types. Any other JSON value (object, array, number, bool) is
// stored as compacted JSON text so that it matches what jsonencode() produces
// in configuration for search types such as JSON_WILDCARD and JSON_WILDCARD_NOT.
func searchValueToString(raw json.RawMessage) (string, error) {
	if len(raw) == 0 {
		return "", nil
	}

	var asString string
	if err := json.Unmarshal(raw, &asString); err == nil {
		return asString, nil
	}

	var compacted bytes.Buffer
	if err := json.Compact(&compacted, raw); err != nil {
		return "", err
	}
	return compacted.String(), nil
}

func (m *NestedFilterModel) UnmarshalJSON(data []byte) error {
	var temp struct {
		And         []NestedFilterModel `json:"AND,omitempty"`
		Or          []NestedFilterModel `json:"OR,omitempty"`
		SearchField string              `json:"SEARCH_FIELD,omitempty"`
		SearchType  string              `json:"SEARCH_TYPE,omitempty"`
		SearchValue json.RawMessage     `json:"SEARCH_VALUE,omitempty"`
	}

	if err := json.Unmarshal(data, &temp); err != nil {
		return err
	}

	m.And = temp.And
	m.Or = temp.Or

	if temp.SearchField != "" {
		m.SearchField = types.StringValue(temp.SearchField)
	} else {
		m.SearchField = types.StringNull()
	}
	if temp.SearchType != "" {
		m.SearchType = types.StringValue(temp.SearchType)
	} else {
		m.SearchType = types.StringNull()
	}

	searchValue, err := searchValueToString(temp.SearchValue)
	if err != nil {
		return err
	}
	if searchValue != "" {
		m.SearchValue = types.StringValue(searchValue)
	} else {
		m.SearchValue = types.StringNull()
	}

	return nil
}

var (
	rootFilterSchema     = GetRecursiveFilterSchema(0, MaxFilterDepth)
	rootFilterAttrType   = GetRecursiveFilterAttrType(0, MaxFilterDepth)
	RootFilterAttributes = map[string]schema.Attribute{
		"and": schema.ListNestedAttribute{
			Optional: true,
			Computed: true,
			NestedObject: schema.NestedAttributeObject{
				Attributes: rootFilterSchema,
			},
			Default: listdefault.StaticValue(
				types.ListNull(
					types.ObjectType{
						AttrTypes: rootFilterAttrType,
					},
				),
			),
		},
		"or": schema.ListNestedAttribute{
			Optional: true,
			Computed: true,
			NestedObject: schema.NestedAttributeObject{
				Attributes: rootFilterSchema,
			},
			Default: listdefault.StaticValue(
				types.ListNull(
					types.ObjectType{
						AttrTypes: rootFilterAttrType,
					},
				),
			),
		},
	}
	RootFilterAttrTypeMap = map[string]attr.Type{
		"and": types.ListType{
			ElemType: types.ObjectType{
				AttrTypes: rootFilterAttrType,
			},
		},
		"or": types.ListType{
			ElemType: types.ObjectType{
				AttrTypes: rootFilterAttrType,
			},
		},
	}
	RootFilterWithNullChildren = types.ObjectValueMust(
		RootFilterAttrTypeMap,
		map[string]attr.Value{
			"and": types.ListValueMust(
				types.ObjectType{
					AttrTypes: rootFilterAttrType,
				},
				[]attr.Value{},
			),
			"or": types.ListValueMust(
				types.ObjectType{
					AttrTypes: rootFilterAttrType,
				},
				[]attr.Value{},
			),
		},
	)
)

func GetRecursiveFilterSchema(depth, maxDepth int) map[string]schema.Attribute {
	attrs := map[string]schema.Attribute{
		"search_field": schema.StringAttribute{
			Description: "The field to match on, for example `xdm.asset.name`.",
			Optional:    true,
		},
		"search_type": schema.StringAttribute{
			Description: "The comparison to apply, for example `EQ`, `CONTAINS`, `JSON_WILDCARD` or `JSON_WILDCARD_NOT`.",
			Optional:    true,
			Validators: []validator.String{
				stringvalidator.OneOf(enums.AllSearchTypes()...),
			},
		},
		"search_value": schema.StringAttribute{
			Description: "The value to compare against.\n\n" +
				"For most search types this is a plain string. The JSON-valued search types " +
				"(`JSON_WILDCARD` and `JSON_WILDCARD_NOT`) instead expect a " +
				"JSON object, which must be supplied using `jsonencode(...)`; the encoded " +
				"value is sent to the API as native JSON rather than as a quoted string. For example, " +
				"to match a tag: `search_value = jsonencode({ key = \"application\", value = \"databricks\" })`.",
			Optional: true,
		},
	}

	if depth < maxDepth {
		attrs["and"] = schema.ListNestedAttribute{
			Optional: true,
			Computed: true,
			NestedObject: schema.NestedAttributeObject{
				Attributes: GetRecursiveFilterSchema(depth+1, maxDepth),
			},
			Default: listdefault.StaticValue(
				types.ListNull(
					types.ObjectType{
						AttrTypes: GetRecursiveFilterAttrType(depth+1, MaxFilterDepth),
					},
				),
			),
		}
		attrs["or"] = schema.ListNestedAttribute{
			Optional: true,
			Computed: true,
			NestedObject: schema.NestedAttributeObject{
				Attributes: GetRecursiveFilterSchema(depth+1, maxDepth),
			},
			Default: listdefault.StaticValue(
				types.ListNull(
					types.ObjectType{
						AttrTypes: GetRecursiveFilterAttrType(depth+1, MaxFilterDepth),
					},
				),
			),
		}
	}

	return attrs
}

func GetRecursiveFilterAttrType(depth, maxDepth int) map[string]attr.Type {
	attrs := map[string]attr.Type{
		"search_field": types.StringType,
		"search_type":  types.StringType,
		"search_value": types.StringType,
	}

	if depth < maxDepth {
		attrs["and"] = types.ListType{
			ElemType: types.ObjectType{
				AttrTypes: GetRecursiveFilterAttrType(depth+1, maxDepth),
			},
		}
		attrs["or"] = types.ListType{
			ElemType: types.ObjectType{
				AttrTypes: GetRecursiveFilterAttrType(depth+1, maxDepth),
			},
		}
	}

	return attrs
}

//func GetRecursiveFilterAttrNullValue(depth, maxDepth int) map[string]attr.Value {
//	attrs := map[string]attr.Value{
//		"search_field": types.StringNull(),
//		"search_type":  types.StringNull(),
//		"search_value": types.StringNull(),
//	}
//
//	if depth < maxDepth {
//		attrs["and"] = types.ListType{
//			ElemType: types.ObjectType{
//				AttrTypes: GetRecursiveFilterAttrType(depth+1, maxDepth),
//			},
//		}
//		attrs["or"] = types.ListType{
//			ElemType: types.ObjectType{
//				AttrTypes: GetRecursiveFilterAttrType(depth+1, maxDepth),
//			},
//		}
//	}
//
//	return attrs
//}

func RootModelToSDKFilter(ctx context.Context, model *RootFilterModel) filterTypes.FilterRoot {
	tflog.Debug(ctx, "Converting root filter model to SDK type")
	if model == nil {
		tflog.Trace(ctx, "Root filter model is nil, returning empty FilterRoot")
		return filterTypes.NewRootFilter(nil, nil)
	}

	var andFilters []filterTypes.Filter
	if len(model.And) > 0 {
		andFilters = make([]filterTypes.Filter, 0, len(model.And))
		for i := range model.And {
			andFilters = append(andFilters, NestedModelToSDKFilter(ctx, &model.And[i]))
		}
	}

	var orFilters []filterTypes.Filter
	if len(model.Or) > 0 {
		orFilters = make([]filterTypes.Filter, 0, len(model.Or))
		for i := range model.Or {
			orFilters = append(orFilters, NestedModelToSDKFilter(ctx, &model.Or[i]))
		}
	}

	return filterTypes.NewRootFilter(andFilters, orFilters)
}

func NestedModelToSDKFilter(ctx context.Context, model *NestedFilterModel) filterTypes.Filter {
	tflog.Debug(ctx, "Converting nested filter model to SDK type")
	if model == nil {
		tflog.Trace(ctx, "Nested filter model is nil, returning nil")
		return nil
	}

	isSearch := !model.SearchField.IsNull() && !model.SearchField.IsUnknown() && model.SearchField.ValueString() != ""
	hasAnd := len(model.And) > 0
	hasOr := len(model.Or) > 0

	if hasAnd {
		filters := make([]filterTypes.Filter, 0, len(model.And))
		for i := range model.And {
			filters = append(filters, NestedModelToSDKFilter(ctx, &model.And[i]))
		}
		return filterTypes.NewAndFilter(filters...)
	}

	if hasOr {
		filters := make([]filterTypes.Filter, 0, len(model.Or))
		for i := range model.Or {
			filters = append(filters, NestedModelToSDKFilter(ctx, &model.Or[i]))
		}
		return filterTypes.NewOrFilter(filters...)
	}

	if isSearch {
		searchField := model.SearchField.ValueString()
		searchType := model.SearchType.ValueString()
		searchValue := model.SearchValue.ValueString()

		// Search types such as JSON_WILDCARD and JSON_WILDCARD_NOT require SEARCH_VALUE to be sent as
		// a native JSON object rather than a JSON-encoded string. Practitioners
		// express these with jsonencode(...) in configuration, so the encoded
		// text is forwarded verbatim as raw JSON.
		if enums.IsJSONValuedSearchType(searchType) {
			raw := json.RawMessage(searchValue)
			if filter, err := filterTypes.NewSearchFilterRawJSON(searchField, searchType, raw); err == nil {
				return filter
			} else {
				tflog.Error(ctx, "search_value is not valid JSON for a JSON-valued search type; sending it as a string", map[string]any{"error": err})
			}
		}

		return filterTypes.NewSearchFilter(searchField, searchType, searchValue)
	}

	return nil
}

func SDKToModel(ctx context.Context, sdkFilter filterTypes.FilterRoot) *RootFilterModel {
	tflog.Debug(ctx, "Converting SDK filter to root model type")

	jsonData, err := json.Marshal(sdkFilter)
	if err != nil {
		tflog.Error(ctx, "SDKToModel: Failed to marshal SDK filter", map[string]any{"error": err})
		return nil
	}

	if string(jsonData) == "null" {
		tflog.Trace(ctx, "SDK filter is nil, returning nil")
		return nil
	}

	var model RootFilterModel
	if err := json.Unmarshal(jsonData, &model); err != nil {
		tflog.Error(ctx, "SDKToModel: Failed to unmarshal filter model", map[string]any{"error": err})
		return nil
	}

	return &model
}
