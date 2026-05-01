package models

import (
	"context"
	"encoding/json"

	filterTypes "github.com/PaloAltoNetworks/cortex-cloud-go/types/filter"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listdefault"
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

func (m *NestedFilterModel) UnmarshalJSON(data []byte) error {
	var temp struct {
		And         []NestedFilterModel `json:"AND,omitempty"`
		Or          []NestedFilterModel `json:"OR,omitempty"`
		SearchField string              `json:"SEARCH_FIELD,omitempty"`
		SearchType  string              `json:"SEARCH_TYPE,omitempty"`
		SearchValue string              `json:"SEARCH_VALUE,omitempty"`
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
	if temp.SearchValue != "" {
		m.SearchValue = types.StringValue(temp.SearchValue)
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
			Optional: true,
		},
		"search_type": schema.StringAttribute{
			Optional: true,
		},
		"search_value": schema.StringAttribute{
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
		return filterTypes.NewSearchFilter(
			model.SearchField.ValueString(),
			model.SearchType.ValueString(),
			model.SearchValue.ValueString(),
		)
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
