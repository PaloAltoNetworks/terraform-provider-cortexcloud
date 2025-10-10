// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package models

import (
	"context"
	"encoding/json"

	platformTypes "github.com/PaloAltoNetworks/cortex-cloud-go/types/platform"
	filterTypes "github.com/PaloAltoNetworks/cortex-cloud-go/types/filter"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// AssetGroupModel is the model for the asset_group resource.
type AssetGroupModel struct {
	ID                  types.Int64      `tfsdk:"id"`
	Name                types.String     `tfsdk:"name"`
	Type                types.String     `tfsdk:"type"`
	Description         types.String     `tfsdk:"description"`
	MembershipPredicate *RootFilterModel `tfsdk:"membership_predicate"`
	CreationTime        types.Int64      `tfsdk:"creation_time"`
	CreatedBy           types.String     `tfsdk:"created_by"`
	LastUpdateTime      types.Int64      `tfsdk:"last_update_time"`
	ModifiedBy          types.String     `tfsdk:"modified_by"`
}

// RefreshFromRemote refreshes the model from the remote API response.
func (m *AssetGroupModel) RefreshFromRemote(ctx context.Context, diags *diag.Diagnostics, remote *platformTypes.AssetGroup) {
	tflog.Debug(ctx, "Refreshing asset group model from remote")

	tflog.Trace(ctx, "Setting asset group attributes")
	m.ID = types.Int64Value(int64(remote.ID))
	m.Name = types.StringValue(remote.Name)
	m.Type = types.StringValue(remote.Type)
	m.Description = types.StringValue(remote.Description)
	m.CreationTime = types.Int64Value(remote.CreationTime)
	m.CreatedBy = types.StringValue(remote.CreatedBy)
	m.LastUpdateTime = types.Int64Value(remote.LastUpdateTime)
	m.ModifiedBy = types.StringValue(remote.ModifiedBy)
	m.MembershipPredicate = SDKToModel(ctx, remote.MembershipPredicate)
}

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
	m.SearchField = types.StringValue(temp.SearchField)
	m.SearchType = types.StringValue(temp.SearchType)
	m.SearchValue = types.StringValue(temp.SearchValue)

	return nil
}

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
			NestedObject: schema.NestedAttributeObject{
				Attributes: GetRecursiveFilterSchema(depth+1, maxDepth),
			},
		}
		attrs["or"] = schema.ListNestedAttribute{
			Optional: true,
			NestedObject: schema.NestedAttributeObject{
				Attributes: GetRecursiveFilterSchema(depth+1, maxDepth),
			},
		}
	}

	return attrs
}

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
