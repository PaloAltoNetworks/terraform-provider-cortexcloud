// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package models

import (
	"context"

	cortexTypes "github.com/PaloAltoNetworks/cortex-cloud-go/types"
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
func (m *AssetGroupModel) RefreshFromRemote(ctx context.Context, diags *diag.Diagnostics, remote *cortexTypes.AssetGroup) {
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
	m.MembershipPredicate = SDKToModel(ctx, &remote.MembershipPredicate)
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

func RootModelToSDKFilter(ctx context.Context, model *RootFilterModel) *cortexTypes.Filter {
	tflog.Debug(ctx, "Converting root filter model to SDK type")
	if model == nil {
		tflog.Trace(ctx, "Root filter model is nil, returning nil")
		return nil
	}

	sdkFilter := &cortexTypes.Filter{}

	for _, andFilterModel := range model.And {
		sdkFilter.And = append(sdkFilter.And, NestedModelToSDKFilter(ctx, &andFilterModel))
	}

	for _, orFilterModel := range model.Or {
		sdkFilter.Or = append(sdkFilter.Or, NestedModelToSDKFilter(ctx, &orFilterModel))
	}

	return sdkFilter
}

func NestedModelToSDKFilter(ctx context.Context, model *NestedFilterModel) *cortexTypes.Filter {
	tflog.Debug(ctx, "Converting nested filter model to SDK type")
	if model == nil {
		tflog.Trace(ctx, "Nested filter model is nil, returning nil")
		return nil
	}

	sdkFilter := &cortexTypes.Filter{
		SearchField: model.SearchField.ValueString(),
		SearchType:  model.SearchType.ValueString(),
		SearchValue: model.SearchValue.ValueString(),
	}
	tflog.Trace(ctx, "Converting search fields", map[string]any{
		"search_field": sdkFilter.SearchField,
		"search_type":  sdkFilter.SearchType,
		"search_value": sdkFilter.SearchValue,
	})

	for _, andFilterModel := range model.And {
		sdkFilter.And = append(sdkFilter.And, NestedModelToSDKFilter(ctx, &andFilterModel))
	}

	for _, orFilterModel := range model.Or {
		sdkFilter.Or = append(sdkFilter.Or, NestedModelToSDKFilter(ctx, &orFilterModel))
	}

	return sdkFilter
}

func SDKToModel(ctx context.Context, sdkFilter *cortexTypes.Filter) *RootFilterModel {
	tflog.Debug(ctx, "Converting SDK filter to root model type")
	if sdkFilter == nil {
		tflog.Trace(ctx, "SDK filter is nil, returning nil")
		return nil
	}

	model := &RootFilterModel{}

	for _, sdkAndFilter := range sdkFilter.And {
		model.And = append(model.And, *SDKToNestedModel(ctx, sdkAndFilter))
	}

	for _, sdkOrFilter := range sdkFilter.Or {
		model.Or = append(model.Or, *SDKToNestedModel(ctx, sdkOrFilter))
	}

	return model
}

func SDKToNestedModel(ctx context.Context, sdkFilter *cortexTypes.Filter) *NestedFilterModel {
	tflog.Debug(ctx, "Converting SDK filter to nested model type")
	if sdkFilter == nil {
		tflog.Trace(ctx, "SDK filter is nil, returning nil")
		return nil
	}

	model := &NestedFilterModel{
		SearchField: types.StringValue(sdkFilter.SearchField),
		SearchType:  types.StringValue(sdkFilter.SearchType),
		SearchValue: types.StringValue(sdkFilter.SearchValue),
	}
	tflog.Trace(ctx, "Converting search fields", map[string]any{
		"search_field": model.SearchField,
		"search_type":  model.SearchType,
		"search_value": model.SearchValue,
	})

	for _, sdkAndFilter := range sdkFilter.And {
		model.And = append(model.And, *SDKToNestedModel(ctx, sdkAndFilter))
	}

	for _, sdkOrFilter := range sdkFilter.Or {
		model.Or = append(model.Or, *SDKToNestedModel(ctx, sdkOrFilter))
	}

	return model
}
