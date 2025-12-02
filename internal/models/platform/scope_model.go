// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package models

import (
	"context"
	"strings"

	platformtypes "github.com/PaloAltoNetworks/cortex-cloud-go/types/platform"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// ScopeModel is the model for the scope resource.
type ScopeModel struct {
	ID           types.String       `tfsdk:"id"`
	EntityType   types.String       `tfsdk:"entity_type"`
	EntityID     types.String       `tfsdk:"entity_id"`
	Assets       *AssetsModel       `tfsdk:"assets"`
	DatasetsRows *DatasetsRowsModel `tfsdk:"datasets_rows"`
	Endpoints    *EndpointsModel    `tfsdk:"endpoints"`
	CasesIssues  *CasesIssuesModel  `tfsdk:"cases_issues"`
}

// AssetsModel represents the "assets" section in a Scope.
type AssetsModel struct {
	Mode        types.String              `tfsdk:"mode"`
	AssetGroups []ScopeAssetGroupRefModel `tfsdk:"asset_groups"`
}

// ScopeAssetGroupRefModel
type ScopeAssetGroupRefModel struct {
	AssetGroupID   types.Int64  `tfsdk:"asset_group_id"`
	AssetGroupName types.String `tfsdk:"asset_group_name"`
}

// DatasetsRowsModel is the model for the datasets rows scope.
type DatasetsRowsModel struct {
	DefaultFilterMode types.String  `tfsdk:"default_filter_mode"`
	Filters           []FilterModel `tfsdk:"filters"`
}

// FilterModel is the model for a filter in the datasets rows scope.
type FilterModel struct {
	Dataset types.String `tfsdk:"dataset"`
	Filter  types.String `tfsdk:"filter"`
}

// EndpointsModel is the model for the endpoints scope.
type EndpointsModel struct {
	EndpointGroups *EndpointGroupsModel `tfsdk:"endpoint_groups"`
	EndpointTags   *EndpointTagsModel   `tfsdk:"endpoint_tags"`
}

// EndpointGroupsModel is the model for the endpoint groups scope.
type EndpointGroupsModel struct {
	Mode types.String `tfsdk:"mode"`
	Tags []TagModel   `tfsdk:"tags"`
}

// EndpointTagsModel is the model for the endpoint tags scope.
type EndpointTagsModel struct {
	Mode types.String `tfsdk:"mode"`
	Tags []TagModel   `tfsdk:"tags"`
}

// CasesIssuesModel is the model for the cases issues scope.
type CasesIssuesModel struct {
	Mode types.String `tfsdk:"mode"`
	Tags []TagModel   `tfsdk:"tags"`
}

// TagModel is the model for a tag in the scope.
type TagModel struct {
	TagID   types.String `tfsdk:"tag_id"`
	TagName types.String `tfsdk:"tag_name"`
}

// ToEditRequest converts the model to an EditScopeRequestData for the SDK.
func (m *ScopeModel) ToEditRequest() platformtypes.EditScopeRequestData {
	// ---------- Assets ----------
	var assets *platformtypes.EditAssets = &platformtypes.EditAssets{
		Mode:          "no_scope",
		AssetGroupIDs: make([]int, 0),
	}
	if m.Assets != nil {
		assetGroupIDs := make([]int, 0, len(m.Assets.AssetGroups))
		for _, ag := range m.Assets.AssetGroups {
			if !ag.AssetGroupID.IsNull() && !ag.AssetGroupID.IsUnknown() {
				assetGroupIDs = append(assetGroupIDs, int(ag.AssetGroupID.ValueInt64()))
			}
		}
		assets = &platformtypes.EditAssets{
			Mode:          m.Assets.Mode.ValueString(),
			AssetGroupIDs: assetGroupIDs, // [] -> JSON []
		}
	}

	// ---------- DatasetsRows ----------
	var datasetsRows *platformtypes.EditDatasetsRows = &platformtypes.EditDatasetsRows{
		Filters:           make([]platformtypes.Filter, 0),
		DefaultFilterMode: "no_scope",
	}
	if m.DatasetsRows != nil {
		filters := make([]platformtypes.Filter, 0, len(m.DatasetsRows.Filters))
		for _, f := range m.DatasetsRows.Filters {
			filters = append(filters, platformtypes.Filter{
				Dataset: f.Dataset.ValueString(),
				Filter:  f.Filter.ValueString(),
			})
		}
		datasetsRows = &platformtypes.EditDatasetsRows{
			DefaultFilterMode: m.DatasetsRows.DefaultFilterMode.ValueString(),
			Filters:           filters, // [] -> JSON []
		}
	}

	// ---------- Endpoints ----------
	var endpoints *platformtypes.EditEndpoints = &platformtypes.EditEndpoints{
		EndpointGroups: &platformtypes.EditEndpointGroups{
			Names: make([]string, 0),
			Mode:  "no_scope",
		},
		EndpointTags: &platformtypes.EditEndpointTags{
			Names: make([]string, 0),
			Mode:  "no_scope",
		},
	}
	if m.Endpoints != nil {
		var endpointGroups *platformtypes.EditEndpointGroups = &platformtypes.EditEndpointGroups{
			Names: make([]string, 0),
			Mode:  "no_scope",
		}
		if m.Endpoints.EndpointGroups != nil {
			names := make([]string, 0, len(m.Endpoints.EndpointGroups.Tags))
			for _, t := range m.Endpoints.EndpointGroups.Tags {
				if !t.TagName.IsNull() && !t.TagName.IsUnknown() {
					names = append(names, t.TagName.ValueString())
				}
			}
			endpointGroups = &platformtypes.EditEndpointGroups{
				Mode:  m.Endpoints.EndpointGroups.Mode.ValueString(),
				Names: names, // [] -> JSON []
			}
		}

		var endpointTags *platformtypes.EditEndpointTags = &platformtypes.EditEndpointTags{
			Names: make([]string, 0),
			Mode:  "no_scope",
		}
		if m.Endpoints.EndpointTags != nil {
			names := make([]string, 0, len(m.Endpoints.EndpointTags.Tags))
			for _, t := range m.Endpoints.EndpointTags.Tags {
				if !t.TagName.IsNull() && !t.TagName.IsUnknown() {
					names = append(names, t.TagName.ValueString())
				}
			}
			endpointTags = &platformtypes.EditEndpointTags{
				Mode:  m.Endpoints.EndpointTags.Mode.ValueString(), // Allow "any"
				Names: names,                                       // [] -> JSON []
			}
		}

		endpoints = &platformtypes.EditEndpoints{
			EndpointGroups: endpointGroups,
			EndpointTags:   endpointTags,
		}
	}

	// ---------- CasesIssues ----------
	var casesIssues *platformtypes.EditCasesIssues = &platformtypes.EditCasesIssues{
		Names: make([]string, 0),
		Mode:  "no_scope",
	}
	if m.CasesIssues != nil {
		names := make([]string, 0, len(m.CasesIssues.Tags))
		for _, t := range m.CasesIssues.Tags {
			if !t.TagName.IsNull() && !t.TagName.IsUnknown() {
				names = append(names, t.TagName.ValueString())
			}
		}
		casesIssues = &platformtypes.EditCasesIssues{
			Mode:  m.CasesIssues.Mode.ValueString(),
			Names: names, // [] -> JSON []
		}
	}

	return platformtypes.EditScopeRequestData{
		Assets:       assets,
		DatasetsRows: datasetsRows,
		Endpoints:    endpoints,
		CasesIssues:  casesIssues,
	}
}

// RefreshFromRemote populates the model from the SDK's Scope object.
func (m *ScopeModel) RefreshFromRemote(ctx context.Context, diags *diag.Diagnostics, remote *platformtypes.Scope) {
	if remote == nil {
		return
	}

	// ---------- Assets ----------
	if remote.Assets != nil {
		m.Assets = &AssetsModel{
			Mode: types.StringValue(remote.Assets.Mode),
		}
		if len(remote.Assets.AssetGroups) > 0 {
			ags := make([]ScopeAssetGroupRefModel, 0, len(remote.Assets.AssetGroups))
			for _, ag := range remote.Assets.AssetGroups {
				ags = append(ags, ScopeAssetGroupRefModel{
					AssetGroupID:   types.Int64Value(int64(ag.ID)),
					AssetGroupName: types.StringValue(ag.Name),
				})
			}
			m.Assets.AssetGroups = ags
		} else {
			m.Assets.AssetGroups = make([]ScopeAssetGroupRefModel, 0)
		}
	}

	// ---------- DatasetsRows ----------
	if remote.DatasetsRows != nil {
		m.DatasetsRows = &DatasetsRowsModel{
			DefaultFilterMode: types.StringValue(remote.DatasetsRows.DefaultFilterMode),
		}
		if len(remote.DatasetsRows.Filters) > 0 {
			fs := make([]FilterModel, 0, len(remote.DatasetsRows.Filters))
			for _, f := range remote.DatasetsRows.Filters {
				fs = append(fs, FilterModel{
					Dataset: types.StringValue(f.Dataset),
					Filter:  types.StringValue(f.Filter),
				})
			}
			m.DatasetsRows.Filters = fs
		} else {
			m.DatasetsRows.Filters = make([]FilterModel, 0) // []
		}
	}

	// ---------- Endpoints ----------
	if remote.Endpoints != nil {
		m.Endpoints = &EndpointsModel{}

		// endpoint_groups
		if remote.Endpoints.EndpointGroups != nil {
			eg := &EndpointGroupsModel{
				Mode: types.StringValue(strings.ToLower(remote.Endpoints.EndpointGroups.Mode)),
			}
			if len(remote.Endpoints.EndpointGroups.Tags) > 0 {
				tags := make([]TagModel, 0, len(remote.Endpoints.EndpointGroups.Tags))
				for _, t := range remote.Endpoints.EndpointGroups.Tags {
					tags = append(tags, TagModel{
						TagID:   types.StringPointerValue(nilIfEmpty(t.TagID)),
						TagName: types.StringValue(t.TagName),
					})
				}
				eg.Tags = tags
			} else {
				eg.Tags = nil
			}
			m.Endpoints.EndpointGroups = eg
		}

		// endpoint_tags
		if remote.Endpoints.EndpointTags != nil {
			mode := strings.ToLower(remote.Endpoints.EndpointTags.Mode) // "Any" -> "any"
			et := &EndpointTagsModel{
				Mode: types.StringValue(mode),
			}

			if mode == "any" {
				et.Tags = make([]TagModel, 0)
			} else if len(remote.Endpoints.EndpointTags.Tags) > 0 {
				tags := make([]TagModel, 0, len(remote.Endpoints.EndpointTags.Tags))
				for _, t := range remote.Endpoints.EndpointTags.Tags {
					tags = append(tags, TagModel{
						TagID:   types.StringPointerValue(nilIfEmpty(t.TagID)),
						TagName: types.StringValue(t.TagName),
					})
				}
				et.Tags = tags
			} else {
				et.Tags = make([]TagModel, 0) // []
			}
			m.Endpoints.EndpointTags = et
		}
	}

	// ---------- Cases / Issues ----------
	if remote.CasesIssues != nil {
		ci := &CasesIssuesModel{
			Mode: types.StringValue(strings.ToLower(remote.CasesIssues.Mode)),
		}
		if len(remote.CasesIssues.Tags) > 0 {
			tags := make([]TagModel, 0, len(remote.CasesIssues.Tags))
			for _, t := range remote.CasesIssues.Tags {
				tags = append(tags, TagModel{
					TagID:   types.StringPointerValue(nilIfEmpty(t.TagID)),
					TagName: types.StringValue(t.TagName),
				})
			}
			ci.Tags = tags
		} else {
			ci.Tags = make([]TagModel, 0)
		}
		m.CasesIssues = ci
	}
}

func nilIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
