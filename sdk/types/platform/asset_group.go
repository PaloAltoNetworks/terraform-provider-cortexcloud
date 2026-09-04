// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package types

import (
	filterTypes "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/types/filter"
)

// ----------------------------------------------------------------------------
// Asset Group
// ----------------------------------------------------------------------------

// AssetGroup defines the structure for an asset group as returned by the API.
type AssetGroup struct {
	ID                  int                    `json:"XDM.ASSET_GROUP.ID"`
	Name                string                 `json:"XDM.ASSET_GROUP.NAME"`
	Type                string                 `json:"XDM.ASSET_GROUP.TYPE"`
	Description         string                 `json:"XDM.ASSET_GROUP.DESCRIPTION"`
	Filter              []AssetGroupFilter     `json:"XDM.ASSET_GROUP.FILTER"`
	CreationTime        int64                  `json:"XDM.ASSET_GROUP.CREATION_TIME"`
	CreatedBy           string                 `json:"XDM.ASSET_GROUP.CREATED_BY"`
	CreatedByPretty     string                 `json:"XDM.ASSET_GROUP.CREATED_BY_PRETTY"`
	LastUpdateTime      int64                  `json:"XDM.ASSET_GROUP.LAST_UPDATE_TIME"`
	ModifiedBy          string                 `json:"XDM.ASSET_GROUP.MODIFIED_BY"`
	ModifiedByPretty    string                 `json:"XDM.ASSET_GROUP.MODIFIED_BY_PRETTY"`
	MembershipPredicate filterTypes.FilterRoot `json:"XDM.ASSET_GROUP.MEMBERSHIP_PREDICATE"`
	IsUsedBySBAC        bool                   `json:"IS_USED_BY_SBAC"`
}

// AssetGroupFilter represents a filter component in the asset group list response.
type AssetGroupFilter struct {
	PrettyName string `json:"pretty_name"`
	DataType   string `json:"data_type"`
	RenderType string `json:"render_type"`
	EntityMap  any    `json:"entity_map"`
	DMLType    any    `json:"dml_type"`
}

// CreateOrUpdateAssetGroupRequest is the request for creating or updating an
// asset group.
type CreateOrUpdateAssetGroupRequest struct {
	GroupName           string                 `json:"group_name"`
	GroupType           string                 `json:"group_type"`
	GroupDescription    string                 `json:"group_description,omitempty"`
	MembershipPredicate filterTypes.FilterRoot `json:"membership_predicate"`
}

// ListAssetGroupsRequest is the request for listing asset groups.
type ListAssetGroupsRequest struct {
	Filters    filterTypes.Filter       `json:"filters"`
	Sort       []filterTypes.SortFilter `json:"sort,omitempty"`
	SearchFrom int                      `json:"search_from,omitempty"`
	SearchTo   int                      `json:"search_to,omitempty"`
}
