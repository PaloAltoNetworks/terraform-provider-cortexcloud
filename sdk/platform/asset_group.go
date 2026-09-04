// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package platform

import (
	"context"
	"net/http"
	"strconv"

	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/internal/client"
	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/types/platform"
)

// GenericAssetGroupsRespons is a generic response for asset group operations.
type genericAssetGroupsResponse struct {
	Success      bool `json:"success"`
	AssetGroupID int  `json:"asset_group_id"`
}

// CreateAssetGroup creates a new asset group.
func (c *Client) CreateAssetGroup(ctx context.Context, req types.CreateOrUpdateAssetGroupRequest) (success bool, assetGroupID int, err error) {
	var resp genericAssetGroupsResponse
	_, err = c.internalClient.Do(ctx, http.MethodPost, CreateAssetGroupEndpoint, nil, nil, req, &resp, &client.DoOptions{
		RequestWrapperKeys:  []string{"request_data", "asset_group"},
		ResponseWrapperKeys: []string{"reply", "data"},
	})
	return resp.Success, resp.AssetGroupID, err
}

// ListAssetGroups retrieves a list of asset groups.
func (c *Client) ListAssetGroups(ctx context.Context, req types.ListAssetGroupsRequest) (assetGroups []types.AssetGroup, err error) {
	var resp []types.AssetGroup
	_, err = c.internalClient.Do(ctx, http.MethodPost, ListAssetGroupsEndpoint, nil, nil, req, &resp, &client.DoOptions{
		RequestWrapperKeys:  []string{"request_data"},
		ResponseWrapperKeys: []string{"reply", "data"},
	})
	return resp, err
}

// UpdateAssetGroup updates an existing asset group.
func (c *Client) UpdateAssetGroup(ctx context.Context, groupID int, req types.CreateOrUpdateAssetGroupRequest) (success bool, err error) {
	var resp genericAssetGroupsResponse
	_, err = c.internalClient.Do(ctx, http.MethodPost, UpdateAssetGroupEndpoint, &[]string{strconv.Itoa(groupID)}, nil, req, &resp, &client.DoOptions{
		RequestWrapperKeys:  []string{"request_data", "asset_group"},
		ResponseWrapperKeys: []string{"reply", "data"},
	})
	return resp.Success, err
}

// DeleteAssetGroup deletes an asset group.
func (c *Client) DeleteAssetGroup(ctx context.Context, groupID int) (success bool, err error) {
	var resp genericAssetGroupsResponse
	_, err = c.internalClient.Do(ctx, http.MethodPost, DeleteAssetGroupEndpoint, &[]string{strconv.Itoa(groupID)}, nil, nil, &resp, &client.DoOptions{
		ResponseWrapperKeys: []string{"reply", "data"},
	})
	return resp.Success, err
}
