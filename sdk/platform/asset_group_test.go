// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package platform

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"

	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/enums"
	filterTypes "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/types/filter"
	platformTypes "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/types/platform"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClient_CreateAssetGroup(t *testing.T) {
	t.Run("should create asset group successfully", func(t *testing.T) {
		membershipPredicate := filterTypes.NewRootFilter(
			[]filterTypes.Filter{
				filterTypes.NewSearchFilter(
					"xdm.asset.name",
					enums.SearchTypeNotContains.String(),
					"test",
				),
			},
			[]filterTypes.Filter{},
		)

		type requestWrapper struct {
			RequestData struct {
				AssetGroup platformTypes.CreateOrUpdateAssetGroupRequest `json:"asset_group"`
			} `json:"request_data"`
		}

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodPost, r.Method)
			assert.Equal(t, fmt.Sprintf("/%s", CreateAssetGroupEndpoint), r.URL.Path)

			var req requestWrapper
			err := json.NewDecoder(r.Body).Decode(&req)
			require.NoError(t, err)
			assert.Equal(t, "New Group", req.RequestData.AssetGroup.GroupName)
			assert.Equal(t, "Dynamic", req.RequestData.AssetGroup.GroupType)
			assert.Equal(t, "Description for New Group", req.RequestData.AssetGroup.GroupDescription)
			assert.Equal(t, membershipPredicate, req.RequestData.AssetGroup.MembershipPredicate)

			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"reply":{"data":{"success":true,"asset_group_id":123}}}`)
		})
		client, server := setupTest(t, handler)
		defer server.Close()

		createReq := platformTypes.CreateOrUpdateAssetGroupRequest{
			GroupName:           "New Group",
			GroupType:           "Dynamic",
			GroupDescription:    "Description for New Group",
			MembershipPredicate: membershipPredicate,
		}

		success, groupID, err := client.CreateAssetGroup(context.Background(), createReq)
		assert.NoError(t, err)
		assert.True(t, success)
		assert.Equal(t, 123, groupID)
	})
}

func TestClient_UpdateAssetGroup(t *testing.T) {
	t.Run("should update asset group successfully", func(t *testing.T) {
		requestURL := fmt.Sprintf("/%s123", UpdateAssetGroupEndpoint)

		type requestWrapper struct {
			RequestData struct {
				AssetGroup platformTypes.CreateOrUpdateAssetGroupRequest `json:"asset_group"`
			} `json:"request_data"`
		}

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodPost, r.Method)
			assert.Equal(t, requestURL, r.URL.Path)

			var req requestWrapper
			body, readBodyErr := io.ReadAll(r.Body)
			require.NoError(t, readBodyErr)

			unmarshalErr := json.Unmarshal(body, &req)
			require.NoError(t, unmarshalErr)

			assert.Equal(t, "Updated Name", req.RequestData.AssetGroup.GroupName)
			assert.Equal(t, "Updated Description", req.RequestData.AssetGroup.GroupDescription)

			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"reply":{"data":{"success":true}}}`)
		})
		client, server := setupTest(t, handler)
		defer server.Close()

		updateReq := platformTypes.CreateOrUpdateAssetGroupRequest{
			GroupName:        "Updated Name",
			GroupDescription: "Updated Description",
		}

		success, err := client.UpdateAssetGroup(context.Background(), 123, updateReq)
		assert.NoError(t, err)
		assert.True(t, success)
	})
}

func TestClient_DeleteAssetGroup(t *testing.T) {
	t.Run("should delete asset group successfully", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodPost, r.Method)
			assert.Equal(t, fmt.Sprintf("/%s123", DeleteAssetGroupEndpoint), r.URL.Path)

			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"reply":{"data":{"success":true}}}`)
		})
		client, server := setupTest(t, handler)
		defer server.Close()

		success, err := client.DeleteAssetGroup(context.Background(), 123)
		assert.NoError(t, err)
		assert.True(t, success)
	})
}

func TestClient_ListAssetGroups(t *testing.T) {
	t.Run("should list asset groups successfully", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodPost, r.Method)
			assert.Equal(t, "/"+ListAssetGroupsEndpoint, r.URL.Path)
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{
				"reply": {
					"data": [
						{
							"XDM.ASSET_GROUP.ID": 1,
							"XDM.ASSET_GROUP.NAME": "grp_pcs_lab",
							"XDM.ASSET_GROUP.TYPE": "Dynamic",
							"XDM.ASSET_GROUP.DESCRIPTION": "test description"
						}
					]
				}
			}`)
		})
		client, server := setupTest(t, handler)
		defer server.Close()

		groups, err := client.ListAssetGroups(context.Background(), platformTypes.ListAssetGroupsRequest{})
		assert.NoError(t, err)
		assert.Len(t, groups, 1)
		assert.Equal(t, 1, groups[0].ID)
		assert.Equal(t, "grp_pcs_lab", groups[0].Name)
		assert.Equal(t, "Dynamic", groups[0].Type)
		assert.Equal(t, "test description", groups[0].Description)
	})
}
