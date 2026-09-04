// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package compliance

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	types "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/types/compliance"
	util "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/types/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClient_CreateStandard(t *testing.T) {
	t.Run("should create standard successfully", func(t *testing.T) {
		type requestWrapper struct {
			RequestData types.CreateStandardRequest `json:"request_data"`
		}

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodPost, r.Method)
			assert.Equal(t, fmt.Sprintf("/%s", CreateStandardEndpoint), r.URL.Path)

			var req requestWrapper
			err := json.NewDecoder(r.Body).Decode(&req)
			require.NoError(t, err)
			assert.Equal(t, "Custom Security Framework 2024", req.RequestData.StandardName)
			assert.Equal(t, "Internal security compliance framework", req.RequestData.Description)
			assert.Equal(t, []string{"aws", "azure", "gcp", "oci"}, req.RequestData.Labels)
			assert.Len(t, req.RequestData.ControlsIDs, 2)

			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"reply":{"success":true}}`)
		})
		client, server := setupTest(t, handler)
		defer server.Close()

		createReq := types.CreateStandardRequest{
			StandardName: "Custom Security Framework 2024",
			Description:  "Internal security compliance framework",
			Labels:       []string{"aws", "azure", "gcp", "oci"},
			ControlsIDs: []string{
				"48f2f6a9fde049479e9c8c8eda0be163",
				"59g3g7b0gef150580f0d9d9feb1cf274",
			},
		}

		success, err := client.CreateStandard(context.Background(), createReq)
		assert.NoError(t, err)
		assert.True(t, success)
	})
}

func TestClient_GetStandard(t *testing.T) {
	t.Run("should get standard successfully", func(t *testing.T) {
		type requestWrapper struct {
			RequestData types.GetStandardRequest `json:"request_data"`
		}

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodPost, r.Method)
			assert.Equal(t, fmt.Sprintf("/%s", GetStandardEndpoint), r.URL.Path)

			var req requestWrapper
			err := json.NewDecoder(r.Body).Decode(&req)
			require.NoError(t, err)
			assert.Equal(t, "36ed307155e446938f157e3ed214fd72", req.RequestData.ID)

			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{
				"reply": {
					"standard": [
						{
							"id": "36ed307155e446938f157e3ed214fd72",
							"name": "CIS AWS Foundations Benchmark v1.4.0",
							"description": "CIS Amazon Web Services Foundations Benchmark",
							"version": "1.4.0",
							"assessments_profiles_count": 3,
							"controls_ids": [
								"0b0b5304d06d44ffb3d7465855378185",
								"98497e7bf21f413b9df0d84ccb8857d0"
							],
							"labels": ["aws", "azure", "gcp"],
							"revision": 8279863739578999000,
							"publisher": "Center for Internet Security",
							"release_date": "2025-06-18",
							"created_date": "2025-06-18",
							"created_by": "Palo Alto Networks",
							"insert_ts": 1750247411000,
							"modify_ts": 1750247413000,
							"is_custom": false
						}
					]
				}
			}`)
		})
		client, server := setupTest(t, handler)
		defer server.Close()

		getReq := types.GetStandardRequest{
			ID: "36ed307155e446938f157e3ed214fd72",
		}

		standard, err := client.GetStandard(context.Background(), getReq)
		assert.NoError(t, err)
		require.NotNil(t, standard)
		assert.Equal(t, "36ed307155e446938f157e3ed214fd72", standard.ID)
		assert.Equal(t, "CIS AWS Foundations Benchmark v1.4.0", standard.Name)
		assert.Equal(t, "1.4.0", standard.Version)
		assert.Equal(t, 3, standard.AssessmentsProfilesCount)
		assert.Equal(t, []string{"aws", "azure", "gcp"}, standard.Labels)
		assert.Equal(t, "Center for Internet Security", standard.Publisher)
		assert.False(t, standard.IsCustom)
	})
}

func TestClient_UpdateStandard(t *testing.T) {
	t.Run("should update standard successfully", func(t *testing.T) {
		type requestWrapper struct {
			RequestData interface{} `json:"request_data"`
		}

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodPost, r.Method)

			// UpdateStandard calls GetStandard internally, so handle both endpoints
			if r.URL.Path == fmt.Sprintf("/%s", GetStandardEndpoint) {
				// Handle GET request (called by UpdateStandard internally)
				w.WriteHeader(http.StatusOK)
				fmt.Fprint(w, `{
					"reply": {
						"standard": [
							{
								"id": "48e2f6a9fdc049479e9c6a8eda0bd163",
								"name": "Original Framework Name",
								"description": "Original description",
								"labels": ["original"],
								"controls_ids": []
							}
						]
					}
				}`)
				return
			}

			// Handle UPDATE request
			assert.Equal(t, fmt.Sprintf("/%s", UpdateStandardEndpoint), r.URL.Path)

			var req requestWrapper
			err := json.NewDecoder(r.Body).Decode(&req)
			require.NoError(t, err)

			// Convert to map for flexible assertion
			reqMap := req.RequestData.(map[string]interface{})
			assert.Equal(t, "48e2f6a9fdc049479e9c6a8eda0bd163", reqMap["id"])
			assert.Equal(t, "Updated Framework Name", reqMap["standard_name"])

			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"reply":{"success":true}}`)
		})
		client, server := setupTest(t, handler)
		defer server.Close()

		updateReq := types.UpdateStandardRequest{
			ID:           "48e2f6a9fdc049479e9c6a8eda0bd163",
			StandardName: "Updated Framework Name",
			Labels:       []string{"aws", "security"},
		}

		success, err := client.UpdateStandard(context.Background(), updateReq)
		assert.NoError(t, err)
		assert.True(t, success)
	})
}

func TestClient_DeleteStandard(t *testing.T) {
	t.Run("should delete standard successfully", func(t *testing.T) {
		type requestWrapper struct {
			RequestData types.DeleteStandardRequest `json:"request_data"`
		}

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodPost, r.Method)
			assert.Equal(t, fmt.Sprintf("/%s", DeleteStandardEndpoint), r.URL.Path)

			var req requestWrapper
			err := json.NewDecoder(r.Body).Decode(&req)
			require.NoError(t, err)
			assert.Equal(t, "f9f764717b284e9483f9c1210ed3149d", req.RequestData.ID)

			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"reply":{"success":true}}`)
		})
		client, server := setupTest(t, handler)
		defer server.Close()

		deleteReq := types.DeleteStandardRequest{
			ID: "f9f764717b284e9483f9c1210ed3149d",
		}

		success, err := client.DeleteStandard(context.Background(), deleteReq)
		assert.NoError(t, err)
		assert.True(t, success)
	})
}

func TestClient_ListStandards(t *testing.T) {
	t.Run("should list standards successfully", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodPost, r.Method)
			assert.Equal(t, "/"+ListStandardsEndpoint, r.URL.Path)

			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{
				"reply": {
					"total_count": 17,
					"result_count": 2,
					"standards": [
						{
							"id": "394fc8fc210645f6af8bb4267321482a",
							"name": "CIS AWS Foundations Benchmark",
							"description": "Comprehensive security benchmark for AWS",
							"version": "1.4.0",
							"assessments_profiles_count": 5,
							"controls_ids": ["ctrl-1", "ctrl-2"],
							"labels": ["aws", "azure", "gcp"],
							"revision": -6043636965775741000,
							"publisher": "Center for Internet Security",
							"release_date": "2025-06-18",
							"created_date": "2025-06-18",
							"created_by": "Palo Alto Networks",
							"insert_ts": 1750247438000,
							"modify_ts": 1750247439000,
							"is_custom": false
						},
						{
							"id": "495gd9gd321756g7bg9cc5378432593b",
							"name": "Custom Security Framework",
							"description": "Internal compliance framework",
							"version": "1.0.0",
							"assessments_profiles_count": 2,
							"controls_ids": ["ctrl-3", "ctrl-4"],
							"labels": ["custom", "internal"],
							"revision": 1234567890123456000,
							"publisher": "Internal Team",
							"release_date": "2025-10-01",
							"created_date": "2025-10-01",
							"created_by": "Admin User",
							"insert_ts": 1750247500000,
							"modify_ts": 1750247500000,
							"is_custom": true
						}
					]
				}
			}`)
		})
		client, server := setupTest(t, handler)
		defer server.Close()

		listReq := types.ListStandardsRequest{}
		resp, err := client.ListStandards(context.Background(), listReq)
		assert.NoError(t, err)
		require.NotNil(t, resp)
		assert.Equal(t, 17, resp.TotalCount)
		assert.Equal(t, 2, resp.ResultCount)
		assert.Len(t, resp.Standards, 2)

		// Verify first standard
		assert.Equal(t, "394fc8fc210645f6af8bb4267321482a", resp.Standards[0].ID)
		assert.Equal(t, "CIS AWS Foundations Benchmark", resp.Standards[0].Name)
		assert.Equal(t, "1.4.0", resp.Standards[0].Version)
		assert.Equal(t, 5, resp.Standards[0].AssessmentsProfilesCount)
		assert.False(t, resp.Standards[0].IsCustom)

		// Verify second standard
		assert.Equal(t, "495gd9gd321756g7bg9cc5378432593b", resp.Standards[1].ID)
		assert.Equal(t, "Custom Security Framework", resp.Standards[1].Name)
		assert.True(t, resp.Standards[1].IsCustom)
	})

	t.Run("should list standards with filters", func(t *testing.T) {
		type requestWrapper struct {
			RequestData types.ListStandardsRequest `json:"request_data"`
		}

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req requestWrapper
			err := json.NewDecoder(r.Body).Decode(&req)
			require.NoError(t, err)
			assert.Len(t, req.RequestData.Filters, 2)
			assert.Equal(t, "is_custom", req.RequestData.Filters[0].Field)
			assert.Equal(t, "in", req.RequestData.Filters[0].Operator)
			assert.Equal(t, []interface{}{"yes"}, req.RequestData.Filters[0].Value)
			assert.Equal(t, "labels", req.RequestData.Filters[1].Field)
			assert.Equal(t, "contains", req.RequestData.Filters[1].Operator)
			assert.Equal(t, "aws", req.RequestData.Filters[1].Value)

			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"reply":{"total_count":5,"result_count":5,"standards":[]}}`)
		})
		client, server := setupTest(t, handler)
		defer server.Close()

		listReq := types.ListStandardsRequest{
			Filters: []types.Filter{
				{
					Field:    "is_custom",
					Operator: "in",
					Value:    []string{"yes"},
				},
				{
					Field:    "labels",
					Operator: "contains",
					Value:    "aws",
				},
			},
		}
		resp, err := client.ListStandards(context.Background(), listReq)
		assert.NoError(t, err)
		require.NotNil(t, resp)
		assert.Equal(t, 5, resp.TotalCount)
	})

	t.Run("should list standards with pagination and sorting", func(t *testing.T) {
		type requestWrapper struct {
			RequestData types.ListStandardsRequest `json:"request_data"`
		}

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req requestWrapper
			err := json.NewDecoder(r.Body).Decode(&req)
			require.NoError(t, err)
			require.NotNil(t, req.RequestData.SearchFrom)
			require.NotNil(t, req.RequestData.SearchTo)
			assert.Equal(t, 0, *req.RequestData.SearchFrom)
			assert.Equal(t, 24, *req.RequestData.SearchTo)
			require.NotNil(t, req.RequestData.Sort)
			assert.Equal(t, "insertion_time", req.RequestData.Sort.Field)
			assert.Equal(t, "desc", req.RequestData.Sort.Keyword)

			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"reply":{"total_count":100,"result_count":25,"standards":[]}}`)
		})
		client, server := setupTest(t, handler)
		defer server.Close()

		listReq := types.ListStandardsRequest{
			SearchFrom: util.ToPointer(0),
			SearchTo:   util.ToPointer(24),
			Sort: &types.SortFilter{
				Field:   "insertion_time",
				Keyword: "desc",
			},
		}
		resp, err := client.ListStandards(context.Background(), listReq)
		assert.NoError(t, err)
		require.NotNil(t, resp)
		assert.Equal(t, 100, resp.TotalCount)
		assert.Equal(t, 25, resp.ResultCount)
	})
}
