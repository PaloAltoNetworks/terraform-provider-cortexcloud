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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClient_CreateAssessmentProfile(t *testing.T) {
	t.Run("should create assessment profile successfully", func(t *testing.T) {
		type requestWrapper struct {
			RequestData types.CreateAssessmentProfileRequest `json:"request_data"`
		}

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodPost, r.Method)
			assert.Equal(t, fmt.Sprintf("/%s", CreateAssessmentProfileEndpoint), r.URL.Path)

			var req requestWrapper
			err := json.NewDecoder(r.Body).Decode(&req)
			require.NoError(t, err)
			assert.Equal(t, "Production AWS Assessment", req.RequestData.ProfileName)
			assert.Equal(t, "ag-12345", req.RequestData.AssetGroupID)
			assert.Equal(t, "std-67890", req.RequestData.StandardID)
			assert.Equal(t, "Monthly compliance assessment", req.RequestData.Description)
			assert.Equal(t, "PDF", req.RequestData.ReportType)
			assert.Equal(t, "0 0 * * *", req.RequestData.EvaluationFrequency)

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"reply":{"success":true}}`)
		})
		client, server := setupTest(t, handler)
		defer server.Close()

		createReq := types.CreateAssessmentProfileRequest{
			ProfileName:         "Production AWS Assessment",
			AssetGroupID:        "ag-12345",
			StandardID:          "std-67890",
			Description:         "Monthly compliance assessment",
			ReportType:          "PDF",
			EvaluationFrequency: "0 0 * * *", // Daily at midnight
		}

		success, err := client.CreateAssessmentProfile(context.Background(), createReq)
		assert.NoError(t, err)
		assert.True(t, success)
	})
}

func TestClient_GetAssessmentProfile(t *testing.T) {
	t.Run("should get assessment profile successfully", func(t *testing.T) {
		type requestWrapper struct {
			RequestData types.GetAssessmentProfileRequest `json:"request_data"`
		}

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodPost, r.Method)
			assert.Equal(t, fmt.Sprintf("/%s", GetAssessmentProfileEndpoint), r.URL.Path)

			var req requestWrapper
			err := json.NewDecoder(r.Body).Decode(&req)
			require.NoError(t, err)
			assert.Equal(t, "472141782aff4a2f999c5e3c35745b3a", req.RequestData.ID)

			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{
				"reply": {
					"assessment_profile": [
						{
							"ID": "472141782aff4a2f999c5e3c35745b3a",
							"NAME": "Assessment example",
							"STANDARD_ID": "2nnd684-4z14-5cs82-c1a0-7c322b671844",
							"STANDARD_NAME": "CIS Amazon Linux 2 Benchmark v1.0.0",
							"ASSET_GROUP_ID": 1,
							"ASSET_GROUP_NAME": "asset group name",
							"DESCRIPTION": "assessment description",
							"REPORT_FREQUENCY": null,
							"REPORT_TARGETS": [],
							"REPORT_TYPE": "NONE",
							"ENABLED": true,
							"INSERT_TS": 1748259453615,
							"MODIFY_TS": 1748259453615,
							"CREATED_BY": "Generic Name",
							"MODIFIED_BY": "Generic Name"
						}
					]
				}
			}`)
		})
		client, server := setupTest(t, handler)
		defer server.Close()

		getReq := types.GetAssessmentProfileRequest{
			ID: "472141782aff4a2f999c5e3c35745b3a",
		}

		profile, err := client.GetAssessmentProfile(context.Background(), getReq)
		assert.NoError(t, err)
		require.NotNil(t, profile)
		assert.Equal(t, "472141782aff4a2f999c5e3c35745b3a", profile.ID)
		assert.Equal(t, "Assessment example", profile.Name)
		assert.Equal(t, "CIS Amazon Linux 2 Benchmark v1.0.0", profile.StandardName)
		assert.Equal(t, 1, profile.AssetGroupID)
		assert.True(t, profile.Enabled)
	})
}

func TestClient_UpdateAssessmentProfile(t *testing.T) {
	t.Run("should update assessment profile successfully", func(t *testing.T) {
		type requestWrapper struct {
			RequestData interface{} `json:"request_data"`
		}

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodPost, r.Method)

			// UpdateAssessmentProfile calls GetAssessmentProfile internally, so handle both endpoints
			if r.URL.Path == fmt.Sprintf("/%s", GetAssessmentProfileEndpoint) {
				// Handle GET request (called by UpdateAssessmentProfile internally)
				w.WriteHeader(http.StatusOK)
				fmt.Fprint(w, `{
					"reply": {
						"assessment_profile": [
							{
								"ID": "48e2f6a9fdc049479e9c6a8eda0bd163",
								"NAME": "Original Profile Name",
								"STANDARD_ID": "std-123",
								"ASSET_GROUP_ID": 1,
								"DESCRIPTION": "Original description",
								"REPORT_TYPE": "NONE",
								"REPORT_FREQUENCY": null,
								"REPORT_TARGETS": [],
								"ENABLED": true
							}
						]
					}
				}`)
				return
			}

			// Handle UPDATE request
			assert.Equal(t, fmt.Sprintf("/%s", UpdateAssessmentProfileEndpoint), r.URL.Path)

			var req requestWrapper
			err := json.NewDecoder(r.Body).Decode(&req)
			require.NoError(t, err)

			// Convert to map for flexible assertion
			reqMap := req.RequestData.(map[string]interface{})
			assert.Equal(t, "48e2f6a9fdc049479e9c6a8eda0bd163", reqMap["id"])
			assert.Equal(t, "Updated Profile Name", reqMap["profile_name"])

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"reply":{"success":true}}`)
		})
		client, server := setupTest(t, handler)
		defer server.Close()

		updateReq := types.UpdateAssessmentProfileRequest{
			ID:                  "48e2f6a9fdc049479e9c6a8eda0bd163",
			ProfileName:         "Updated Profile Name",
			EvaluationFrequency: "0 0 * * 0", // Weekly on Sunday at midnight
			Enabled:             "yes",
		}

		success, err := client.UpdateAssessmentProfile(context.Background(), updateReq)
		assert.NoError(t, err)
		assert.True(t, success)
	})
}

func TestClient_DeleteAssessmentProfile(t *testing.T) {
	t.Run("should delete assessment profile successfully", func(t *testing.T) {
		type requestWrapper struct {
			RequestData types.DeleteAssessmentProfileRequest `json:"request_data"`
		}

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodPost, r.Method)
			assert.Equal(t, fmt.Sprintf("/%s", DeleteAssessmentProfileEndpoint), r.URL.Path)

			var req requestWrapper
			err := json.NewDecoder(r.Body).Decode(&req)
			require.NoError(t, err)
			assert.Equal(t, "48e2f6a9fdc049479e9c6a8eda0bd163", req.RequestData.ID)

			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"reply":{"success":true}}`)
		})
		client, server := setupTest(t, handler)
		defer server.Close()

		deleteReq := types.DeleteAssessmentProfileRequest{
			ID: "48e2f6a9fdc049479e9c6a8eda0bd163",
		}

		success, err := client.DeleteAssessmentProfile(context.Background(), deleteReq)
		assert.NoError(t, err)
		assert.True(t, success)
	})
}

func TestClient_ListAssessmentProfiles(t *testing.T) {
	t.Run("should list assessment profiles successfully", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodPost, r.Method)
			assert.Equal(t, "/"+ListAssessmentProfilesEndpoint, r.URL.Path)

			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{
				"reply": {
					"total_count": 925,
					"result_count": 1,
					"assessment_profiles": [
						{
							"ID": "472141782aff4a2f999c5e3c35745b3a",
							"NAME": "Assessment example",
							"STANDARD_ID": "2nnd684-4z14-5cs82-c1a0-7c322b671844",
							"STANDARD_NAME": "CIS Amazon Linux 2 Benchmark v1.0.0",
							"ASSET_GROUP_ID": 1,
							"ASSET_GROUP_NAME": "asset group name",
							"DESCRIPTION": "assessment description",
							"REPORT_FREQUENCY": null,
							"REPORT_TARGETS": [],
							"REPORT_TYPE": "NONE",
							"ENABLED": true,
							"INSERT_TS": 1748259453615,
							"MODIFY_TS": 1748259453615,
							"CREATED_BY": "Generic Name",
							"MODIFIED_BY": "Generic Name"
						}
					]
				}
			}`)
		})
		client, server := setupTest(t, handler)
		defer server.Close()

		listReq := types.ListAssessmentProfilesRequest{}
		resp, err := client.ListAssessmentProfiles(context.Background(), listReq)
		assert.NoError(t, err)
		require.NotNil(t, resp)
		assert.Equal(t, 925, resp.TotalCount)
		assert.Equal(t, 1, resp.ResultCount)
		assert.Len(t, resp.AssessmentProfiles, 1)
		assert.Equal(t, "472141782aff4a2f999c5e3c35745b3a", resp.AssessmentProfiles[0].ID)
		assert.Equal(t, "Assessment example", resp.AssessmentProfiles[0].Name)
	})

	t.Run("should list assessment profiles with filters", func(t *testing.T) {
		type requestWrapper struct {
			RequestData types.ListAssessmentProfilesRequest `json:"request_data"`
		}

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req requestWrapper
			err := json.NewDecoder(r.Body).Decode(&req)
			require.NoError(t, err)
			assert.Len(t, req.RequestData.Filters, 1)
			assert.Equal(t, "name", req.RequestData.Filters[0].Field)
			assert.Equal(t, "contains", req.RequestData.Filters[0].Operator)
			assert.Equal(t, "Production", req.RequestData.Filters[0].Value)

			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"reply":{"total_count":1,"result_count":1,"assessment_profiles":[]}}`)
		})
		client, server := setupTest(t, handler)
		defer server.Close()

		listReq := types.ListAssessmentProfilesRequest{
			Filters: []types.Filter{
				{
					Field:    "name",
					Operator: "contains",
					Value:    "Production",
				},
			},
		}
		resp, err := client.ListAssessmentProfiles(context.Background(), listReq)
		assert.NoError(t, err)
		require.NotNil(t, resp)
	})
}
