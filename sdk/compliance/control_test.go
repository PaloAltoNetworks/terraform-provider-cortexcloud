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

func TestClient_CreateControl(t *testing.T) {
	t.Run("should create control successfully", func(t *testing.T) {
		type requestWrapper struct {
			RequestData types.CreateControlRequest `json:"request_data"`
		}

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodPost, r.Method)
			assert.Equal(t, fmt.Sprintf("/%s", CreateControlEndpoint), r.URL.Path)

			var req requestWrapper
			err := json.NewDecoder(r.Body).Decode(&req)
			require.NoError(t, err)
			assert.Equal(t, "Access Enforcement", req.RequestData.ControlName)
			assert.Equal(t, "Access Control", req.RequestData.Category)
			assert.Equal(t, "AC-3", req.RequestData.Subcategory)
			assert.Equal(t, "Enforce approved authorizations", req.RequestData.Description)

			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"reply":{"success":true,"control_id":"test-control-id-123"}}`)
		})
		client, server := setupTest(t, handler)
		defer server.Close()

		createReq := types.CreateControlRequest{
			ControlName: "Access Enforcement",
			Category:    "Access Control",
			Subcategory: "AC-3",
			Description: "Enforce approved authorizations",
		}

		resp, err := client.CreateControl(context.Background(), createReq)
		assert.NoError(t, err)
		require.NotNil(t, resp)
		assert.True(t, resp.Success)
		assert.Equal(t, "test-control-id-123", resp.ControlID)
	})
}

func TestClient_GetControl(t *testing.T) {
	t.Run("should get control successfully", func(t *testing.T) {
		type requestWrapper struct {
			RequestData types.GetControlRequest `json:"request_data"`
		}

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodPost, r.Method)
			assert.Equal(t, fmt.Sprintf("/%s", GetControlEndpoint), r.URL.Path)

			var req requestWrapper
			err := json.NewDecoder(r.Body).Decode(&req)
			require.NoError(t, err)
			assert.Equal(t, "control-id-123", req.RequestData.ID)

			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{
				"reply": {
					"control": [{
						"CONTROL_ID": "control-id-123",
						"CONTROL_NAME": "Access Enforcement",
						"DESCRIPTION": "Enforce approved authorizations",
						"CATEGORY": "Access Control",
						"CATEGORY_DESCRIPTION": "Access Control Category",
						"SUBCATEGORY": "AC-3",
						"SUBCATEGORY_DESCRIPTION": "Access Enforcement Subcategory",
						"STANDARDS": ["CIS AWS", "NIST"],
						"SEVERITY": "HIGH",
						"SUPPORTED": true,
						"INSERTION_TIME": 1640995200000,
						"MODIFICATION_TIME": 1672531200000,
						"MODIFIED_BY": "admin",
						"CREATED_BY": "admin",
						"MITIGATION": "Apply access controls",
						"ADDITIONAL_DATA": [],
						"COMPLIANCE_RULES": [],
						"RULES": 5,
						"REVISION": "rev-123",
						"IMPACT": "High impact",
						"AUTOMATION_STATUS": "automated",
						"AUDIT_PROCEDURE": "Review access logs",
						"ENABLED": true,
						"IS_CUSTOM": false,
						"STATUS": "active"
					}]
				}
			}`)
		})
		client, server := setupTest(t, handler)
		defer server.Close()

		getReq := types.GetControlRequest{
			ID: "control-id-123",
		}

		control, err := client.GetControl(context.Background(), getReq)
		assert.NoError(t, err)
		require.NotNil(t, control)
		assert.Equal(t, "control-id-123", control.ID)
		assert.Equal(t, "Access Enforcement", control.Name)
		assert.Equal(t, "Access Control", control.Category)
		assert.Equal(t, "AC-3", control.Subcategory)
		assert.Equal(t, "HIGH", control.Severity)
		assert.True(t, control.Supported)
		assert.True(t, control.Enabled)
		assert.False(t, control.IsCustom)
		assert.Equal(t, 5, control.Rules)
	})
}

func TestClient_UpdateControl(t *testing.T) {
	t.Run("should update control successfully", func(t *testing.T) {
		type requestWrapper struct {
			RequestData types.UpdateControlRequest `json:"request_data"`
		}

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodPost, r.Method)
			assert.Equal(t, fmt.Sprintf("/%s", UpdateControlEndpoint), r.URL.Path)

			var req requestWrapper
			err := json.NewDecoder(r.Body).Decode(&req)
			require.NoError(t, err)
			assert.Equal(t, "48e2f6a9fcc049579e9c6b8eda0bd123", req.RequestData.ID)
			assert.Equal(t, "Updated Control Name", req.RequestData.ControlName)

			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"reply":{"success":true}}`)
		})
		client, server := setupTest(t, handler)
		defer server.Close()

		updateReq := types.UpdateControlRequest{
			ID:          "48e2f6a9fcc049579e9c6b8eda0bd123",
			ControlName: "Updated Control Name",
		}

		success, err := client.UpdateControl(context.Background(), updateReq)
		assert.NoError(t, err)
		assert.True(t, success)
	})
}

func TestClient_DeleteControl(t *testing.T) {
	t.Run("should delete control successfully", func(t *testing.T) {
		type requestWrapper struct {
			RequestData types.DeleteControlRequest `json:"request_data"`
		}

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodPost, r.Method)
			assert.Equal(t, fmt.Sprintf("/%s", DeleteControlEndpoint), r.URL.Path)

			var req requestWrapper
			err := json.NewDecoder(r.Body).Decode(&req)
			require.NoError(t, err)
			assert.Equal(t, "control-to-delete-789", req.RequestData.ID)

			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"reply":{"success":true}}`)
		})
		client, server := setupTest(t, handler)
		defer server.Close()

		deleteReq := types.DeleteControlRequest{
			ID: "control-to-delete-789",
		}

		success, err := client.DeleteControl(context.Background(), deleteReq)
		assert.NoError(t, err)
		assert.True(t, success)
	})
}

func TestClient_ListControls(t *testing.T) {
	t.Run("should list controls successfully", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodPost, r.Method)
			assert.Equal(t, "/"+ListControlsEndpoint, r.URL.Path)

			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{
				"reply": {
					"total_count": 150,
					"result_count": 2,
					"controls": [
						{
							"CONTROL_ID": "ctrl-001",
							"CONTROL_NAME": "Access Control Policy",
							"DESCRIPTION": "Enforce access control policies",
							"CATEGORY": "Access Control",
							"CATEGORY_DESCRIPTION": "Access Control Category",
							"SUBCATEGORY": "AC-1",
							"SUBCATEGORY_DESCRIPTION": "Access Control Policy",
							"STANDARDS": ["CIS", "NIST"],
							"SEVERITY": "HIGH",
							"SUPPORTED": true,
							"INSERTION_TIME": 1640995200000,
							"MODIFICATION_TIME": 1672531200000,
							"MODIFIED_BY": "admin",
							"CREATED_BY": "admin",
							"MITIGATION": null,
							"ADDITIONAL_DATA": [],
							"COMPLIANCE_RULES": [],
							"RULES": 3,
							"REVISION": "rev-001",
							"IMPACT": null,
							"AUTOMATION_STATUS": "manual",
							"AUDIT_PROCEDURE": null,
							"ENABLED": true,
							"IS_CUSTOM": false,
							"STATUS": "active"
						},
						{
							"CONTROL_ID": "ctrl-002",
							"CONTROL_NAME": "Custom Security Control",
							"DESCRIPTION": "Custom control for internal use",
							"CATEGORY": "Security",
							"CATEGORY_DESCRIPTION": "Security Category",
							"SUBCATEGORY": "SEC-1",
							"SUBCATEGORY_DESCRIPTION": "Security Control 1",
							"STANDARDS": ["Internal"],
							"SEVERITY": "MEDIUM",
							"SUPPORTED": true,
							"INSERTION_TIME": 1650000000000,
							"MODIFICATION_TIME": 1660000000000,
							"MODIFIED_BY": "user",
							"CREATED_BY": "user",
							"MITIGATION": "Apply security patches",
							"ADDITIONAL_DATA": [],
							"COMPLIANCE_RULES": [],
							"RULES": 2,
							"REVISION": "rev-002",
							"IMPACT": "Medium impact",
							"AUTOMATION_STATUS": "automated",
							"AUDIT_PROCEDURE": "Review logs",
							"ENABLED": true,
							"IS_CUSTOM": true,
							"STATUS": "active"
						}
					]
				}
			}`)
		})
		client, server := setupTest(t, handler)
		defer server.Close()

		listReq := types.ListControlsRequest{}
		resp, err := client.ListControls(context.Background(), listReq)
		assert.NoError(t, err)
		require.NotNil(t, resp)
		assert.Equal(t, 150, resp.TotalCount)
		assert.Equal(t, 2, resp.ResultCount)
		assert.Len(t, resp.Controls, 2)

		// Verify first control
		assert.Equal(t, "ctrl-001", resp.Controls[0].ID)
		assert.Equal(t, "Access Control Policy", resp.Controls[0].Name)
		assert.Equal(t, "HIGH", resp.Controls[0].Severity)
		assert.False(t, resp.Controls[0].IsCustom)
		assert.Equal(t, 3, resp.Controls[0].Rules)

		// Verify second control
		assert.Equal(t, "ctrl-002", resp.Controls[1].ID)
		assert.Equal(t, "Custom Security Control", resp.Controls[1].Name)
		assert.Equal(t, "MEDIUM", resp.Controls[1].Severity)
		assert.True(t, resp.Controls[1].IsCustom)
		assert.Equal(t, 2, resp.Controls[1].Rules)
	})

	t.Run("should list controls with filters", func(t *testing.T) {
		type requestWrapper struct {
			RequestData types.ListControlsRequest `json:"request_data"`
		}

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req requestWrapper
			err := json.NewDecoder(r.Body).Decode(&req)
			require.NoError(t, err)
			assert.Len(t, req.RequestData.Filters, 1)
			assert.Equal(t, "name", req.RequestData.Filters[0].Field)
			assert.Equal(t, "contains", req.RequestData.Filters[0].Operator)
			assert.Equal(t, "Access", req.RequestData.Filters[0].Value)

			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"reply":{"total_count":10,"result_count":10,"controls":[]}}`)
		})
		client, server := setupTest(t, handler)
		defer server.Close()

		listReq := types.ListControlsRequest{
			Filters: []types.Filter{
				{
					Field:    "name",
					Operator: "contains",
					Value:    "Access",
				},
			},
		}
		resp, err := client.ListControls(context.Background(), listReq)
		assert.NoError(t, err)
		require.NotNil(t, resp)
		assert.Equal(t, 10, resp.TotalCount)
	})

	t.Run("should list controls with pagination and sorting", func(t *testing.T) {
		type requestWrapper struct {
			RequestData types.ListControlsRequest `json:"request_data"`
		}

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req requestWrapper
			err := json.NewDecoder(r.Body).Decode(&req)
			require.NoError(t, err)
			require.NotNil(t, req.RequestData.SearchFrom)
			require.NotNil(t, req.RequestData.SearchTo)
			assert.Equal(t, 0, *req.RequestData.SearchFrom)
			assert.Equal(t, 49, *req.RequestData.SearchTo)
			require.NotNil(t, req.RequestData.Sort)
			assert.Equal(t, "creation_time", req.RequestData.Sort.Field)
			assert.Equal(t, "desc", req.RequestData.Sort.Keyword)

			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"reply":{"total_count":200,"result_count":50,"controls":[]}}`)
		})
		client, server := setupTest(t, handler)
		defer server.Close()

		listReq := types.ListControlsRequest{
			SearchFrom: util.ToPointer(0),
			SearchTo:   util.ToPointer(49),
			Sort: &types.SortFilter{
				Field:   "creation_time",
				Keyword: "desc",
			},
		}
		resp, err := client.ListControls(context.Background(), listReq)
		assert.NoError(t, err)
		require.NotNil(t, resp)
		assert.Equal(t, 200, resp.TotalCount)
		assert.Equal(t, 50, resp.ResultCount)
	})
}
