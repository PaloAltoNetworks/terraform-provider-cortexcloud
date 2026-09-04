// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package appsec

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	types "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/types/appsec"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClient_CreatePolicy(t *testing.T) {
	t.Run("should create policy successfully", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodPost, r.Method)
			assert.Equal(t, "/"+PoliciesEndpoint, r.URL.Path)

			var req types.CreatePolicyRequest
			err := json.NewDecoder(r.Body).Decode(&req)
			require.NoError(t, err)
			assert.Equal(t, "Test Policy", req.Name)
			assert.Equal(t, "Test description", req.Description)
			assert.NotNil(t, req.Conditions)

			w.WriteHeader(http.StatusCreated)
			policy := types.Policy{
				ID:          "policy-123",
				Name:        req.Name,
				Description: req.Description,
				Status:      "enabled",
				IsCustom:    true,
				Conditions:  req.Conditions,
				Triggers:    req.Triggers,
			}
			err = json.NewEncoder(w).Encode(policy)
			require.NoError(t, err)
		})
		client, server := setupTest(t, handler)
		defer server.Close()

		searchField := "Severity"
		searchType := "EQ"
		searchValue := "CRITICAL"
		createReq := types.CreatePolicyRequest{
			Name:        "Test Policy",
			Description: "Test description",
			Conditions: types.PolicyCondition{
				SearchField: &searchField,
				SearchType:  &searchType,
				SearchValue: searchValue,
			},
			Triggers: types.PolicyTriggers{
				Periodic: types.PolicyTriggerConfig{
					IsEnabled: true,
					Actions: types.TriggerActions{
						ReportIssue: true,
					},
				},
			},
		}

		policy, err := client.CreatePolicy(context.Background(), createReq)
		assert.NoError(t, err)
		assert.Equal(t, "policy-123", policy.ID)
		assert.Equal(t, "Test Policy", policy.Name)
		assert.True(t, policy.IsCustom)
		assert.Equal(t, "enabled", policy.Status)
	})

	t.Run("should create policy with nested conditions", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodPost, r.Method)

			var req types.CreatePolicyRequest
			err := json.NewDecoder(r.Body).Decode(&req)
			require.NoError(t, err)

			// Verify nested AND/OR structure
			assert.NotEmpty(t, req.Conditions.And)
			assert.Len(t, req.Conditions.And, 2)

			w.WriteHeader(http.StatusCreated)
			policy := types.Policy{
				ID:         "policy-456",
				Name:       req.Name,
				Conditions: req.Conditions,
			}
			err = json.NewEncoder(w).Encode(policy)
			require.NoError(t, err)
		})
		client, server := setupTest(t, handler)
		defer server.Close()

		severity := "Severity"
		eq := "EQ"
		findingType := "Finding Type"

		createReq := types.CreatePolicyRequest{
			Name: "Complex Policy",
			Conditions: types.PolicyCondition{
				And: []types.PolicyCondition{
					{
						SearchField: &severity,
						SearchType:  &eq,
						SearchValue: "CRITICAL",
					},
					{
						Or: []types.PolicyCondition{
							{
								SearchField: &findingType,
								SearchType:  &eq,
								SearchValue: "CAS_CVE_SCANNER",
							},
							{
								SearchField: &findingType,
								SearchType:  &eq,
								SearchValue: "CAS_IAC_SCANNER",
							},
						},
					},
				},
			},
			Triggers: types.PolicyTriggers{
				Periodic: types.PolicyTriggerConfig{
					IsEnabled: true,
					Actions: types.TriggerActions{
						ReportIssue: true,
					},
				},
			},
		}

		policy, err := client.CreatePolicy(context.Background(), createReq)
		assert.NoError(t, err)
		assert.Equal(t, "policy-456", policy.ID)
		assert.Len(t, policy.Conditions.And, 2)
	})

	t.Run("should create policy with scope", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req types.CreatePolicyRequest
			err := json.NewDecoder(r.Body).Decode(&req)
			require.NoError(t, err)
			assert.NotNil(t, req.Scope)
			assert.Nil(t, req.AssetGroupIds)

			w.WriteHeader(http.StatusCreated)
			policy := types.Policy{
				ID:    "policy-789",
				Name:  req.Name,
				Scope: req.Scope,
			}
			err = json.NewEncoder(w).Encode(policy)
			require.NoError(t, err)
		})
		client, server := setupTest(t, handler)
		defer server.Close()

		deployed := "has_deployed_assets"
		eq := "EQ"
		createReq := types.CreatePolicyRequest{
			Name: "Scoped Policy",
			Conditions: types.PolicyCondition{
				SearchField: &deployed,
				SearchType:  &eq,
				SearchValue: true,
			},
			Scope: &types.PolicyScope{
				SearchField: &deployed,
				SearchType:  &eq,
				SearchValue: true,
			},
			Triggers: types.PolicyTriggers{
				Periodic: types.PolicyTriggerConfig{
					IsEnabled: true,
					Actions: types.TriggerActions{
						ReportIssue: true,
					},
				},
			},
		}

		policy, err := client.CreatePolicy(context.Background(), createReq)
		assert.NoError(t, err)
		assert.NotNil(t, policy.Scope)
	})
}

func TestClient_GetPolicy(t *testing.T) {
	t.Run("should get policy successfully", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodGet, r.Method)
			assert.Equal(t, "/"+PoliciesEndpoint+"/policy-123", r.URL.Path)

			w.WriteHeader(http.StatusOK)
			severity := "Severity"
			eq := "EQ"
			policy := types.Policy{
				ID:          "policy-123",
				Name:        "Test Policy",
				Description: "Test description",
				Status:      "enabled",
				IsCustom:    true,
				Conditions: types.PolicyCondition{
					SearchField: &severity,
					SearchType:  &eq,
					SearchValue: "HIGH",
				},
				Triggers: types.PolicyTriggers{
					Periodic: types.PolicyTriggerConfig{
						IsEnabled: true,
						Actions: types.TriggerActions{
							ReportIssue: true,
						},
					},
				},
			}
			err := json.NewEncoder(w).Encode(policy)
			require.NoError(t, err)
		})
		client, server := setupTest(t, handler)
		defer server.Close()

		policy, err := client.GetPolicy(context.Background(), "policy-123")
		assert.NoError(t, err)
		assert.Equal(t, "policy-123", policy.ID)
		assert.Equal(t, "Test Policy", policy.Name)
		assert.Equal(t, "enabled", policy.Status)
		assert.True(t, policy.IsCustom)
	})

	t.Run("should return error for non-existent policy", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodGet, r.Method)
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"error":"Policy not found"}`)
		})
		client, server := setupTest(t, handler)
		defer server.Close()

		_, err := client.GetPolicy(context.Background(), "non-existent")
		assert.Error(t, err)
	})
}

func TestClient_ListPolicies(t *testing.T) {
	t.Run("should list policies successfully", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodGet, r.Method)
			assert.Equal(t, "/"+PoliciesEndpoint, r.URL.Path)

			w.WriteHeader(http.StatusOK)
			policies := []types.Policy{
				{
					ID:       "policy-1",
					Name:     "Policy 1",
					Status:   "enabled",
					IsCustom: true,
				},
				{
					ID:       "policy-2",
					Name:     "Policy 2",
					Status:   "disabled",
					IsCustom: false,
				},
			}
			err := json.NewEncoder(w).Encode(policies)
			require.NoError(t, err)
		})
		client, server := setupTest(t, handler)
		defer server.Close()

		policies, err := client.ListPolicies(context.Background(), types.ListPoliciesRequest{})
		assert.NoError(t, err)
		assert.Len(t, policies, 2)
		assert.Equal(t, "policy-1", policies[0].ID)
		assert.Equal(t, "policy-2", policies[1].ID)
	})

	t.Run("should list policies with filters", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodGet, r.Method)

			// Verify query parameters
			query := r.URL.Query()
			assert.Equal(t, "true", query.Get("isCustom"))
			assert.Equal(t, "enabled", query.Get("status"))
			assert.Contains(t, query["findingTypes"], "CAS_IAC_SCANNER")
			assert.Contains(t, query["actions"], "reportIssue")

			w.WriteHeader(http.StatusOK)
			policies := []types.Policy{
				{
					ID:       "policy-custom",
					Name:     "Custom Policy",
					Status:   "enabled",
					IsCustom: true,
				},
			}
			err := json.NewEncoder(w).Encode(policies)
			require.NoError(t, err)
		})
		client, server := setupTest(t, handler)
		defer server.Close()

		listReq := types.ListPoliciesRequest{
			IsCustom:     true,
			Status:       "enabled",
			FindingTypes: []string{"CAS_IAC_SCANNER"},
			Actions:      []string{"reportIssue"},
		}
		policies, err := client.ListPolicies(context.Background(), listReq)
		assert.NoError(t, err)
		assert.Len(t, policies, 1)
		assert.True(t, policies[0].IsCustom)
		assert.Equal(t, "enabled", policies[0].Status)
	})

	t.Run("should handle empty list", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodGet, r.Method)
			w.WriteHeader(http.StatusOK)
			policies := []types.Policy{}
			err := json.NewEncoder(w).Encode(policies)
			require.NoError(t, err)
		})
		client, server := setupTest(t, handler)
		defer server.Close()

		policies, err := client.ListPolicies(context.Background(), types.ListPoliciesRequest{})
		assert.NoError(t, err)
		assert.Empty(t, policies)
	})
}

func TestClient_UpdatePolicy(t *testing.T) {
	t.Run("should update policy successfully", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodPut, r.Method)
			assert.Equal(t, "/"+PoliciesEndpoint+"/policy-123", r.URL.Path)

			var req types.UpdatePolicyRequest
			err := json.NewDecoder(r.Body).Decode(&req)
			require.NoError(t, err)
			assert.NotNil(t, req.Name)
			assert.Equal(t, "Updated Policy", *req.Name)
			assert.NotNil(t, req.Enabled)
			assert.False(t, *req.Enabled)

			w.WriteHeader(http.StatusOK)
			policy := types.Policy{
				ID:     "policy-123",
				Name:   *req.Name,
				Status: "disabled",
			}
			err = json.NewEncoder(w).Encode(policy)
			require.NoError(t, err)
		})
		client, server := setupTest(t, handler)
		defer server.Close()

		name := "Updated Policy"
		enabled := false
		updateReq := types.UpdatePolicyRequest{
			Name:    &name,
			Enabled: &enabled,
		}

		policy, err := client.UpdatePolicy(context.Background(), "policy-123", updateReq)
		assert.NoError(t, err)
		assert.Equal(t, "policy-123", policy.ID)
		assert.Equal(t, "Updated Policy", policy.Name)
		assert.Equal(t, "disabled", policy.Status)
	})

	t.Run("should update policy triggers", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodPut, r.Method)

			var req types.UpdatePolicyRequest
			err := json.NewDecoder(r.Body).Decode(&req)
			require.NoError(t, err)
			assert.NotNil(t, req.Triggers)
			assert.True(t, req.Triggers.PR.IsEnabled)

			w.WriteHeader(http.StatusOK)
			policy := types.Policy{
				ID:       "policy-456",
				Triggers: *req.Triggers,
			}
			err = json.NewEncoder(w).Encode(policy)
			require.NoError(t, err)
		})
		client, server := setupTest(t, handler)
		defer server.Close()

		triggers := types.PolicyTriggers{
			Periodic: types.PolicyTriggerConfig{
				IsEnabled: true,
				Actions: types.TriggerActions{
					ReportIssue: true,
				},
			},
			PR: types.PolicyTriggerConfig{
				IsEnabled: true,
				Actions: types.TriggerActions{
					ReportIssue:     true,
					BlockPR:         true,
					ReportPRComment: true,
				},
			},
		}
		updateReq := types.UpdatePolicyRequest{
			Triggers: &triggers,
		}

		policy, err := client.UpdatePolicy(context.Background(), "policy-456", updateReq)
		assert.NoError(t, err)
		assert.True(t, policy.Triggers.PR.IsEnabled)
		assert.True(t, policy.Triggers.PR.Actions.BlockPR)
	})
}

func TestClient_DeletePolicy(t *testing.T) {
	t.Run("should delete policy successfully", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodDelete, r.Method)
			assert.Equal(t, "/"+PoliciesEndpoint+"/policy-123", r.URL.Path)

			w.WriteHeader(http.StatusOK)
			resp := types.DeletePolicyResponse{
				Message: "Policy deleted successfully",
			}
			err := json.NewEncoder(w).Encode(resp)
			require.NoError(t, err)
		})
		client, server := setupTest(t, handler)
		defer server.Close()

		err := client.DeletePolicy(context.Background(), "policy-123")
		assert.NoError(t, err)
	})

	t.Run("should return error for non-existent policy", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodDelete, r.Method)
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"error":"Policy not found"}`)
		})
		client, server := setupTest(t, handler)
		defer server.Close()

		err := client.DeletePolicy(context.Background(), "non-existent")
		assert.Error(t, err)
	})
}

func TestListPoliciesRequest_toQueryValues(t *testing.T) {
	t.Run("should convert all fields to query values", func(t *testing.T) {
		req := types.ListPoliciesRequest{
			FindingTypes:                []string{"CAS_IAC_SCANNER", "CAS_CVE_SCANNER"},
			Actions:                     []string{"reportIssue", "blockPr"},
			Status:                      "enabled",
			Triggers:                    []string{"periodic", "pr"},
			IsCustom:                    true,
			DeveloperSuppressionAffects: true,
		}

		values := req.ToQueryValues()

		assert.Contains(t, values["findingTypes"], "CAS_IAC_SCANNER")
		assert.Contains(t, values["findingTypes"], "CAS_CVE_SCANNER")
		assert.Contains(t, values["actions"], "reportIssue")
		assert.Contains(t, values["actions"], "blockPr")
		assert.Equal(t, "enabled", values.Get("status"))
		assert.Contains(t, values["triggers"], "periodic")
		assert.Contains(t, values["triggers"], "pr")
		assert.Equal(t, "true", values.Get("isCustom"))
		assert.Equal(t, "true", values.Get("developerSuppressionAffects"))
	})

	t.Run("should handle empty request", func(t *testing.T) {
		req := types.ListPoliciesRequest{}
		values := req.ToQueryValues()

		assert.Equal(t, "false", values.Get("isCustom"))
		assert.Equal(t, "false", values.Get("developerSuppressionAffects"))
		assert.Empty(t, values.Get("status"))
	})
}
