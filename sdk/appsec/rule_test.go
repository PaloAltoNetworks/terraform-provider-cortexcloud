// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package appsec

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/log"
	types "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/types/appsec"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupTest creates a test client and HTTP server for testing
func setupTest(t *testing.T, handler http.HandlerFunc) (*Client, *httptest.Server) {
	t.Helper()

	server := httptest.NewServer(handler)
	t.Logf("[%s] Test server URL %s", t.Name(), server.URL)

	client, err := NewClient(
		WithCortexAPIURL(server.URL),
		WithCortexAPIKey("test-key"),
		WithCortexAPIKeyID(123),
		WithTransport(server.Client().Transport.(*http.Transport)),
		WithLogger(log.TflogAdapter{}),
	)
	require.NoError(t, err)
	require.NotNil(t, client)
	return client, server
}

func TestClient_Validate(t *testing.T) {
	t.Run("should validate rule successfully", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodPost, r.Method)
			assert.Equal(t, "/"+RulesValidationEndpoint, r.URL.Path)

			bodyBytes, err := io.ReadAll(r.Body)
			require.NoError(t, err)

			var req []types.ValidateRequest
			err = json.Unmarshal(bodyBytes, &req)
			require.NoError(t, err)
			assert.Len(t, req, 1)
			assert.Equal(t, "terraform", req[0].Framework)
			assert.Equal(t, "resource \"aws_s3_bucket\" \"example\" {}", req[0].Definition)

			w.WriteHeader(http.StatusOK)
			isValid := true
			err = json.NewEncoder(w).Encode(types.ValidateResponse{IsValid: &isValid})
			require.NoError(t, err)
		})
		client, server := setupTest(t, handler)
		defer server.Close()

		validateReq := []types.ValidateRequest{
			{
				Framework:  "terraform",
				Definition: "resource \"aws_s3_bucket\" \"example\" {}",
			},
		}
		resp, err := client.Validate(context.Background(), validateReq)
		assert.NoError(t, err)
		assert.NotNil(t, resp.IsValid)
		assert.True(t, *resp.IsValid)
	})

	t.Run("should return validation errors", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodPost, r.Method)
			assert.Equal(t, "/"+RulesValidationEndpoint, r.URL.Path)

			w.WriteHeader(http.StatusOK)
			isValid := false
			resp := types.ValidateResponse{
				IsValid: &isValid,
				FrameworksErrors: []types.ValidateResponseFrameworkError{
					{
						Framework: "terraform",
						Errors:    []string{"Invalid syntax on line 5"},
					},
				},
			}
			err := json.NewEncoder(w).Encode(resp)
			require.NoError(t, err)
		})
		client, server := setupTest(t, handler)
		defer server.Close()

		validateReq := []types.ValidateRequest{
			{
				Framework:  "terraform",
				Definition: "invalid definition",
			},
		}
		resp, err := client.Validate(context.Background(), validateReq)
		assert.NoError(t, err)
		assert.NotNil(t, resp.IsValid)
		assert.False(t, *resp.IsValid)
		assert.Len(t, resp.FrameworksErrors, 1)
		assert.Equal(t, "terraform", string(resp.FrameworksErrors[0].Framework))
		assert.Contains(t, resp.FrameworksErrors[0].Errors[0], "Invalid syntax")
	})
}

func TestClient_CreateOrClone(t *testing.T) {
	t.Run("should create new rule successfully", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodPost, r.Method)
			assert.Equal(t, "/"+RulesEndpoint, r.URL.Path)

			var req types.CreateOrCloneRequest
			err := json.NewDecoder(r.Body).Decode(&req)
			require.NoError(t, err)
			assert.Equal(t, "Test Rule", req.Name)
			assert.Equal(t, "High", req.Severity)
			assert.Equal(t, "IAC", req.Scanner)
			assert.Len(t, req.Frameworks, 1)
			assert.Equal(t, "terraform", req.Frameworks[0].Name)

			w.WriteHeader(http.StatusCreated)
			rule := types.Rule{
				Id:       "rule-123",
				Name:     req.Name,
				Severity: req.Severity,
				Scanner:  req.Scanner,
				IsCustom: true,
			}
			err = json.NewEncoder(w).Encode(rule)
			require.NoError(t, err)
		})
		client, server := setupTest(t, handler)
		defer server.Close()

		createReq := types.CreateOrCloneRequest{
			Name:        "Test Rule",
			Description: "Test rule description",
			Severity:    "High",
			Scanner:     "IAC",
			Category:    "Security",
			SubCategory: "Access Control",
			Frameworks: []types.FrameworkData{
				{
					Name:       "terraform",
					Definition: "resource \"aws_s3_bucket\" \"example\" {}",
				},
			},
			Labels: []string{"test", "security"},
		}
		rule, err := client.CreateOrClone(context.Background(), createReq)
		assert.NoError(t, err)
		assert.Equal(t, "rule-123", rule.Id)
		assert.Equal(t, "Test Rule", rule.Name)
		assert.True(t, rule.IsCustom)
	})

	t.Run("should clone existing rule successfully", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodPost, r.Method)
			assert.Equal(t, "/"+RulesEndpoint, r.URL.Path)

			var req types.CreateOrCloneRequest
			err := json.NewDecoder(r.Body).Decode(&req)
			require.NoError(t, err)
			assert.Equal(t, "Existing Rule", req.Name)

			w.WriteHeader(http.StatusCreated)
			rule := types.Rule{
				Id:       "rule-456",
				Name:     "Existing Rule (Clone)",
				Severity: req.Severity,
				Scanner:  req.Scanner,
				IsCustom: true,
			}
			err = json.NewEncoder(w).Encode(rule)
			require.NoError(t, err)
		})
		client, server := setupTest(t, handler)
		defer server.Close()

		createReq := types.CreateOrCloneRequest{
			Name:     "Existing Rule",
			Severity: "Medium",
			Scanner:  "Secrets",
		}
		rule, err := client.CreateOrClone(context.Background(), createReq)
		assert.NoError(t, err)
		assert.Equal(t, "rule-456", rule.Id)
		assert.Contains(t, rule.Name, "Clone")
	})

	t.Run("should serialize top-level cspmRuleId and populate read fields", func(t *testing.T) {
		cspmRuleId := "ff6a26a5-f036-4d3a-a650-d5de1d568bab"

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodPost, r.Method)
			assert.Equal(t, "/"+RulesEndpoint, r.URL.Path)

			bodyBytes, err := io.ReadAll(r.Body)
			require.NoError(t, err)

			// cspmRuleId is a top-level field in the request payload (verified
			// against the live API: framework-level placement is rejected with
			// "excess property"; the scanner-object shape returns 422).
			assert.Contains(t, string(bodyBytes), `"cspmRuleId":"`+cspmRuleId+`"`)

			var req types.CreateOrCloneRequest
			require.NoError(t, json.Unmarshal(bodyBytes, &req))
			require.NotNil(t, req.CspmRuleId)
			assert.Equal(t, cspmRuleId, *req.CspmRuleId)

			// The API does NOT echo cspmRuleId back on the response (write-only),
			// but does populate shortDescription and framework remediationIds /
			// resourceTypes.
			w.WriteHeader(http.StatusCreated)
			rule := types.Rule{
				Id:               "rule-cspm",
				Name:             req.Name,
				Severity:         req.Severity,
				Scanner:          req.Scanner,
				IsCustom:         true,
				ShortDescription: "short desc",
				Frameworks: []types.FrameworkData{
					{
						Name:           req.Frameworks[0].Name,
						Definition:     req.Frameworks[0].Definition,
						RemediationIds: []string{"rem-1"},
						ResourceTypes:  []string{"aws_s3_bucket"},
					},
				},
			}
			require.NoError(t, json.NewEncoder(w).Encode(rule))
		})
		client, server := setupTest(t, handler)
		defer server.Close()

		createReq := types.CreateOrCloneRequest{
			Name:       "CSPM Mapped Rule",
			Severity:   "HIGH",
			Scanner:    "IAC",
			CspmRuleId: &cspmRuleId,
			Frameworks: []types.FrameworkData{
				{
					Name:       "TERRAFORM",
					Definition: "resource \"aws_s3_bucket\" \"example\" {}",
				},
			},
		}
		rule, err := client.CreateOrClone(context.Background(), createReq)
		assert.NoError(t, err)
		assert.Equal(t, "rule-cspm", rule.Id)
		assert.Equal(t, "short desc", rule.ShortDescription)
		require.Len(t, rule.Frameworks, 1)
		assert.Equal(t, []string{"rem-1"}, rule.Frameworks[0].RemediationIds)
		assert.Equal(t, []string{"aws_s3_bucket"}, rule.Frameworks[0].ResourceTypes)
	})

	t.Run("should omit cspmRuleId from payload when unset", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			bodyBytes, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			assert.NotContains(t, string(bodyBytes), "cspmRuleId")

			w.WriteHeader(http.StatusCreated)
			require.NoError(t, json.NewEncoder(w).Encode(types.Rule{Id: "rule-nocspm"}))
		})
		client, server := setupTest(t, handler)
		defer server.Close()

		createReq := types.CreateOrCloneRequest{
			Name:     "No CSPM Rule",
			Severity: "LOW",
			Scanner:  "IAC",
			Frameworks: []types.FrameworkData{
				{Name: "TERRAFORM", Definition: "x"},
			},
		}
		_, err := client.CreateOrClone(context.Background(), createReq)
		assert.NoError(t, err)
	})
}

func TestClient_Get(t *testing.T) {
	t.Run("should get rule successfully", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodGet, r.Method)
			assert.Equal(t, "/"+RulesEndpoint+"/rule-123", r.URL.Path)

			w.WriteHeader(http.StatusOK)
			rule := types.Rule{
				Id:          "rule-123",
				Name:        "Test Rule",
				Description: "Test description",
				Severity:    "High",
				Scanner:     "IAC",
				IsCustom:    true,
				IsEnabled:   true,
				Category:    "Security",
				SubCategory: "Access Control",
			}
			err := json.NewEncoder(w).Encode(rule)
			require.NoError(t, err)
		})
		client, server := setupTest(t, handler)
		defer server.Close()

		rule, err := client.Get(context.Background(), "rule-123")
		assert.NoError(t, err)
		assert.Equal(t, "rule-123", rule.Id)
		assert.Equal(t, "Test Rule", rule.Name)
		assert.Equal(t, "High", rule.Severity)
		assert.True(t, rule.IsCustom)
		assert.True(t, rule.IsEnabled)
	})

	t.Run("should return error for non-existent rule", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodGet, r.Method)
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"error":"Rule not found"}`)
		})
		client, server := setupTest(t, handler)
		defer server.Close()

		_, err := client.Get(context.Background(), "non-existent")
		assert.Error(t, err)
	})
}

func TestClient_GetLabels(t *testing.T) {
	t.Run("should get labels successfully", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodGet, r.Method)
			assert.Equal(t, "/"+RulesLabelsEndpoint, r.URL.Path)

			w.WriteHeader(http.StatusOK)
			resp := types.GetLabelsResponse{
				Labels: []string{"security", "compliance", "best-practice", "performance"},
			}
			err := json.NewEncoder(w).Encode(resp)
			require.NoError(t, err)
		})
		client, server := setupTest(t, handler)
		defer server.Close()

		resp, err := client.GetLabels(context.Background())
		assert.NoError(t, err)
		assert.Len(t, resp.Labels, 4)
		assert.Contains(t, resp.Labels, "security")
		assert.Contains(t, resp.Labels, "compliance")
		assert.Contains(t, resp.Labels, "best-practice")
		assert.Contains(t, resp.Labels, "performance")
	})

	t.Run("should handle empty labels list", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodGet, r.Method)
			w.WriteHeader(http.StatusOK)
			resp := types.GetLabelsResponse{
				Labels: []string{},
			}
			err := json.NewEncoder(w).Encode(resp)
			require.NoError(t, err)
		})
		client, server := setupTest(t, handler)
		defer server.Close()

		resp, err := client.GetLabels(context.Background())
		assert.NoError(t, err)
		assert.Empty(t, resp.Labels)
	})
}

func TestClient_List(t *testing.T) {
	t.Run("should list rules successfully", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodGet, r.Method)
			assert.Equal(t, "/"+RulesEndpoint, r.URL.Path)
			assert.Equal(t, "true", r.URL.Query().Get("enabled"))
			assert.Equal(t, "10", r.URL.Query().Get("limit"))
			// offset=0 is omitted (not added to query string)

			w.WriteHeader(http.StatusOK)
			resp := types.ListResponse{
				Offset: 0,
				Rules: []types.Rule{
					{
						Id:       "rule-1",
						Name:     "Rule 1",
						Severity: "High",
						Scanner:  "IAC",
					},
					{
						Id:       "rule-2",
						Name:     "Rule 2",
						Severity: "Medium",
						Scanner:  "Secrets",
					},
				},
			}
			err := json.NewEncoder(w).Encode(resp)
			require.NoError(t, err)
		})
		client, server := setupTest(t, handler)
		defer server.Close()

		listReq := types.ListRequest{
			Enabled: true,
			Limit:   10,
			Offset:  0,
		}
		resp, err := client.List(context.Background(), listReq)
		assert.NoError(t, err)
		assert.Len(t, resp.Rules, 2)
		assert.Equal(t, "rule-1", resp.Rules[0].Id)
		assert.Equal(t, "rule-2", resp.Rules[1].Id)
	})

	t.Run("should list rules with filters", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodGet, r.Method)
			assert.Equal(t, "/"+RulesEndpoint, r.URL.Path)

			// Verify query parameters
			query := r.URL.Query()
			assert.Equal(t, "true", query.Get("isCustom"))
			assert.Contains(t, query["severities"], "High")
			assert.Contains(t, query["scanners"], "IAC")
			assert.Contains(t, query["labels"], "security")

			w.WriteHeader(http.StatusOK)
			resp := types.ListResponse{
				Offset: 0,
				Rules: []types.Rule{
					{
						Id:       "rule-custom",
						Name:     "Custom Rule",
						Severity: "High",
						Scanner:  "IAC",
						IsCustom: true,
					},
				},
			}
			err := json.NewEncoder(w).Encode(resp)
			require.NoError(t, err)
		})
		client, server := setupTest(t, handler)
		defer server.Close()

		listReq := types.ListRequest{
			IsCustom:   true,
			Severities: []string{"High"},
			Scanners:   []string{"IAC"},
			Labels:     []string{"security"},
			Limit:      10,
		}
		resp, err := client.List(context.Background(), listReq)
		assert.NoError(t, err)
		assert.Len(t, resp.Rules, 1)
		assert.True(t, resp.Rules[0].IsCustom)
	})

	t.Run("should handle empty list", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodGet, r.Method)
			w.WriteHeader(http.StatusOK)
			resp := types.ListResponse{
				Offset: 0,
				Rules:  []types.Rule{},
			}
			err := json.NewEncoder(w).Encode(resp)
			require.NoError(t, err)
		})
		client, server := setupTest(t, handler)
		defer server.Close()

		listReq := types.ListRequest{Limit: 10}
		resp, err := client.List(context.Background(), listReq)
		assert.NoError(t, err)
		assert.Empty(t, resp.Rules)
	})
}

func TestClient_Update(t *testing.T) {
	t.Run("should update custom rule successfully", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Single call: PATCH to update rule (no more GET+merge)
			assert.Equal(t, http.MethodPatch, r.Method)
			assert.Equal(t, "/"+RulesEndpoint+"/rule-123", r.URL.Path)

			var req types.UpdateRequest
			err := json.NewDecoder(r.Body).Decode(&req)
			require.NoError(t, err)
			assert.Equal(t, "Updated Name", req.Name)
			assert.Equal(t, "High", req.Severity)
			assert.Equal(t, "IAC", req.Scanner)
			assert.Equal(t, "Security", req.Category)
			assert.Equal(t, "Access Control", req.SubCategory)

			w.WriteHeader(http.StatusOK)
			resp := types.UpdateResponse{
				Rule: types.Rule{
					Id:          "rule-123",
					Name:        req.Name,
					Description: req.Description,
					Severity:    req.Severity,
					Scanner:     req.Scanner,
					IsCustom:    true,
					IsEnabled:   true,
				},
			}
			err = json.NewEncoder(w).Encode(resp)
			require.NoError(t, err)
		})
		client, server := setupTest(t, handler)
		defer server.Close()

		updateReq := types.UpdateRequest{
			Name:        "Updated Name",
			Severity:    "High",
			Scanner:     "IAC",
			Category:    "Security",
			SubCategory: "Access Control",
			Frameworks: []types.FrameworkData{
				{Name: "terraform", Definition: "resource definition"},
			},
		}
		resp, err := client.Update(context.Background(), "rule-123", updateReq)
		assert.NoError(t, err)
		assert.Equal(t, "rule-123", resp.Rule.Id)
		assert.Equal(t, "Updated Name", resp.Rule.Name)
		assert.Equal(t, "High", resp.Rule.Severity)
	})

	t.Run("should update OOB rule labels only", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Single call: PATCH to update labels (no more GET+merge)
			assert.Equal(t, http.MethodPatch, r.Method)

			var req types.UpdateRequest
			err := json.NewDecoder(r.Body).Decode(&req)
			require.NoError(t, err)
			assert.Contains(t, req.Labels, "new-label")

			w.WriteHeader(http.StatusOK)
			resp := types.UpdateResponse{
				Rule: types.Rule{
					Id:       "oob-rule-1",
					Name:     "OOB Rule",
					Severity: "High",
					Scanner:  "IAC",
					IsCustom: false,
					Labels:   &req.Labels,
				},
			}
			err = json.NewEncoder(w).Encode(resp)
			require.NoError(t, err)
		})
		client, server := setupTest(t, handler)
		defer server.Close()

		updateReq := types.UpdateRequest{
			Labels: []string{"new-label"},
		}
		resp, err := client.Update(context.Background(), "oob-rule-1", updateReq)
		assert.NoError(t, err)
		assert.Equal(t, "oob-rule-1", resp.Rule.Id)
		assert.Contains(t, *resp.Rule.Labels, "new-label")
	})

	t.Run("should not send excess properties to PATCH endpoint", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodPatch, r.Method)

			// Decode the raw JSON to check for excess fields
			var rawBody map[string]interface{}
			err := json.NewDecoder(r.Body).Decode(&rawBody)
			require.NoError(t, err)

			// These fields must NOT be present in the request body
			for _, field := range []string{
				"cloudProvider", "docLink", "domain", "findingCategory",
				"findingDocs", "findingTypeId", "findingTypeName",
				"isEnabled", "mitreTactics", "mitreTechniques", "owner", "source",
			} {
				_, exists := rawBody[field]
				assert.False(t, exists, "excess field %q should not be sent to PATCH endpoint", field)
			}

			// These fields should be present
			assert.Contains(t, rawBody, "name")
			assert.Contains(t, rawBody, "severity")
			assert.Contains(t, rawBody, "labels")

			w.WriteHeader(http.StatusOK)
			resp := types.UpdateResponse{
				Rule: types.Rule{
					Id:   "rule-123",
					Name: "Test Rule",
				},
			}
			err = json.NewEncoder(w).Encode(resp)
			require.NoError(t, err)
		})
		client, server := setupTest(t, handler)
		defer server.Close()

		updateReq := types.UpdateRequest{
			Name:     "Test Rule",
			Severity: "High",
			Scanner:  "IAC",
			Category: "Security",
			Labels:   []string{"test"},
		}
		_, err := client.Update(context.Background(), "rule-123", updateReq)
		assert.NoError(t, err)
	})
}

func TestClient_Delete(t *testing.T) {
	t.Run("should delete rule successfully", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodDelete, r.Method)
			assert.Equal(t, "/"+RulesEndpoint+"/rule-123", r.URL.Path)
			w.WriteHeader(http.StatusNoContent)
		})
		client, server := setupTest(t, handler)
		defer server.Close()

		err := client.Delete(context.Background(), "rule-123")
		assert.NoError(t, err)
	})

	t.Run("should return error for non-existent rule", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodDelete, r.Method)
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"error":"Rule not found"}`)
		})
		client, server := setupTest(t, handler)
		defer server.Close()

		err := client.Delete(context.Background(), "non-existent")
		assert.Error(t, err)
	})
}

func TestListRequest_toQueryValues(t *testing.T) {
	t.Run("should convert all fields to query values", func(t *testing.T) {
		req := types.ListRequest{
			Enabled:        true,
			Frameworks:     []string{"terraform", "cloudformation"},
			IsCustom:       true,
			Labels:         []string{"security", "compliance"},
			Limit:          50,
			Offset:         10,
			Scanners:       []string{"IAC", "Secrets"},
			Severities:     []string{"High", "Critical"},
			SortBy:         "name",
			SortOrder:      1,
			Categories:     []string{"Security"},
			CloudProviders: []string{"AWS", "Azure"},
			SubCategories:  []string{"Access Control"},
		}

		values := req.ToQueryValues()

		assert.Equal(t, "true", values.Get("enabled"))
		assert.Equal(t, "true", values.Get("isCustom"))
		assert.Equal(t, "50", values.Get("limit"))
		assert.Equal(t, "10", values.Get("offset"))
		assert.Equal(t, "name", values.Get("sortBy"))
		assert.Equal(t, "1", values.Get("sortOrder"))

		assert.Contains(t, values["frameworks"], "terraform")
		assert.Contains(t, values["frameworks"], "cloudformation")
		assert.Contains(t, values["labels"], "security")
		assert.Contains(t, values["scanners"], "IAC")
		assert.Contains(t, values["severities"], "High")
		assert.Contains(t, values["categories"], "Security")
		assert.Contains(t, values["cloudProviders"], "AWS")
		assert.Contains(t, values["subCategories"], "Access Control")
	})

	t.Run("should handle empty request", func(t *testing.T) {
		req := types.ListRequest{}
		values := req.ToQueryValues()

		assert.Equal(t, "false", values.Get("enabled"))
		assert.Equal(t, "false", values.Get("isCustom"))
		// limit=0 and offset=0 are omitted (not added to query string)
		assert.Equal(t, "", values.Get("limit"))
		assert.Equal(t, "", values.Get("offset"))
	})
}

func TestRule_ToUpdateRequest(t *testing.T) {
	t.Run("should convert rule to update request with only PATCH-allowed fields", func(t *testing.T) {
		labels := []string{"security", "compliance"}
		rule := types.Rule{
			Id:              "rule-123",
			Name:            "Test Rule",
			Description:     "Test description",
			Severity:        "High",
			Scanner:         "IAC",
			Category:        "Security",
			SubCategory:     "Access Control",
			CloudProvider:   "AWS",
			DocLink:         "https://docs.example.com",
			Domain:          "Infrastructure",
			FindingCategory: "Misconfiguration",
			FindingDocs:     "https://findings.example.com",
			FindingTypeId:   123,
			FindingTypeName: "S3 Bucket Public",
			IsEnabled:       true,
			Labels:          &labels,
			MitreTactics:    []string{"TA0001"},
			MitreTechniques: []string{"T1078"},
			Owner:           "security-team",
			Source:          "custom",
			Frameworks: []types.FrameworkData{
				{
					Name:       "terraform",
					Definition: "resource definition",
				},
			},
		}

		updateReq := rule.ToUpdateRequest()

		// Fields that SHOULD be included (accepted by PATCH endpoint)
		assert.Equal(t, rule.Name, updateReq.Name)
		assert.Equal(t, rule.Description, updateReq.Description)
		assert.Equal(t, rule.Severity, updateReq.Severity)
		assert.Equal(t, rule.Scanner, updateReq.Scanner)
		assert.Equal(t, rule.Category, updateReq.Category)
		assert.Equal(t, rule.SubCategory, updateReq.SubCategory)
		assert.Equal(t, labels, updateReq.Labels)
		assert.Len(t, updateReq.Frameworks, 1)
	})

	t.Run("should handle nil labels", func(t *testing.T) {
		rule := types.Rule{
			Id:     "rule-123",
			Name:   "Test Rule",
			Labels: nil,
		}

		updateReq := rule.ToUpdateRequest()

		assert.NotNil(t, updateReq.Labels)
		assert.Empty(t, updateReq.Labels)
	})
}
