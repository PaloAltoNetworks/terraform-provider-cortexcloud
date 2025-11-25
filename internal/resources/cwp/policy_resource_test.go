// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package cwp_test

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/provider"
)

// TestUnitPolicyResource tests the CRUD operations for the CWP policy resource using a mock HTTP server.
// It verifies policy creation, retrieval, update, and deletion functionality by simulating API responses
// and checking that the Terraform resource properly handles the lifecycle operations with correct
// attribute mapping and state management.
func TestUnitPolicyResource(t *testing.T) {
	var updated atomic.Bool

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Printf("--- PROCESSING REQUEST: %s %s ---\n", r.Method, r.URL.Path)

		// Handle ListPolicies - important for the UpdatePolicy method in the SDK
		if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/public_api/v1/cwp/policies") {
			w.WriteHeader(http.StatusOK)
			// Return a list with our test policy
			if !updated.Load() {
				fmt.Fprintln(w, `[{
					"id": "123",
					"revision": 1,
					"createdAt": "2023-01-01T00:00:00Z",
					"modifiedAt": "2023-01-01T00:00:00Z",
					"type": "workload_protection",
					"createdBy": "admin@example.com",
					"disabled": false,
					"name": "Test CWP Policy",
					"description": "A test CWP policy for unit testing",
					"evaluationModes": ["runtime"],
					"evaluationStage": "build",
					"rulesIds": ["rule-1", "rule-2"],
					"condition": "process.name == 'suspicious'",
					"exception": "process.path startswith '/usr/bin'",
					"assetScope": "all",
					"assetGroupsIDs": [1, 2, 3],
					"assetGroups": ["group-1", "group-2"],
					"action": "block",
					"severity": "high",
					"remediationGuidance": "Investigate and remediate the suspicious process"
				}]`)
			} else {
				fmt.Fprintln(w, `[{
					"id": "123",
					"revision": 2,
					"createdAt": "2023-01-01T00:00:00Z",
					"modifiedAt": "2023-01-01T01:00:00Z",
					"type": "workload_protection",
					"createdBy": "admin@example.com",
					"disabled": false,
					"name": "Updated Test CWP Policy",
					"description": "An updated test CWP policy for unit testing",
					"evaluationModes": ["runtime", "build"],
					"evaluationStage": "runtime",
					"rulesIds": ["rule-1", "rule-2", "rule-3"],
					"condition": "process.name == 'suspicious'",
					"exception": "process.path startswith '/usr/bin'",
					"assetScope": "all",
					"assetGroupsIDs": [1, 2, 3, 4],
					"assetGroups": ["group-1", "group-2", "group-3"],
					"action": "alert", 
					"severity": "medium",
					"remediationGuidance": "Updated remediation guidance"
				}]`)
			}
			return
		}

		// Handle policy creation
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/public_api/v1/cwp/policies") {
			w.WriteHeader(http.StatusCreated)
			fmt.Fprintln(w, `{
				"id": "123"
			}`) //nolint:errcheck
			return
		}

		// Handle policy retrieval by ID
		if r.Method == http.MethodGet && (strings.Contains(r.URL.Path, "/public_api/v1/cwp/policies/123") ||
			strings.Contains(r.URL.Path, "/public_api/v1/cwp/get_policy_details/123")) {
			w.WriteHeader(http.StatusOK)

			// In the first step (creation) vs second step (update)
			if !updated.Load() {
				// Return exactly what we expect for the first test case
				fmt.Fprintln(w, `{
					"id": "123",
					"revision": 1,
					"createdAt": "2023-01-01T00:00:00Z",
					"modifiedAt": "2023-01-01T00:00:00Z",
					"type": "workload_protection",
					"createdBy": "admin@example.com",
					"disabled": false,
					"name": "Test CWP Policy",
					"description": "A test CWP policy for unit testing",
					"evaluationModes": ["runtime"],
					"evaluationStage": "build",
					"rulesIds": ["rule-1", "rule-2"],
					"condition": "process.name == 'suspicious'",
					"exception": "process.path startswith '/usr/bin'",
					"assetScope": "all",
					"assetGroupsIDs": [1, 2, 3],
					"assetGroups": ["group-1", "group-2"],
					"action": "block",
					"severity": "high",
					"remediationGuidance": "Investigate and remediate the suspicious process"
				}`)
			} else {
				// Return updated policy data
				fmt.Fprintln(w, `{
					"id": "123",
					"revision": 2,
					"createdAt": "2023-01-01T00:00:00Z",
					"modifiedAt": "2023-01-01T01:00:00Z",
					"type": "workload_protection",
					"createdBy": "admin@example.com",
					"disabled": false,
					"name": "Updated Test CWP Policy",
					"description": "An updated test CWP policy for unit testing",
					"evaluationModes": ["runtime", "build"],
					"evaluationStage": "runtime",
					"rulesIds": ["rule-1", "rule-2", "rule-3"],
					"condition": "process.name == 'suspicious'",
					"exception": "process.path startswith '/usr/bin'",
					"assetScope": "all",
					"assetGroupsIDs": [1, 2, 3, 4],
					"assetGroups": ["group-1", "group-2", "group-3"],
					"action": "alert", 
					"severity": "medium",
					"remediationGuidance": "Updated remediation guidance"
				}`)
			}
			return
		}

		// Handle policy updates
		if r.Method == http.MethodPut && (strings.HasSuffix(r.URL.Path, "/public_api/v1/cwp/policies") ||
			strings.Contains(r.URL.Path, "/public_api/v1/cwp/policies/123")) {
			// Read body to check if it contains "Updated Test CWP Policy"
			bodyBytes, _ := io.ReadAll(r.Body)
			r.Body = io.NopCloser(strings.NewReader(string(bodyBytes))) // Replace the body

			fmt.Printf("--- UPDATE BODY: %s ---\n", string(bodyBytes))

			if strings.Contains(string(bodyBytes), "Updated Test CWP Policy") {
				updated.Store(true)
				fmt.Println("--- SETTING UPDATED FLAG ---")
			}

			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, `{"message":"policy updated successfully"}`) //nolint:errcheck
			return
		}

		// Handle policy deletion
		if r.Method == http.MethodDelete && (strings.Contains(r.URL.Path, "/public_api/v1/cwp/policies/123") ||
			strings.Contains(r.URL.Path, "/public_api/v1/cwp/delete_policy/123")) {
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, `{"message": "policy deleted successfully"}`) //nolint:errcheck
			return
		}

		// Log the unhandled request and return a not found
		fmt.Printf("--- UNHANDLED REQUEST: %s %s ---\n", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprintln(w, `{"error": "Not found"}`) //nolint:errcheck
	}))
	defer server.Close()

	resource.Test(t, resource.TestCase{
		IsUnitTest: true,
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"cortexcloud": providerserver.NewProtocol6WithError(provider.New("test")()),
		},
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
					provider "cortexcloud" {
						api_url   = "%s"
						api_key   = "test"
						api_key_id = 123
					}

					resource "cortexcloud_cwp_policy" "test" {
						name                = "Test CWP Policy"
						description         = "A test CWP policy for unit testing"
						type               = "workload_protection"
						disabled           = false
						evaluation_modes   = ["runtime"]
						evaluation_stage   = "build"
						rules_ids          = ["rule-1", "rule-2"]
						condition          = "process.name == 'suspicious'"
						exception          = "process.path startswith '/usr/bin'"
						asset_scope        = "all"
						asset_group_ids    = [1, 2, 3]
						policy_action      = "block"
						policy_severity    = "high"
						remediation_guidance = "Investigate and remediate the suspicious process"
					}
				`, server.URL),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("cortexcloud_cwp_policy.test", "id", "123"),
					resource.TestCheckResourceAttr("cortexcloud_cwp_policy.test", "name", "Test CWP Policy"),
					resource.TestCheckResourceAttr("cortexcloud_cwp_policy.test", "description", "A test CWP policy for unit testing"),
					resource.TestCheckResourceAttr("cortexcloud_cwp_policy.test", "type", "workload_protection"),
					resource.TestCheckResourceAttr("cortexcloud_cwp_policy.test", "disabled", "false"),
					resource.TestCheckResourceAttr("cortexcloud_cwp_policy.test", "revision", "1"),
					resource.TestCheckResourceAttr("cortexcloud_cwp_policy.test", "created_by", "admin@example.com"),
					resource.TestCheckResourceAttrSet("cortexcloud_cwp_policy.test", "created_at"),
					resource.TestCheckResourceAttrSet("cortexcloud_cwp_policy.test", "modified_at"),
				),
			},
			// Update test
			{
				Config: fmt.Sprintf(`
						provider "cortexcloud" {
							api_url   = "%s"
							api_key   = "test"
							api_key_id = 123
						}

						resource "cortexcloud_cwp_policy" "test" {
							name                = "Updated Test CWP Policy"
							description         = "An updated test CWP policy for unit testing"
							type               = "workload_protection"
							disabled           = false
							evaluation_modes   = ["runtime", "build"]
							evaluation_stage   = "runtime"
							rules_ids          = ["rule-1", "rule-2", "rule-3"]
							condition          = "process.name == 'suspicious'"
							exception          = "process.path startswith '/usr/bin'"
							asset_scope        = "all"
							asset_group_ids    = [1, 2, 3, 4]
							policy_action      = "alert"
							policy_severity    = "medium"
							remediation_guidance = "Updated remediation guidance"
						}
					`, server.URL),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("cortexcloud_cwp_policy.test", "id", "123"),
					resource.TestCheckResourceAttr("cortexcloud_cwp_policy.test", "name", "Updated Test CWP Policy"),
					resource.TestCheckResourceAttr("cortexcloud_cwp_policy.test", "description", "An updated test CWP policy for unit testing"),
					resource.TestCheckResourceAttr("cortexcloud_cwp_policy.test", "revision", "2"),
				),
				// Tell the test framework that it's okay to have a non-empty plan after apply
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// TestUnitPolicyResourceMinimal tests the creation of a CWP policy resource with only the minimal required fields.
// This test verifies that the provider can successfully create a policy when only name and type are specified,
// and that all other fields are properly handled with default or empty values. It validates the basic
// create-read lifecycle for the simplest possible policy configuration.
func TestUnitPolicyResourceMinimal(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		// Handle policy creation
		if r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/public_api/v1/cwp/policies") {
			w.WriteHeader(http.StatusCreated)
			fmt.Fprintln(w, `{
				"id": "456"
			}`) //nolint:errcheck
			return
		}

		// Handle policy retrieval by ID
		if r.Method == http.MethodGet && (strings.Contains(r.URL.Path, "/public_api/v1/cwp/policies/456") ||
			strings.Contains(r.URL.Path, "/public_api/v1/cwp/policies/456")) {
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, `{
				"id": "456",
				"revision": 1,
				"createdAt": "2023-01-01T00:00:00Z",
				"modifiedAt": "2023-01-01T00:00:00Z",
				"type": "runtime_protection",
				"createdBy": "admin@example.com",
				"disabled": false,
				"name": "Minimal Policy",
				"description": "",
				"evaluationModes": [],
				"evaluationStage": "",
				"rulesIds": [],
				"condition": "",
				"exception": "",
				"assetScope": "",
				"assetGroupsIDs": [],
				"assetGroups": [],
				"action": "",
				"severity": "",
				"remediationGuidance": ""
			}`) //nolint:errcheck
			return
		}

		// Handle policy deletion
		if r.Method == http.MethodDelete && (strings.Contains(r.URL.Path, "/public_api/v1/cwp/policies/456") ||
			strings.Contains(r.URL.Path, "/public_api/v1/cwp/policies/456")) {
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, `{"message": "policy deleted successfully"}`) //nolint:errcheck
			return
		}

		// Default response for unmatched requests
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprintln(w, `{"error": "Not found"}`) //nolint:errcheck
	}))
	defer server.Close()

	resource.Test(t, resource.TestCase{
		IsUnitTest: true,
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"cortexcloud": providerserver.NewProtocol6WithError(provider.New("test")()),
		},
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
					provider "cortexcloud" {
						api_url   = "%s"
						api_key   = "test"
						api_key_id = 123
					}

					resource "cortexcloud_cwp_policy" "minimal" {
						name = "Minimal Policy"
						type = "runtime_protection"
					}
				`, server.URL),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("cortexcloud_cwp_policy.minimal", "id", "456"),
					resource.TestCheckResourceAttr("cortexcloud_cwp_policy.minimal", "name", "Minimal Policy"),
					resource.TestCheckResourceAttr("cortexcloud_cwp_policy.minimal", "type", "runtime_protection"),
					resource.TestCheckResourceAttr("cortexcloud_cwp_policy.minimal", "disabled", "false"),
					resource.TestCheckResourceAttr("cortexcloud_cwp_policy.minimal", "revision", "1"),
					resource.TestCheckResourceAttr("cortexcloud_cwp_policy.minimal", "created_by", "admin@example.com"),
					resource.TestCheckResourceAttrSet("cortexcloud_cwp_policy.minimal", "created_at"),
					resource.TestCheckResourceAttrSet("cortexcloud_cwp_policy.minimal", "modified_at"),
				),
			},
		},
	})
}

func TestUnitPolicyResourceCreateOnly(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		// Handle policy creation
		if r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/public_api/v1/cwp/policies") {
			w.WriteHeader(http.StatusCreated)
			fmt.Fprintln(w, `{
				"id": "789"
			}`) //nolint:errcheck
			return
		}

		// Handle policy retrieval by ID
		if r.Method == http.MethodGet && (strings.Contains(r.URL.Path, "/public_api/v1/cwp/policies/789") ||
			strings.Contains(r.URL.Path, "/public_api/v1/cwp/policies/789")) {
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, `{
				"id": "789",
				"revision": 1,
				"createdAt": "2023-01-01T00:00:00Z",
				"modifiedAt": "2023-01-01T00:00:00Z",
				"type": "workload_protection",
				"createdBy": "admin@example.com",
				"disabled": false,
				"name": "Create Only Policy",
				"description": "A policy for testing creation only",
				"evaluationModes": ["runtime"],
				"evaluationStage": "build",
				"rulesIds": ["rule-1"],
				"condition": "",
				"exception": "",
				"assetScope": "specific",
				"assetGroupsIDs": [1],
				"assetGroups": ["test-group"],
				"action": "alert",
				"severity": "medium",
				"remediationGuidance": "Review policy configuration"
			}`) //nolint:errcheck
			return
		}

		// Handle policy deletion
		if r.Method == http.MethodDelete && (strings.Contains(r.URL.Path, "/public_api/v1/cwp/policies/789") ||
			strings.Contains(r.URL.Path, "/public_api/v1/cwp/policies/789")) {
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, `{"message": "policy deleted successfully"}`) //nolint:errcheck
			return
		}

		// Default response
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprintln(w, `{"error": "Not found"}`) //nolint:errcheck
	}))
	defer server.Close()

	resource.Test(t, resource.TestCase{
		IsUnitTest: true,
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"cortexcloud": providerserver.NewProtocol6WithError(provider.New("test")()),
		},
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
					provider "cortexcloud" {
						api_url   = "%s"
						api_key   = "test"
						api_key_id = 123
					}

					resource "cortexcloud_cwp_policy" "create_only" {
						name                = "Create Only Policy"
						description         = "A policy for testing creation only"
						type               = "workload_protection"
						disabled           = false
						evaluation_modes   = ["runtime"]
						evaluation_stage   = "build"
						rules_ids          = ["rule-1"]
						asset_scope        = "specific"
						asset_group_ids    = [1]
						policy_action      = "alert"
						policy_severity    = "medium"
						remediation_guidance = "Review policy configuration"
					}
				`, server.URL),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("cortexcloud_cwp_policy.create_only", "id", "789"),
					resource.TestCheckResourceAttr("cortexcloud_cwp_policy.create_only", "name", "Create Only Policy"),
					resource.TestCheckResourceAttr("cortexcloud_cwp_policy.create_only", "description", "A policy for testing creation only"),
					resource.TestCheckResourceAttr("cortexcloud_cwp_policy.create_only", "type", "workload_protection"),
					resource.TestCheckResourceAttr("cortexcloud_cwp_policy.create_only", "disabled", "false"),
					resource.TestCheckResourceAttr("cortexcloud_cwp_policy.create_only", "evaluation_modes.#", "1"),
					resource.TestCheckResourceAttr("cortexcloud_cwp_policy.create_only", "evaluation_modes.0", "runtime"),
					resource.TestCheckResourceAttr("cortexcloud_cwp_policy.create_only", "evaluation_stage", "build"),
					resource.TestCheckResourceAttr("cortexcloud_cwp_policy.create_only", "rules_ids.#", "1"),
					resource.TestCheckResourceAttr("cortexcloud_cwp_policy.create_only", "rules_ids.0", "rule-1"),
					resource.TestCheckResourceAttr("cortexcloud_cwp_policy.create_only", "asset_scope", "specific"),
					resource.TestCheckResourceAttr("cortexcloud_cwp_policy.create_only", "asset_group_ids.#", "1"),
					resource.TestCheckResourceAttr("cortexcloud_cwp_policy.create_only", "asset_group_ids.0", "1"),
					resource.TestCheckResourceAttr("cortexcloud_cwp_policy.create_only", "asset_groups.#", "1"),
					resource.TestCheckResourceAttr("cortexcloud_cwp_policy.create_only", "asset_groups.0", "test-group"),
					resource.TestCheckResourceAttr("cortexcloud_cwp_policy.create_only", "policy_action", "alert"),
					resource.TestCheckResourceAttr("cortexcloud_cwp_policy.create_only", "policy_severity", "medium"),
					resource.TestCheckResourceAttr("cortexcloud_cwp_policy.create_only", "remediation_guidance", "Review policy configuration"),
					resource.TestCheckResourceAttr("cortexcloud_cwp_policy.create_only", "revision", "1"),
					resource.TestCheckResourceAttr("cortexcloud_cwp_policy.create_only", "created_by", "admin@example.com"),
					resource.TestCheckResourceAttrSet("cortexcloud_cwp_policy.create_only", "created_at"),
					resource.TestCheckResourceAttrSet("cortexcloud_cwp_policy.create_only", "modified_at"),
				),
			},
		},
	})
}
