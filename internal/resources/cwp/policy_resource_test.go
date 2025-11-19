// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package cwp_test

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/provider"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestUnitPolicyResource(t *testing.T) {
	var updated atomic.Bool

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		// Handle policy creation
		if r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/public_api/v1/cwp/policies") {
			w.WriteHeader(http.StatusCreated)
			fmt.Fprintln(w, `{
				"id": "123"
			}`) //nolint:errcheck
			return
		}

		// Handle policy retrieval by ID
		if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/public_api/v1/cwp/get_policy_details/123") {
			log.Printf("--- DEBUG: GET HANDLER HIT. updated.Load() is: %v ---", updated.Load()) // <-- ADD THIS

			w.WriteHeader(http.StatusOK)
			if !updated.Load() {
				_, _ = fmt.Fprintln(w, `{
					"id": "123",
					"revision": 1,
					"created_at": "2023-01-01T00:00:00Z",
					"modified_at": "2023-01-01T00:00:00Z",
					"type": "workload_protection",
					"created_by": "admin@example.com",
					"disabled": false,
					"name": "Test CWP Policy",
					"description": "A test CWP policy for unit testing",
					"evaluation_modes": ["runtime"],
					"evaluation_stage": "build",
					"rules_ids": ["rule-1", "rule-2"],
					"condition": "process.name == 'suspicious'",
					"exception": "process.path startswith '/usr/bin'",
					"asset_scope": "all",
					"asset_group_ids": [1, 2, 3],
					"asset_groups": ["group-1", "group-2"],
					"policy_action": "block",
					"policy_severity": "high",
					"remediation_guidance": "Investigate and remediate the suspicious process"
				}`)
				return
			}
			_, _ = fmt.Fprintln(w, `{
				"id": "123",
				"revision": 2,
				"created_at": "2023-01-01T00:00:00Z",
				"modified_at": "2023-01-01T01:00:00Z",
				"type": "workload_protection",
				"created_by": "admin@example.com",
				"disabled": false,
				"name": "Updated Test CWP Policy",
				"description": "An updated test CWP policy for unit testing",
				"evaluation_modes": ["runtime", "build"],
				"evaluation_stage": "runtime",
				"rules_ids": ["rule-1", "rule-2", "rule-3"],
				"condition": "process.name == 'suspicious'",
				"exception": "process.path startswith '/usr/bin'",
				"asset_scope": "all",
				"asset_group_ids": [1, 2, 3, 4],
				"asset_groups": ["group-1", "group-2", "group-3"],
				"policy_action": "alert",
				"policy_severity": "medium",
				"remediation_guidance": "Updated remediation guidance"
			}`)
			return
		}

		// Handle policy updates - this endpoint should receive the PUT request
		// if the SDK issue is fixed
		// In your test server handler, make sure after a PUT request, subsequent GETs return the updated data
		// Handle policy updates
		if r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/public_api/v1/cwp/policies/123") {
			log.Println("--- DEBUG: PUT HANDLER HIT ---") // <-- ADD THIS

			bodyBytes, _ := io.ReadAll(r.Body)
			r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
			bodyString := string(bodyBytes)

			log.Printf("--- DEBUG: PUT BODY --- \n%s\n -----------------", bodyString) // <-- ADD THIS

			if strings.Contains(bodyString, `"Updated Test CWP Policy"`) {
				log.Println("--- DEBUG: Body contains updated name. Setting atomic.Store(true) ---") // <-- ADD THIS
				updated.Store(true)
			} else {
				log.Println("--- DEBUG: Body ***DOES NOT*** contain updated name. ---") // <-- ADD THIS
			}

			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprintln(w, `{"message":"policy updated successfully"}`)
			return
		}

		// Handle policy deletion
		if r.Method == http.MethodDelete && strings.Contains(r.URL.Path, "/public_api/v1/cwp/delete_policy/123") {
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, `{
				"message": "policy deleted successfully"
			}`) //nolint:errcheck
			return
		}

		w.WriteHeader(http.StatusNotFound)
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
			// Skip update test for now due to SDK limitation
			// When SDK is fixed, this step can be uncommented
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
			},
		},
	})
}

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
		if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/public_api/v1/cwp/get_policy_details/456") {
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprintln(w, `{
				"id": "456",
				"revision": 1,
				"created_at": "2023-01-01T00:00:00Z",
				"modified_at": "2023-01-01T00:00:00Z",
				"type": "runtime_protection",
				"created_by": "admin@example.com",
				"disabled": false,
				"name": "Minimal Policy",
				"description": "",
				"evaluation_modes": [],
				"evaluation_stage": "",
				"rules_ids": [],
				"condition": "",
				"exception": "",
				"asset_scope": "",
				"asset_group_ids": [],
				"asset_groups": [],
				"policy_action": "",
				"policy_severity": "",
				"remediation_guidance": ""
			}`)
			return
		}

		// Handle policy deletion
		if r.Method == http.MethodDelete && strings.Contains(r.URL.Path, "/public_api/v1/cwp/delete_policy/456") {
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, `{
				"message": "policy deleted successfully"
			}`) //nolint:errcheck
			return
		}

		w.WriteHeader(http.StatusNotFound)
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
		if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/public_api/v1/cwp/get_policy_details/789") {
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprintln(w, `{
				"id": "789",
				"revision": 1,
				"created_at": "2023-01-01T00:00:00Z",
				"modified_at": "2023-01-01T00:00:00Z",
				"type": "workload_protection",
				"created_by": "admin@example.com",
				"disabled": false,
				"name": "Create Only Policy",
				"description": "A policy for testing creation only",
				"evaluation_modes": ["runtime"],
				"evaluation_stage": "build",
				"rules_ids": ["rule-1"],
				"condition": "",
				"exception": "",
				"asset_scope": "specific",
				"asset_group_ids": [1],
				"asset_groups": ["test-group"],
				"policy_action": "alert",
				"policy_severity": "medium",
				"remediation_guidance": "Review policy configuration"
			}`)
			return
		}

		// Handle policy deletion
		if r.Method == http.MethodDelete && strings.Contains(r.URL.Path, "/public_api/v1/cwp/delete_policy/789") {
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, `{
				"message": "policy deleted successfully"
			}`) //nolint:errcheck
			return
		}

		w.WriteHeader(http.StatusNotFound)
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
