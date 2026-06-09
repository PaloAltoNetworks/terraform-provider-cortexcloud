// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package cloudsec_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/provider"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestUnitCloudSecPolicyDataSource_ReadAllRules(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		for strings.Contains(path, "//") {
			path = strings.ReplaceAll(path, "//", "/")
		}
		if strings.HasSuffix(path, "/") && path != "/" {
			path = strings.TrimSuffix(path, "/")
		}

		switch {
		case path == "/public_api/v1/policy/policy-all-rules-123" && r.Method == http.MethodGet:
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, `{
				"data": {
					"id": "policy-all-rules-123",
					"name": "All Rules Policy",
					"description": "Policy matching all rules",
					"labels": ["production", "security"],
					"rule_matching_type": "ALL_RULES",
					"asset_matching_type": "ALL_ASSETS",
					"enabled": true,
					"mode": "CUSTOM",
					"creation_time": 1678886400000,
					"created_by": "test-user",
					"modification_time": 1678886400000,
					"modified_by": "test-user"
				}
			}`)

		default:
			http.Error(w, "not found: "+r.URL.Path, http.StatusNotFound)
		}
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
						api_url    = "%s"
						api_key    = "test"
						api_key_id = 123
					}
					data "cortexcloud_cloudsec_policy" "test" {
						id = "policy-all-rules-123"
					}
				`, server.URL),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("data.cortexcloud_cloudsec_policy.test", "id", "policy-all-rules-123"),
					resource.TestCheckResourceAttr("data.cortexcloud_cloudsec_policy.test", "name", "All Rules Policy"),
					resource.TestCheckResourceAttr("data.cortexcloud_cloudsec_policy.test", "description", "Policy matching all rules"),
					resource.TestCheckResourceAttr("data.cortexcloud_cloudsec_policy.test", "labels.#", "2"),
					resource.TestCheckTypeSetElemAttr("data.cortexcloud_cloudsec_policy.test", "labels.*", "production"),
					resource.TestCheckTypeSetElemAttr("data.cortexcloud_cloudsec_policy.test", "labels.*", "security"),
					resource.TestCheckResourceAttr("data.cortexcloud_cloudsec_policy.test", "rule_matching.type", "ALL_RULES"),
					resource.TestCheckResourceAttr("data.cortexcloud_cloudsec_policy.test", "asset_matching.type", "ALL_ASSETS"),
					resource.TestCheckResourceAttr("data.cortexcloud_cloudsec_policy.test", "enabled", "true"),
					resource.TestCheckResourceAttr("data.cortexcloud_cloudsec_policy.test", "mode", "CUSTOM"),
					resource.TestCheckResourceAttr("data.cortexcloud_cloudsec_policy.test", "created_by", "test-user"),
					resource.TestCheckResourceAttr("data.cortexcloud_cloudsec_policy.test", "created_at", "1678886400000"),
					resource.TestCheckResourceAttr("data.cortexcloud_cloudsec_policy.test", "updated_by", "test-user"),
					resource.TestCheckResourceAttr("data.cortexcloud_cloudsec_policy.test", "updated_at", "1678886400000"),
				),
			},
		},
	})
}

func TestUnitCloudSecPolicyDataSource_ReadSpecificRules(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		for strings.Contains(path, "//") {
			path = strings.ReplaceAll(path, "//", "/")
		}
		if strings.HasSuffix(path, "/") && path != "/" {
			path = strings.TrimSuffix(path, "/")
		}

		switch {
		case path == "/public_api/v1/policy/policy-specific-rules-456" && r.Method == http.MethodGet:
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, `{
				"data": {
					"id": "policy-specific-rules-456",
					"name": "Specific Rules Policy",
					"description": "Policy with specific rule IDs",
					"labels": ["security", "compliance"],
					"rule_matching_type": "RULES",
					"associated_rule_ids": ["rule-id-1", "rule-id-2", "rule-id-3"],
					"asset_matching_type": "ASSET_GROUPS",
					"associated_asset_group_ids": [100, 200, 300],
					"enabled": true,
					"mode": "CUSTOM",
					"creation_time": 1678886400000,
					"created_by": "test-user",
					"modification_time": 1678886400000,
					"modified_by": "test-user"
				}
			}`)

		default:
			http.Error(w, "not found: "+r.URL.Path, http.StatusNotFound)
		}
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
						api_url    = "%s"
						api_key    = "test"
						api_key_id = 123
					}
					data "cortexcloud_cloudsec_policy" "test" {
						id = "policy-specific-rules-456"
					}
				`, server.URL),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("data.cortexcloud_cloudsec_policy.test", "id", "policy-specific-rules-456"),
					resource.TestCheckResourceAttr("data.cortexcloud_cloudsec_policy.test", "name", "Specific Rules Policy"),
					resource.TestCheckResourceAttr("data.cortexcloud_cloudsec_policy.test", "description", "Policy with specific rule IDs"),
					resource.TestCheckResourceAttr("data.cortexcloud_cloudsec_policy.test", "labels.#", "2"),
					resource.TestCheckTypeSetElemAttr("data.cortexcloud_cloudsec_policy.test", "labels.*", "security"),
					resource.TestCheckTypeSetElemAttr("data.cortexcloud_cloudsec_policy.test", "labels.*", "compliance"),
					resource.TestCheckResourceAttr("data.cortexcloud_cloudsec_policy.test", "rule_matching.type", "RULES"),
					resource.TestCheckResourceAttr("data.cortexcloud_cloudsec_policy.test", "rule_matching.rules.0", "rule-id-1"),
					resource.TestCheckResourceAttr("data.cortexcloud_cloudsec_policy.test", "rule_matching.rules.1", "rule-id-2"),
					resource.TestCheckResourceAttr("data.cortexcloud_cloudsec_policy.test", "rule_matching.rules.2", "rule-id-3"),
					resource.TestCheckResourceAttr("data.cortexcloud_cloudsec_policy.test", "asset_matching.type", "ASSET_GROUPS"),
					resource.TestCheckResourceAttr("data.cortexcloud_cloudsec_policy.test", "asset_matching.asset_group_ids.0", "100"),
					resource.TestCheckResourceAttr("data.cortexcloud_cloudsec_policy.test", "asset_matching.asset_group_ids.1", "200"),
					resource.TestCheckResourceAttr("data.cortexcloud_cloudsec_policy.test", "asset_matching.asset_group_ids.2", "300"),
					resource.TestCheckResourceAttr("data.cortexcloud_cloudsec_policy.test", "enabled", "true"),
					resource.TestCheckResourceAttr("data.cortexcloud_cloudsec_policy.test", "mode", "CUSTOM"),
				),
			},
		},
	})
}

func TestUnitCloudSecPolicyDataSource_ReadRuleFilter(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		for strings.Contains(path, "//") {
			path = strings.ReplaceAll(path, "//", "/")
		}
		if strings.HasSuffix(path, "/") && path != "/" {
			path = strings.TrimSuffix(path, "/")
		}

		switch {
		case path == "/public_api/v1/policy/policy-filter-789" && r.Method == http.MethodGet:
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, `{
				"data": {
					"id": "policy-filter-789",
					"name": "Filtered Rules Policy",
					"description": "Policy with rule filter",
					"labels": ["high-severity"],
					"rule_matching_type": "RULE_FILTER",
					"associated_rule_filter": {
						"SEARCH_FIELD": "severity",
						"SEARCH_TYPE": "EQ",
						"SEARCH_VALUE": "high"
					},
					"asset_matching_type": "CLOUD_ACCOUNTS",
					"associated_cloud_account_ids": ["account-1", "account-2"],
					"enabled": true,
					"mode": "CUSTOM",
					"creation_time": 1678886400000,
					"created_by": "test-user",
					"modification_time": 1678886400000,
					"modified_by": "test-user"
				}
			}`)

		default:
			http.Error(w, "not found: "+r.URL.Path, http.StatusNotFound)
		}
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
						api_url    = "%s"
						api_key    = "test"
						api_key_id = 123
					}
					data "cortexcloud_cloudsec_policy" "test" {
						id = "policy-filter-789"
					}
				`, server.URL),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("data.cortexcloud_cloudsec_policy.test", "id", "policy-filter-789"),
					resource.TestCheckResourceAttr("data.cortexcloud_cloudsec_policy.test", "name", "Filtered Rules Policy"),
					resource.TestCheckResourceAttr("data.cortexcloud_cloudsec_policy.test", "description", "Policy with rule filter"),
					resource.TestCheckResourceAttr("data.cortexcloud_cloudsec_policy.test", "labels.#", "1"),
					resource.TestCheckTypeSetElemAttr("data.cortexcloud_cloudsec_policy.test", "labels.*", "high-severity"),
					resource.TestCheckResourceAttr("data.cortexcloud_cloudsec_policy.test", "rule_matching.type", "RULE_FILTER"),
					resource.TestCheckResourceAttr("data.cortexcloud_cloudsec_policy.test", "rule_matching.filter_criteria.field", "severity"),
					resource.TestCheckResourceAttr("data.cortexcloud_cloudsec_policy.test", "rule_matching.filter_criteria.type", "EQ"),
					resource.TestCheckResourceAttr("data.cortexcloud_cloudsec_policy.test", "rule_matching.filter_criteria.value", "high"),
					resource.TestCheckResourceAttr("data.cortexcloud_cloudsec_policy.test", "asset_matching.type", "CLOUD_ACCOUNTS"),
					resource.TestCheckResourceAttr("data.cortexcloud_cloudsec_policy.test", "asset_matching.cloud_account_ids.0", "account-1"),
					resource.TestCheckResourceAttr("data.cortexcloud_cloudsec_policy.test", "asset_matching.cloud_account_ids.1", "account-2"),
					resource.TestCheckResourceAttr("data.cortexcloud_cloudsec_policy.test", "enabled", "true"),
					resource.TestCheckResourceAttr("data.cortexcloud_cloudsec_policy.test", "mode", "CUSTOM"),
				),
			},
		},
	})
}

func TestUnitCloudSecPolicyDataSource_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		for strings.Contains(path, "//") {
			path = strings.ReplaceAll(path, "//", "/")
		}
		if strings.HasSuffix(path, "/") && path != "/" {
			path = strings.TrimSuffix(path, "/")
		}

		switch {
		case path == "/public_api/v1/policy/non-existent-policy-id" && r.Method == http.MethodGet:
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprintln(w, `{
				"error": "Policy not found"
			}`)

		default:
			http.Error(w, "not found: "+r.URL.Path, http.StatusNotFound)
		}
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
						api_url    = "%s"
						api_key    = "test"
						api_key_id = 123
					}
					data "cortexcloud_cloudsec_policy" "test" {
						id = "non-existent-policy-id"
					}
				`, server.URL),
				ExpectError: regexp.MustCompile("Error Reading CloudSec Policy|Could not read policy"),
			},
		},
	})
}
