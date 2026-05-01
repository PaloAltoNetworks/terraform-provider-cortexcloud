// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package cloudsec_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/provider"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestUnitCloudSecPolicyResource_CreateAllRules(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		for strings.Contains(path, "//") {
			path = strings.ReplaceAll(path, "//", "/")
		}
		if strings.HasSuffix(path, "/") && path != "/" {
			path = strings.TrimSuffix(path, "/")
		}

		switch {
		case path == "/public_api/v1/policy" && r.Method == http.MethodPost:
			w.WriteHeader(http.StatusCreated)
			fmt.Fprintln(w, `{
				"data": {
					"id": "policy-all-rules-123",
					"name": "All Rules Policy",
					"description": "Policy matching all rules",
					"labels": ["production"],
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

		case path == "/public_api/v1/policy/policy-all-rules-123" && r.Method == http.MethodGet:
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, `{
				"data": {
					"id": "policy-all-rules-123",
					"name": "All Rules Policy",
					"description": "Policy matching all rules",
					"labels": ["production"],
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

		case path == "/public_api/v1/policy/policy-all-rules-123" && r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusOK)

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
					resource "cortexcloud_cloudsec_policy" "test" {
						name        = "All Rules Policy"
						description = "Policy matching all rules"
						labels      = ["production"]
						rule_matching = {
							type = "ALL_RULES"
						}
						asset_matching = {
							type = "ALL_ASSETS"
						}
						enabled = true
					}
				`, server.URL),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("cortexcloud_cloudsec_policy.test", "id", "policy-all-rules-123"),
					resource.TestCheckResourceAttr("cortexcloud_cloudsec_policy.test", "name", "All Rules Policy"),
					resource.TestCheckResourceAttr("cortexcloud_cloudsec_policy.test", "description", "Policy matching all rules"),
					resource.TestCheckResourceAttr("cortexcloud_cloudsec_policy.test", "rule_matching.type", "ALL_RULES"),
					resource.TestCheckResourceAttr("cortexcloud_cloudsec_policy.test", "asset_matching.type", "ALL_ASSETS"),
					resource.TestCheckResourceAttr("cortexcloud_cloudsec_policy.test", "enabled", "true"),
					resource.TestCheckResourceAttr("cortexcloud_cloudsec_policy.test", "mode", "CUSTOM"),
				),
			},
		},
	})
}

func TestUnitCloudSecPolicyResource_CreateSpecificRules(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		for strings.Contains(path, "//") {
			path = strings.ReplaceAll(path, "//", "/")
		}
		if strings.HasSuffix(path, "/") && path != "/" {
			path = strings.TrimSuffix(path, "/")
		}

		switch {
		case path == "/public_api/v1/policy" && r.Method == http.MethodPost:
			w.WriteHeader(http.StatusCreated)
			fmt.Fprintln(w, `{
				"data": {
					"id": "policy-specific-rules-456",
					"name": "Specific Rules Policy",
					"description": "Policy with specific rule IDs",
					"labels": ["security", "compliance"],
					"rule_matching_type": "RULES",
					"associated_rule_ids": ["rule-id-1", "rule-id-2", "rule-id-3"],
					"asset_matching_type": "ASSET_GROUPS",
					"associated_asset_group_ids": [100, 200],
					"enabled": true,
					"mode": "CUSTOM",
					"creation_time": 1678886400000,
					"created_by": "test-user",
					"modification_time": 1678886400000,
					"modified_by": "test-user"
				}
			}`)

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
					"associated_asset_group_ids": [100, 200],
					"enabled": true,
					"mode": "CUSTOM",
					"creation_time": 1678886400000,
					"created_by": "test-user",
					"modification_time": 1678886400000,
					"modified_by": "test-user"
				}
			}`)

		case path == "/public_api/v1/policy/policy-specific-rules-456" && r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusOK)

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
					resource "cortexcloud_cloudsec_policy" "test" {
						name        = "Specific Rules Policy"
						description = "Policy with specific rule IDs"
						labels      = ["security", "compliance"]
						rule_matching = {
							type  = "RULES"
							rules = ["rule-id-1", "rule-id-2", "rule-id-3"]
						}
						asset_matching = {
							type            = "ASSET_GROUPS"
							asset_group_ids = [100, 200]
						}
						enabled = true
					}
				`, server.URL),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("cortexcloud_cloudsec_policy.test", "id", "policy-specific-rules-456"),
					resource.TestCheckResourceAttr("cortexcloud_cloudsec_policy.test", "name", "Specific Rules Policy"),
					resource.TestCheckResourceAttr("cortexcloud_cloudsec_policy.test", "rule_matching.type", "RULES"),
					resource.TestCheckResourceAttr("cortexcloud_cloudsec_policy.test", "rule_matching.rules.0", "rule-id-1"),
					resource.TestCheckResourceAttr("cortexcloud_cloudsec_policy.test", "rule_matching.rules.1", "rule-id-2"),
					resource.TestCheckResourceAttr("cortexcloud_cloudsec_policy.test", "rule_matching.rules.2", "rule-id-3"),
					resource.TestCheckResourceAttr("cortexcloud_cloudsec_policy.test", "asset_matching.type", "ASSET_GROUPS"),
					resource.TestCheckResourceAttr("cortexcloud_cloudsec_policy.test", "asset_matching.asset_group_ids.0", "100"),
					resource.TestCheckResourceAttr("cortexcloud_cloudsec_policy.test", "asset_matching.asset_group_ids.1", "200"),
				),
			},
		},
	})
}

func TestUnitCloudSecPolicyResource_CreateRuleFilter(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		for strings.Contains(path, "//") {
			path = strings.ReplaceAll(path, "//", "/")
		}
		if strings.HasSuffix(path, "/") && path != "/" {
			path = strings.TrimSuffix(path, "/")
		}

		switch {
		case path == "/public_api/v1/policy" && r.Method == http.MethodPost:
			w.WriteHeader(http.StatusCreated)
			fmt.Fprintln(w, `{
				"data": {
					"id": "policy-filter-789",
					"name": "Filtered Rules Policy",
					"description": "Policy with rule filter",
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

		case path == "/public_api/v1/policy/policy-filter-789" && r.Method == http.MethodGet:
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, `{
				"data": {
					"id": "policy-filter-789",
					"name": "Filtered Rules Policy",
					"description": "Policy with rule filter",
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

		case path == "/public_api/v1/policy/policy-filter-789" && r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusOK)

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
					resource "cortexcloud_cloudsec_policy" "test" {
						name        = "Filtered Rules Policy"
						description = "Policy with rule filter"
						rule_matching = {
							type = "RULE_FILTER"
							filter_criteria = {
								field = "severity"
								type  = "EQ"
								value = "high"
							}
						}
						asset_matching = {
							type              = "CLOUD_ACCOUNTS"
							cloud_account_ids = ["account-1", "account-2"]
						}
						enabled = true
					}
				`, server.URL),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("cortexcloud_cloudsec_policy.test", "id", "policy-filter-789"),
					resource.TestCheckResourceAttr("cortexcloud_cloudsec_policy.test", "name", "Filtered Rules Policy"),
					resource.TestCheckResourceAttr("cortexcloud_cloudsec_policy.test", "rule_matching.type", "RULE_FILTER"),
					resource.TestCheckResourceAttr("cortexcloud_cloudsec_policy.test", "rule_matching.filter_criteria.field", "severity"),
					resource.TestCheckResourceAttr("cortexcloud_cloudsec_policy.test", "rule_matching.filter_criteria.type", "EQ"),
					resource.TestCheckResourceAttr("cortexcloud_cloudsec_policy.test", "rule_matching.filter_criteria.value", "high"),
					resource.TestCheckResourceAttr("cortexcloud_cloudsec_policy.test", "asset_matching.type", "CLOUD_ACCOUNTS"),
					resource.TestCheckResourceAttr("cortexcloud_cloudsec_policy.test", "asset_matching.cloud_account_ids.0", "account-1"),
					resource.TestCheckResourceAttr("cortexcloud_cloudsec_policy.test", "asset_matching.cloud_account_ids.1", "account-2"),
				),
			},
		},
	})
}

func TestUnitCloudSecPolicyResource_CreateComplexFilter(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		for strings.Contains(path, "//") {
			path = strings.ReplaceAll(path, "//", "/")
		}
		if strings.HasSuffix(path, "/") && path != "/" {
			path = strings.TrimSuffix(path, "/")
		}

		switch {
		case path == "/public_api/v1/policy" && r.Method == http.MethodPost:
			w.WriteHeader(http.StatusCreated)
			fmt.Fprintln(w, `{
				"data": {
					"id": "policy-complex-filter-999",
					"name": "Complex Filter Policy",
					"description": "Policy with nested filter criteria",
					"rule_matching_type": "RULE_FILTER",
					"associated_rule_filter": {
						"AND": [
							{
								"SEARCH_FIELD": "severity",
								"SEARCH_TYPE": "EQ",
								"SEARCH_VALUE": "critical"
							},
							{
								"SEARCH_FIELD": "cloudType",
								"SEARCH_TYPE": "CONTAINS",
								"SEARCH_VALUE": "aws"
							}
						]
					},
					"asset_matching_type": "ALL_ASSETS",
					"enabled": true,
					"mode": "CUSTOM",
					"creation_time": 1678886400000,
					"created_by": "test-user",
					"modification_time": 1678886400000,
					"modified_by": "test-user"
				}
			}`)

		case path == "/public_api/v1/policy/policy-complex-filter-999" && r.Method == http.MethodGet:
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, `{
				"data": {
					"id": "policy-complex-filter-999",
					"name": "Complex Filter Policy",
					"description": "Policy with nested filter criteria",
					"rule_matching_type": "RULE_FILTER",
					"associated_rule_filter": {
						"AND": [
							{
								"SEARCH_FIELD": "severity",
								"SEARCH_TYPE": "EQ",
								"SEARCH_VALUE": "critical"
							},
							{
								"SEARCH_FIELD": "cloudType",
								"SEARCH_TYPE": "CONTAINS",
								"SEARCH_VALUE": "aws"
							}
						]
					},
					"asset_matching_type": "ALL_ASSETS",
					"enabled": true,
					"mode": "CUSTOM",
					"creation_time": 1678886400000,
					"created_by": "test-user",
					"modification_time": 1678886400000,
					"modified_by": "test-user"
				}
			}`)

		case path == "/public_api/v1/policy/policy-complex-filter-999" && r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusOK)

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
					resource "cortexcloud_cloudsec_policy" "test" {
						name        = "Complex Filter Policy"
						description = "Policy with nested filter criteria"
						rule_matching = {
							type = "RULE_FILTER"
							filter_criteria = {
								operator = "AND"
								criteria = [
									{
										field = "severity"
										type  = "EQ"
										value = "critical"
									},
									{
										field = "cloudType"
										type  = "CONTAINS"
										value = "aws"
									}
								]
							}
						}
						asset_matching = {
							type = "ALL_ASSETS"
						}
						enabled = true
					}
				`, server.URL),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("cortexcloud_cloudsec_policy.test", "id", "policy-complex-filter-999"),
					resource.TestCheckResourceAttr("cortexcloud_cloudsec_policy.test", "name", "Complex Filter Policy"),
					resource.TestCheckResourceAttr("cortexcloud_cloudsec_policy.test", "rule_matching.type", "RULE_FILTER"),
					resource.TestCheckResourceAttr("cortexcloud_cloudsec_policy.test", "rule_matching.filter_criteria.operator", "AND"),
				),
			},
		},
	})
}

func TestUnitCloudSecPolicyResource_Update(t *testing.T) {
	var updated bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		for strings.Contains(path, "//") {
			path = strings.ReplaceAll(path, "//", "/")
		}
		if strings.HasSuffix(path, "/") && path != "/" {
			path = strings.TrimSuffix(path, "/")
		}

		switch {
		case path == "/public_api/v1/policy" && r.Method == http.MethodPost:
			w.WriteHeader(http.StatusCreated)
			fmt.Fprintln(w, `{
				"data": {
					"id": "policy-update-111",
					"name": "Original Policy Name",
					"description": "Original description",
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

		case path == "/public_api/v1/policy/policy-update-111" && r.Method == http.MethodGet:
			w.WriteHeader(http.StatusOK)
			if updated {
				fmt.Fprintln(w, `{
					"data": {
						"id": "policy-update-111",
						"name": "Updated Policy Name",
						"description": "Updated description",
						"labels": ["updated", "test"],
						"rule_matching_type": "ALL_RULES",
						"asset_matching_type": "ALL_ASSETS",
						"enabled": false,
						"mode": "CUSTOM",
						"creation_time": 1678886400000,
						"created_by": "test-user",
						"modification_time": 1678886500000,
						"modified_by": "test-user"
					}
				}`)
			} else {
				fmt.Fprintln(w, `{
					"data": {
						"id": "policy-update-111",
						"name": "Original Policy Name",
						"description": "Original description",
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
			}

		case path == "/public_api/v1/policy/policy-update-111" && r.Method == http.MethodPatch:
			updated = true
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, `{
				"data": {
					"id": "policy-update-111",
					"name": "Updated Policy Name",
					"description": "Updated description",
					"labels": ["updated", "test"],
					"rule_matching_type": "ALL_RULES",
					"asset_matching_type": "ALL_ASSETS",
					"enabled": false,
					"mode": "CUSTOM",
					"creation_time": 1678886400000,
					"created_by": "test-user",
					"modification_time": 1678886500000,
					"modified_by": "test-user"
				}
			}`)

		case path == "/public_api/v1/policy/policy-update-111" && r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusOK)

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
					resource "cortexcloud_cloudsec_policy" "test" {
						name        = "Original Policy Name"
						description = "Original description"
						rule_matching = {
							type = "ALL_RULES"
						}
						asset_matching = {
							type = "ALL_ASSETS"
						}
					}
				`, server.URL),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("cortexcloud_cloudsec_policy.test", "name", "Original Policy Name"),
					resource.TestCheckResourceAttr("cortexcloud_cloudsec_policy.test", "enabled", "true"),
				),
			},
			{
				Config: fmt.Sprintf(`
					provider "cortexcloud" {
						api_url    = "%s"
						api_key    = "test"
						api_key_id = 123
					}
					resource "cortexcloud_cloudsec_policy" "test" {
						name        = "Updated Policy Name"
						description = "Updated description"
						labels      = ["updated", "test"]
						rule_matching = {
							type = "ALL_RULES"
						}
						asset_matching = {
							type = "ALL_ASSETS"
						}
						enabled = false
					}
				`, server.URL),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("cortexcloud_cloudsec_policy.test", "id", "policy-update-111"),
					resource.TestCheckResourceAttr("cortexcloud_cloudsec_policy.test", "name", "Updated Policy Name"),
					resource.TestCheckResourceAttr("cortexcloud_cloudsec_policy.test", "description", "Updated description"),
					resource.TestCheckResourceAttr("cortexcloud_cloudsec_policy.test", "labels.0", "updated"),
					resource.TestCheckResourceAttr("cortexcloud_cloudsec_policy.test", "labels.1", "test"),
					resource.TestCheckResourceAttr("cortexcloud_cloudsec_policy.test", "enabled", "false"),
				),
			},
		},
	})
}

func TestUnitCloudSecPolicyResource_UpdateSwitchMatchingType(t *testing.T) {
	var updated bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		for strings.Contains(path, "//") {
			path = strings.ReplaceAll(path, "//", "/")
		}
		if strings.HasSuffix(path, "/") && path != "/" {
			path = strings.TrimSuffix(path, "/")
		}

		switch {
		case path == "/public_api/v1/policy" && r.Method == http.MethodPost:
			w.WriteHeader(http.StatusCreated)
			fmt.Fprintln(w, `{
				"data": {
					"id": "policy-switch-222",
					"name": "Switching Policy",
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

		case path == "/public_api/v1/policy/policy-switch-222" && r.Method == http.MethodGet:
			w.WriteHeader(http.StatusOK)
			if updated {
				fmt.Fprintln(w, `{
					"data": {
						"id": "policy-switch-222",
						"name": "Switching Policy",
						"rule_matching_type": "RULES",
						"associated_rule_ids": ["rule-1", "rule-2"],
						"asset_matching_type": "ALL_ASSETS",
						"enabled": true,
						"mode": "CUSTOM",
						"creation_time": 1678886400000,
						"created_by": "test-user",
						"modification_time": 1678886500000,
						"modified_by": "test-user"
					}
				}`)
			} else {
				fmt.Fprintln(w, `{
					"data": {
						"id": "policy-switch-222",
						"name": "Switching Policy",
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
			}

		case path == "/public_api/v1/policy/policy-switch-222" && r.Method == http.MethodPatch:
			updated = true
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, `{
				"data": {
					"id": "policy-switch-222",
					"name": "Switching Policy",
					"rule_matching_type": "RULES",
					"associated_rule_ids": ["rule-1", "rule-2"],
					"asset_matching_type": "ALL_ASSETS",
					"enabled": true,
					"mode": "CUSTOM",
					"creation_time": 1678886400000,
					"created_by": "test-user",
					"modification_time": 1678886500000,
					"modified_by": "test-user"
				}
			}`)

		case path == "/public_api/v1/policy/policy-switch-222" && r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusOK)

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
					resource "cortexcloud_cloudsec_policy" "test" {
						name = "Switching Policy"
						rule_matching = {
							type = "ALL_RULES"
						}
						asset_matching = {
							type = "ALL_ASSETS"
						}
					}
				`, server.URL),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("cortexcloud_cloudsec_policy.test", "rule_matching.type", "ALL_RULES"),
				),
			},
			{
				Config: fmt.Sprintf(`
					provider "cortexcloud" {
						api_url    = "%s"
						api_key    = "test"
						api_key_id = 123
					}
					resource "cortexcloud_cloudsec_policy" "test" {
						name = "Switching Policy"
						rule_matching = {
							type  = "RULES"
							rules = ["rule-1", "rule-2"]
						}
						asset_matching = {
							type = "ALL_ASSETS"
						}
					}
				`, server.URL),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("cortexcloud_cloudsec_policy.test", "id", "policy-switch-222"),
					resource.TestCheckResourceAttr("cortexcloud_cloudsec_policy.test", "rule_matching.type", "RULES"),
					resource.TestCheckResourceAttr("cortexcloud_cloudsec_policy.test", "rule_matching.rules.0", "rule-1"),
					resource.TestCheckResourceAttr("cortexcloud_cloudsec_policy.test", "rule_matching.rules.1", "rule-2"),
				),
			},
		},
	})
}

func TestUnitCloudSecPolicyResource_ReadNotFound(t *testing.T) {
	var deleted bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		for strings.Contains(path, "//") {
			path = strings.ReplaceAll(path, "//", "/")
		}
		if strings.HasSuffix(path, "/") && path != "/" {
			path = strings.TrimSuffix(path, "/")
		}

		switch {
		case path == "/public_api/v1/policy" && r.Method == http.MethodPost:
			w.WriteHeader(http.StatusCreated)
			fmt.Fprintln(w, `{
				"data": {
					"id": "policy-404",
					"name": "Policy to be deleted",
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

		case path == "/public_api/v1/policy/policy-404" && r.Method == http.MethodGet:
			// Simulate policy not found after it was deleted externally
			if deleted {
				w.WriteHeader(http.StatusNotFound)
				// Return empty body - SDK will handle 404 status
			} else {
				// First GET returns the policy
				w.WriteHeader(http.StatusOK)
				fmt.Fprintln(w, `{
					"data": {
						"id": "policy-404",
						"name": "Policy to be deleted",
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
			}

		case path == "/public_api/v1/policy/policy-404" && r.Method == http.MethodDelete:
			// Mark as deleted so subsequent GETs return 404
			deleted = true
			w.WriteHeader(http.StatusOK)

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
					resource "cortexcloud_cloudsec_policy" "test" {
						name = "Policy to be deleted"
						rule_matching = {
							type = "ALL_RULES"
						}
						asset_matching = {
							type = "ALL_ASSETS"
						}
					}
				`, server.URL),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("cortexcloud_cloudsec_policy.test", "id", "policy-404"),
				),
			},
			{
				// Simulate external deletion by triggering a refresh
				// The mock will return 404 after the delete, causing the resource to be removed from state
				PreConfig: func() {
					deleted = true
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

func TestUnitCloudSecPolicyResource_ImportState(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		for strings.Contains(path, "//") {
			path = strings.ReplaceAll(path, "//", "/")
		}
		if strings.HasSuffix(path, "/") && path != "/" {
			path = strings.TrimSuffix(path, "/")
		}

		switch {
		case path == "/public_api/v1/policy" && r.Method == http.MethodPost:
			w.WriteHeader(http.StatusCreated)
			fmt.Fprintln(w, `{
				"data": {
					"id": "import-policy-id",
					"name": "Imported Policy",
					"description": "Policy imported from existing infrastructure",
					"labels": ["imported"],
					"rule_matching_type": "RULES",
					"associated_rule_ids": ["rule-a", "rule-b"],
					"asset_matching_type": "ASSET_GROUPS",
					"associated_asset_group_ids": [500],
					"enabled": true,
					"mode": "CUSTOM",
					"creation_time": 1678886400000,
					"created_by": "admin",
					"modification_time": 1678886400000,
					"modified_by": "admin"
				}
			}`)

		case path == "/public_api/v1/policy/import-policy-id" && r.Method == http.MethodGet:
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, `{
				"data": {
					"id": "import-policy-id",
					"name": "Imported Policy",
					"description": "Policy imported from existing infrastructure",
					"labels": ["imported"],
					"rule_matching_type": "RULES",
					"associated_rule_ids": ["rule-a", "rule-b"],
					"asset_matching_type": "ASSET_GROUPS",
					"associated_asset_group_ids": [500],
					"enabled": true,
					"mode": "CUSTOM",
					"creation_time": 1678886400000,
					"created_by": "admin",
					"modification_time": 1678886400000,
					"modified_by": "admin"
				}
			}`)

		case path == "/public_api/v1/policy/import-policy-id" && r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusOK)

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
					resource "cortexcloud_cloudsec_policy" "test" {
						name        = "Imported Policy"
						description = "Policy imported from existing infrastructure"
						labels      = ["imported"]
						rule_matching = {
							type  = "RULES"
							rules = ["rule-a", "rule-b"]
						}
						asset_matching = {
							type            = "ASSET_GROUPS"
							asset_group_ids = [500]
						}
					}
				`, server.URL),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("cortexcloud_cloudsec_policy.test", "id", "import-policy-id"),
					resource.TestCheckResourceAttr("cortexcloud_cloudsec_policy.test", "name", "Imported Policy"),
				),
			},
			{
				ResourceName:      "cortexcloud_cloudsec_policy.test",
				ImportState:       true,
				ImportStateVerify: true,
				// Ignore computed fields that may differ
				ImportStateVerifyIgnore: []string{"created_at", "created_by", "updated_at", "updated_by"},
			},
		},
	})
}
