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

func TestUnitCloudSecRulesDataSource_ReadAll(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		for strings.Contains(path, "//") {
			path = strings.ReplaceAll(path, "//", "/")
		}
		if strings.HasSuffix(path, "/") && path != "/" {
			path = strings.TrimSuffix(path, "/")
		}

		switch {
		case path == "/public_api/v1/rule/search" && r.Method == http.MethodPost:
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, `{
				"data": [
					{
						"id": "rule-id-1",
						"name": "S3 Bucket Public Access",
						"description": "Detects S3 buckets with public access",
						"rule_class": "config",
						"type": "DETECTION",
						"asset_types": ["aws-s3-bucket"],
						"severity": "high",
						"enabled": true,
						"system_default": false,
						"providers": ["aws"],
						"labels": ["security", "s3"],
						"created_by": "admin",
						"created_on": 1678886400000,
						"last_modified_by": "admin",
						"last_modified_on": 1678886400000,
						"module": "cspm"
					},
					{
						"id": "rule-id-2",
						"name": "Azure Storage Encryption",
						"description": "Checks Azure storage encryption",
						"rule_class": "config",
						"type": "DETECTION",
						"asset_types": ["azure-storage-account"],
						"severity": "critical",
						"enabled": true,
						"system_default": true,
						"providers": ["azure"],
						"labels": ["encryption"],
						"created_by": "system",
						"created_on": 1678800000000,
						"last_modified_by": "system",
						"last_modified_on": 1678800000000,
						"module": "cspm"
					}
				],
				"metadata": {
					"filter_count": 2,
					"total_count": 100
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
					data "cortexcloud_cloudsec_rules" "all" {
					}
				`, server.URL),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("data.cortexcloud_cloudsec_rules.all", "id", "cloudsec_rules"),
					resource.TestCheckResourceAttr("data.cortexcloud_cloudsec_rules.all", "total_count", "100"),
					resource.TestCheckResourceAttr("data.cortexcloud_cloudsec_rules.all", "filter_count", "2"),
					resource.TestCheckResourceAttr("data.cortexcloud_cloudsec_rules.all", "rules.#", "2"),
					// First rule
					resource.TestCheckResourceAttr("data.cortexcloud_cloudsec_rules.all", "rules.0.id", "rule-id-1"),
					resource.TestCheckResourceAttr("data.cortexcloud_cloudsec_rules.all", "rules.0.name", "S3 Bucket Public Access"),
					resource.TestCheckResourceAttr("data.cortexcloud_cloudsec_rules.all", "rules.0.severity", "high"),
					resource.TestCheckResourceAttr("data.cortexcloud_cloudsec_rules.all", "rules.0.enabled", "true"),
					resource.TestCheckResourceAttr("data.cortexcloud_cloudsec_rules.all", "rules.0.system_default", "false"),
					resource.TestCheckResourceAttr("data.cortexcloud_cloudsec_rules.all", "rules.0.providers.0", "aws"),
					resource.TestCheckResourceAttr("data.cortexcloud_cloudsec_rules.all", "rules.0.labels.0", "security"),
					resource.TestCheckResourceAttr("data.cortexcloud_cloudsec_rules.all", "rules.0.labels.1", "s3"),
					resource.TestCheckResourceAttr("data.cortexcloud_cloudsec_rules.all", "rules.0.module", "cspm"),
					// Second rule
					resource.TestCheckResourceAttr("data.cortexcloud_cloudsec_rules.all", "rules.1.id", "rule-id-2"),
					resource.TestCheckResourceAttr("data.cortexcloud_cloudsec_rules.all", "rules.1.name", "Azure Storage Encryption"),
					resource.TestCheckResourceAttr("data.cortexcloud_cloudsec_rules.all", "rules.1.severity", "critical"),
					resource.TestCheckResourceAttr("data.cortexcloud_cloudsec_rules.all", "rules.1.system_default", "true"),
					resource.TestCheckResourceAttr("data.cortexcloud_cloudsec_rules.all", "rules.1.providers.0", "azure"),
				),
			},
		},
	})
}

func TestUnitCloudSecRulesDataSource_ReadWithFilter(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		for strings.Contains(path, "//") {
			path = strings.ReplaceAll(path, "//", "/")
		}
		if strings.HasSuffix(path, "/") && path != "/" {
			path = strings.TrimSuffix(path, "/")
		}

		switch {
		case path == "/public_api/v1/rule/search" && r.Method == http.MethodPost:
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, `{
				"data": [
					{
						"id": "rule-critical-1",
						"name": "Critical Security Rule",
						"description": "A critical severity rule",
						"rule_class": "config",
						"type": "DETECTION",
						"asset_types": ["aws-ec2-instance"],
						"severity": "critical",
						"enabled": true,
						"system_default": false,
						"providers": ["aws"],
						"compliance_metadata": [
							{
								"control_id": "CIS-1.1",
								"standard_id": "CIS",
								"standard_name": "CIS Benchmark",
								"control_name": "Root Account Usage"
							}
						],
						"labels": ["critical"],
						"created_by": "admin",
						"created_on": 1678886400000,
						"last_modified_by": "admin",
						"last_modified_on": 1678886400000,
						"module": "cspm"
					}
				],
				"metadata": {
					"filter_count": 1,
					"total_count": 100
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
					data "cortexcloud_cloudsec_rules" "critical" {
						filter {
							field = "severity"
							type  = "EQ"
							value = "critical"
						}
					}
				`, server.URL),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("data.cortexcloud_cloudsec_rules.critical", "id", "cloudsec_rules"),
					resource.TestCheckResourceAttr("data.cortexcloud_cloudsec_rules.critical", "total_count", "100"),
					resource.TestCheckResourceAttr("data.cortexcloud_cloudsec_rules.critical", "filter_count", "1"),
					resource.TestCheckResourceAttr("data.cortexcloud_cloudsec_rules.critical", "rules.#", "1"),
					resource.TestCheckResourceAttr("data.cortexcloud_cloudsec_rules.critical", "rules.0.id", "rule-critical-1"),
					resource.TestCheckResourceAttr("data.cortexcloud_cloudsec_rules.critical", "rules.0.name", "Critical Security Rule"),
					resource.TestCheckResourceAttr("data.cortexcloud_cloudsec_rules.critical", "rules.0.severity", "critical"),
					resource.TestCheckResourceAttr("data.cortexcloud_cloudsec_rules.critical", "rules.0.compliance_metadata.0.control_id", "CIS-1.1"),
					resource.TestCheckResourceAttr("data.cortexcloud_cloudsec_rules.critical", "rules.0.compliance_metadata.0.standard_name", "CIS Benchmark"),
				),
			},
		},
	})
}

func TestUnitCloudSecRulesDataSource_ReadWithPagination(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		for strings.Contains(path, "//") {
			path = strings.ReplaceAll(path, "//", "/")
		}
		if strings.HasSuffix(path, "/") && path != "/" {
			path = strings.TrimSuffix(path, "/")
		}

		switch {
		case path == "/public_api/v1/rule/search" && r.Method == http.MethodPost:
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, `{
				"data": [
					{
						"id": "rule-page-1",
						"name": "Paginated Rule",
						"description": "First rule in page",
						"rule_class": "config",
						"type": "DETECTION",
						"asset_types": ["gcp-compute-instance"],
						"severity": "medium",
						"enabled": true,
						"system_default": false,
						"providers": ["gcp"],
						"labels": [],
						"created_by": "admin",
						"created_on": 1678886400000,
						"last_modified_by": "admin",
						"last_modified_on": 1678886400000,
						"module": "cspm"
					}
				],
				"metadata": {
					"filter_count": 50,
					"total_count": 50
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
					data "cortexcloud_cloudsec_rules" "paginated" {
						search_from = 0
						search_to   = 10
					}
				`, server.URL),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("data.cortexcloud_cloudsec_rules.paginated", "id", "cloudsec_rules"),
					resource.TestCheckResourceAttr("data.cortexcloud_cloudsec_rules.paginated", "rules.#", "1"),
					resource.TestCheckResourceAttr("data.cortexcloud_cloudsec_rules.paginated", "rules.0.id", "rule-page-1"),
					resource.TestCheckResourceAttr("data.cortexcloud_cloudsec_rules.paginated", "rules.0.severity", "medium"),
					resource.TestCheckResourceAttr("data.cortexcloud_cloudsec_rules.paginated", "rules.0.providers.0", "gcp"),
				),
			},
		},
	})
}

func TestUnitCloudSecRulesDataSource_EmptyResult(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		for strings.Contains(path, "//") {
			path = strings.ReplaceAll(path, "//", "/")
		}
		if strings.HasSuffix(path, "/") && path != "/" {
			path = strings.TrimSuffix(path, "/")
		}

		switch {
		case path == "/public_api/v1/rule/search" && r.Method == http.MethodPost:
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, `{
				"data": [],
				"metadata": {
					"filter_count": 0,
					"total_count": 100
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
					data "cortexcloud_cloudsec_rules" "empty" {
						filter {
							field = "severity"
							type  = "EQ"
							value = "nonexistent"
						}
					}
				`, server.URL),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("data.cortexcloud_cloudsec_rules.empty", "id", "cloudsec_rules"),
					resource.TestCheckResourceAttr("data.cortexcloud_cloudsec_rules.empty", "total_count", "100"),
					resource.TestCheckResourceAttr("data.cortexcloud_cloudsec_rules.empty", "filter_count", "0"),
					resource.TestCheckResourceAttr("data.cortexcloud_cloudsec_rules.empty", "rules.#", "0"),
				),
			},
		},
	})
}
