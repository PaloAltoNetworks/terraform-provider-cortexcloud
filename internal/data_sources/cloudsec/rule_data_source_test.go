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

func TestUnitCloudSecRuleDataSource_Read(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		for strings.Contains(path, "//") {
			path = strings.ReplaceAll(path, "//", "/")
		}
		if strings.HasSuffix(path, "/") && path != "/" {
			path = strings.TrimSuffix(path, "/")
		}

		switch {
		case path == "/public_api/v1/policy/test-rule-id-123" && r.Method == http.MethodGet:
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, `{
				"data": {
					"id": "test-rule-id-123",
					"name": "Test S3 Bucket Rule",
					"description": "Test rule for S3 buckets",
					"class": "config",
					"type": "DETECTION",
					"asset_types": ["aws-s3-bucket"],
					"severity": "high",
					"query": {
						"xql": "config from cloud.resource where cloud.type = 'aws' AND api.name = 's3api.get_bucket_acl'"
					},
					"enabled": true,
					"providers": ["aws"],
					"system_default": false,
					"created_by": "test-user",
					"created_on": 1678886400000,
					"last_modified_by": "test-user",
					"last_modified_on": 1678886400000,
					"deleted": false,
					"deleted_at": 0,
					"deleted_by": ""
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
					data "cortexcloud_cloudsec_rule" "test" {
						id = "test-rule-id-123"
					}
				`, server.URL),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("data.cortexcloud_cloudsec_rule.test", "id", "test-rule-id-123"),
					resource.TestCheckResourceAttr("data.cortexcloud_cloudsec_rule.test", "name", "Test S3 Bucket Rule"),
					resource.TestCheckResourceAttr("data.cortexcloud_cloudsec_rule.test", "description", "Test rule for S3 buckets"),
					resource.TestCheckResourceAttr("data.cortexcloud_cloudsec_rule.test", "class", "config"),
					resource.TestCheckResourceAttr("data.cortexcloud_cloudsec_rule.test", "type", "DETECTION"),
					resource.TestCheckResourceAttr("data.cortexcloud_cloudsec_rule.test", "severity", "high"),
					resource.TestCheckResourceAttr("data.cortexcloud_cloudsec_rule.test", "query.xql", "config from cloud.resource where cloud.type = 'aws' AND api.name = 's3api.get_bucket_acl'"),
					resource.TestCheckResourceAttr("data.cortexcloud_cloudsec_rule.test", "enabled", "true"),
					resource.TestCheckResourceAttr("data.cortexcloud_cloudsec_rule.test", "system_default", "false"),
					resource.TestCheckResourceAttr("data.cortexcloud_cloudsec_rule.test", "asset_types.0", "aws-s3-bucket"),
					resource.TestCheckResourceAttr("data.cortexcloud_cloudsec_rule.test", "providers.0", "aws"),
					resource.TestCheckResourceAttr("data.cortexcloud_cloudsec_rule.test", "created_by", "test-user"),
					resource.TestCheckResourceAttr("data.cortexcloud_cloudsec_rule.test", "created_on", "1678886400000"),
					resource.TestCheckResourceAttr("data.cortexcloud_cloudsec_rule.test", "last_modified_by", "test-user"),
					resource.TestCheckResourceAttr("data.cortexcloud_cloudsec_rule.test", "last_modified_on", "1678886400000"),
					resource.TestCheckResourceAttr("data.cortexcloud_cloudsec_rule.test", "deleted", "false"),
				),
			},
		},
	})
}

func TestUnitCloudSecRuleDataSource_ReadWithCompliance(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		for strings.Contains(path, "//") {
			path = strings.ReplaceAll(path, "//", "/")
		}
		if strings.HasSuffix(path, "/") && path != "/" {
			path = strings.TrimSuffix(path, "/")
		}

		switch {
		case path == "/public_api/v1/policy/test-rule-id-456" && r.Method == http.MethodGet:
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, `{
				"data": {
					"id": "test-rule-id-456",
					"name": "CIS Compliance Rule",
					"description": "Rule with compliance metadata",
					"class": "config",
					"type": "DETECTION",
					"asset_types": ["aws-s3-bucket"],
					"severity": "critical",
					"query": {
						"xql": "config from cloud.resource where cloud.type = 'aws'"
					},
					"metadata": {
						"issue": {
							"recommendation": "Enable encryption at rest"
						}
					},
					"compliance_metadata": [
						{
							"control_id": "CIS-AWS-2.1.5",
							"standard_id": "CIS-AWS",
							"standard_name": "CIS Amazon Web Services Foundations Benchmark",
							"control_name": "Ensure S3 bucket encryption is enabled"
						},
						{
							"control_id": "NIST-800-53-SC-28",
							"standard_id": "NIST-800-53",
							"standard_name": "NIST Special Publication 800-53",
							"control_name": "Protection of Information at Rest"
						}
					],
					"labels": ["security", "encryption", "compliance"],
					"enabled": true,
					"providers": ["aws"],
					"system_default": false,
					"created_by": "test-user",
					"created_on": 1678886400000,
					"last_modified_by": "test-user",
					"last_modified_on": 1678886400000,
					"deleted": false,
					"deleted_at": 0,
					"deleted_by": ""
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
					data "cortexcloud_cloudsec_rule" "test" {
						id = "test-rule-id-456"
					}
				`, server.URL),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("data.cortexcloud_cloudsec_rule.test", "id", "test-rule-id-456"),
					resource.TestCheckResourceAttr("data.cortexcloud_cloudsec_rule.test", "name", "CIS Compliance Rule"),
					resource.TestCheckResourceAttr("data.cortexcloud_cloudsec_rule.test", "description", "Rule with compliance metadata"),
					resource.TestCheckResourceAttr("data.cortexcloud_cloudsec_rule.test", "severity", "critical"),
					resource.TestCheckResourceAttr("data.cortexcloud_cloudsec_rule.test", "metadata.issue.recommendation", "Enable encryption at rest"),
					resource.TestCheckResourceAttr("data.cortexcloud_cloudsec_rule.test", "compliance_metadata.0.control_id", "CIS-AWS-2.1.5"),
					resource.TestCheckResourceAttr("data.cortexcloud_cloudsec_rule.test", "compliance_metadata.0.standard_id", "CIS-AWS"),
					resource.TestCheckResourceAttr("data.cortexcloud_cloudsec_rule.test", "compliance_metadata.0.standard_name", "CIS Amazon Web Services Foundations Benchmark"),
					resource.TestCheckResourceAttr("data.cortexcloud_cloudsec_rule.test", "compliance_metadata.0.control_name", "Ensure S3 bucket encryption is enabled"),
					resource.TestCheckResourceAttr("data.cortexcloud_cloudsec_rule.test", "compliance_metadata.1.control_id", "NIST-800-53-SC-28"),
					resource.TestCheckResourceAttr("data.cortexcloud_cloudsec_rule.test", "compliance_metadata.1.standard_id", "NIST-800-53"),
					resource.TestCheckResourceAttr("data.cortexcloud_cloudsec_rule.test", "compliance_metadata.1.standard_name", "NIST Special Publication 800-53"),
					resource.TestCheckResourceAttr("data.cortexcloud_cloudsec_rule.test", "compliance_metadata.1.control_name", "Protection of Information at Rest"),
					resource.TestCheckResourceAttr("data.cortexcloud_cloudsec_rule.test", "labels.#", "3"),
					resource.TestCheckTypeSetElemAttr("data.cortexcloud_cloudsec_rule.test", "labels.*", "security"),
					resource.TestCheckTypeSetElemAttr("data.cortexcloud_cloudsec_rule.test", "labels.*", "encryption"),
					resource.TestCheckTypeSetElemAttr("data.cortexcloud_cloudsec_rule.test", "labels.*", "compliance"),
				),
			},
		},
	})
}

func TestUnitCloudSecRuleDataSource_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		for strings.Contains(path, "//") {
			path = strings.ReplaceAll(path, "//", "/")
		}
		if strings.HasSuffix(path, "/") && path != "/" {
			path = strings.TrimSuffix(path, "/")
		}

		switch {
		case path == "/public_api/v1/policy/non-existent-rule-id" && r.Method == http.MethodGet:
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprintln(w, `{
				"error": "Rule not found"
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
					data "cortexcloud_cloudsec_rule" "test" {
						id = "non-existent-rule-id"
					}
				`, server.URL),
				ExpectError: regexp.MustCompile("Error Reading CloudSec Rule|Could not read rule"),
			},
		},
	})
}
