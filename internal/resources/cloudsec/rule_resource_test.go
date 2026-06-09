// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package cloudsec_test

import (
	"encoding/json"
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

func TestUnitCloudSecRuleResource_Create(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		for strings.Contains(path, "//") {
			path = strings.ReplaceAll(path, "//", "/")
		}
		if strings.HasSuffix(path, "/") && path != "/" {
			path = strings.TrimSuffix(path, "/")
		}

		switch {
		case path == "/public_api/v1/rule" && r.Method == http.MethodPost:
			w.WriteHeader(http.StatusCreated)
			fmt.Fprintln(w, `{
				"id": "test-rule-id-123",
				"name": "Test S3 Bucket Rule",
				"description": "Test rule for S3 buckets",
				"rule_class": "config",
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
			}`)

		case path == "/public_api/v1/rule/test-rule-id-123" && r.Method == http.MethodGet:
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, `{
				"id": "test-rule-id-123",
				"name": "Test S3 Bucket Rule",
				"description": "Test rule for S3 buckets",
				"rule_class": "config",
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
			}`)

		case path == "/public_api/v1/rule/test-rule-id-123" && r.Method == http.MethodDelete:
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
					resource "cortexcloud_cloudsec_rule" "test" {
						name        = "Test S3 Bucket Rule"
						description = "Test rule for S3 buckets"
						class       = "config"
						type        = "DETECTION"
						asset_types = ["aws-s3-bucket"]
						severity    = "high"
						query = {
							xql = "config from cloud.resource where cloud.type = 'aws' AND api.name = 's3api.get_bucket_acl'"
						}
						enabled = true
					}
				`, server.URL),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("cortexcloud_cloudsec_rule.test", "id", "test-rule-id-123"),
					resource.TestCheckResourceAttr("cortexcloud_cloudsec_rule.test", "name", "Test S3 Bucket Rule"),
					resource.TestCheckResourceAttr("cortexcloud_cloudsec_rule.test", "description", "Test rule for S3 buckets"),
					resource.TestCheckResourceAttr("cortexcloud_cloudsec_rule.test", "class", "config"),
					resource.TestCheckResourceAttr("cortexcloud_cloudsec_rule.test", "type", "DETECTION"),
					resource.TestCheckResourceAttr("cortexcloud_cloudsec_rule.test", "severity", "high"),
					resource.TestCheckResourceAttr("cortexcloud_cloudsec_rule.test", "enabled", "true"),
					resource.TestCheckResourceAttr("cortexcloud_cloudsec_rule.test", "system_default", "false"),
				),
			},
		},
	})
}

func TestUnitCloudSecRuleResource_CreateWithCompliance(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		for strings.Contains(path, "//") {
			path = strings.ReplaceAll(path, "//", "/")
		}
		if strings.HasSuffix(path, "/") && path != "/" {
			path = strings.TrimSuffix(path, "/")
		}

		switch {
		case path == "/public_api/v1/rule" && r.Method == http.MethodPost:
			w.WriteHeader(http.StatusCreated)
			fmt.Fprintln(w, `{
				"id": "test-rule-id-456",
				"name": "CIS Compliance Rule",
				"description": "Rule with compliance metadata",
				"rule_class": "config",
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
					}
				],
				"labels": ["security", "encryption"],
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
			}`)

		case path == "/public_api/v1/rule/test-rule-id-456" && r.Method == http.MethodGet:
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, `{
				"id": "test-rule-id-456",
				"name": "CIS Compliance Rule",
				"description": "Rule with compliance metadata",
				"rule_class": "config",
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
					}
				],
				"labels": ["security", "encryption"],
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
			}`)

		case path == "/public_api/v1/rule/test-rule-id-456" && r.Method == http.MethodDelete:
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
					resource "cortexcloud_cloudsec_rule" "test" {
						name        = "CIS Compliance Rule"
						description = "Rule with compliance metadata"
						class       = "config"
						type        = "DETECTION"
						asset_types = ["aws-s3-bucket"]
						severity    = "critical"
						query = {
							xql = "config from cloud.resource where cloud.type = 'aws'"
						}
						metadata = {
							issue = {
								recommendation = "Enable encryption at rest"
							}
						}
						compliance_metadata = [
							{
								control_id = "CIS-AWS-2.1.5"
							}
						]
						labels  = ["security", "encryption"]
						enabled = true
					}
				`, server.URL),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("cortexcloud_cloudsec_rule.test", "id", "test-rule-id-456"),
					resource.TestCheckResourceAttr("cortexcloud_cloudsec_rule.test", "name", "CIS Compliance Rule"),
					resource.TestCheckResourceAttr("cortexcloud_cloudsec_rule.test", "severity", "critical"),
					resource.TestCheckResourceAttr("cortexcloud_cloudsec_rule.test", "metadata.issue.recommendation", "Enable encryption at rest"),
					resource.TestCheckResourceAttr("cortexcloud_cloudsec_rule.test", "compliance_metadata.0.control_id", "CIS-AWS-2.1.5"),
					resource.TestCheckResourceAttr("cortexcloud_cloudsec_rule.test", "compliance_metadata.0.standard_id", "CIS-AWS"),
					resource.TestCheckResourceAttr("cortexcloud_cloudsec_rule.test", "labels.0", "encryption"),
					resource.TestCheckResourceAttr("cortexcloud_cloudsec_rule.test", "labels.1", "security"),
				),
			},
		},
	})
}

func TestUnitCloudSecRuleResource_Update(t *testing.T) {
	updated := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		for strings.Contains(path, "//") {
			path = strings.ReplaceAll(path, "//", "/")
		}
		if strings.HasSuffix(path, "/") && path != "/" {
			path = strings.TrimSuffix(path, "/")
		}

		switch {
		case path == "/public_api/v1/rule" && r.Method == http.MethodPost:
			w.WriteHeader(http.StatusCreated)
			fmt.Fprintln(w, `{
				"id": "test-rule-id-789",
				"name": "Original Rule Name",
				"description": "Original description",
				"rule_class": "config",
				"type": "DETECTION",
				"asset_types": ["aws-s3-bucket"],
				"severity": "medium",
				"query": {
					"xql": "config from cloud.resource where cloud.type = 'aws'"
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
			}`)

		case path == "/public_api/v1/rule/test-rule-id-789" && r.Method == http.MethodGet:
			w.WriteHeader(http.StatusOK)
			if updated {
				fmt.Fprintln(w, `{
					"id": "test-rule-id-789",
					"name": "Updated Rule Name",
					"description": "Updated description",
					"rule_class": "config",
					"type": "DETECTION",
					"asset_types": ["aws-s3-bucket"],
					"severity": "high",
					"query": {
						"xql": "config from cloud.resource where cloud.type = 'aws' AND api.name = 's3api.get_bucket_acl'"
					},
					"enabled": false,
					"providers": ["aws"],
					"system_default": false,
					"created_by": "test-user",
					"created_on": 1678886400000,
					"last_modified_by": "test-user",
					"last_modified_on": 1678886500000,
					"deleted": false,
					"deleted_at": 0,
					"deleted_by": ""
				}`)
			} else {
				fmt.Fprintln(w, `{
					"id": "test-rule-id-789",
					"name": "Original Rule Name",
					"description": "Original description",
					"rule_class": "config",
					"type": "DETECTION",
					"asset_types": ["aws-s3-bucket"],
					"severity": "medium",
					"query": {
						"xql": "config from cloud.resource where cloud.type = 'aws'"
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
				}`)
			}

		case path == "/public_api/v1/rule/test-rule-id-789" && r.Method == http.MethodPatch:
			updated = true
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, `{
				"id": "test-rule-id-789",
				"name": "Updated Rule Name",
				"description": "Updated description",
				"rule_class": "config",
				"type": "DETECTION",
				"asset_types": ["aws-s3-bucket"],
				"severity": "high",
				"query": {
					"xql": "config from cloud.resource where cloud.type = 'aws' AND api.name = 's3api.get_bucket_acl'"
				},
				"enabled": false,
				"providers": ["aws"],
				"system_default": false,
				"created_by": "test-user",
				"created_on": 1678886400000,
				"last_modified_by": "test-user",
				"last_modified_on": 1678886500000,
				"deleted": false,
				"deleted_at": 0,
				"deleted_by": ""
			}`)

		case path == "/public_api/v1/rule/test-rule-id-789" && r.Method == http.MethodDelete:
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
					resource "cortexcloud_cloudsec_rule" "test" {
						name        = "Original Rule Name"
						description = "Original description"
						class       = "config"
						asset_types = ["aws-s3-bucket"]
						severity    = "medium"
						query = {
							xql = "config from cloud.resource where cloud.type = 'aws'"
						}
					}
				`, server.URL),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("cortexcloud_cloudsec_rule.test", "name", "Original Rule Name"),
					resource.TestCheckResourceAttr("cortexcloud_cloudsec_rule.test", "severity", "medium"),
				),
			},
			{
				Config: fmt.Sprintf(`
					provider "cortexcloud" {
						api_url    = "%s"
						api_key    = "test"
						api_key_id = 123
					}
					resource "cortexcloud_cloudsec_rule" "test" {
						name        = "Updated Rule Name"
						description = "Updated description"
						class       = "config"
						asset_types = ["aws-s3-bucket"]
						severity    = "high"
						query = {
							xql = "config from cloud.resource where cloud.type = 'aws' AND api.name = 's3api.get_bucket_acl'"
						}
						enabled = false
					}
				`, server.URL),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("cortexcloud_cloudsec_rule.test", "id", "test-rule-id-789"),
					resource.TestCheckResourceAttr("cortexcloud_cloudsec_rule.test", "name", "Updated Rule Name"),
					resource.TestCheckResourceAttr("cortexcloud_cloudsec_rule.test", "description", "Updated description"),
					resource.TestCheckResourceAttr("cortexcloud_cloudsec_rule.test", "severity", "high"),
					resource.TestCheckResourceAttr("cortexcloud_cloudsec_rule.test", "enabled", "false"),
				),
			},
		},
	})
}

func TestUnitCloudSecRuleResource_ReadNotFound(t *testing.T) {
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
		case path == "/public_api/v1/rule" && r.Method == http.MethodPost:
			w.WriteHeader(http.StatusCreated)
			fmt.Fprintln(w, `{
				"id": "test-rule-id-404",
				"name": "Rule to be deleted",
				"description": "This rule will be deleted externally",
				"rule_class": "config",
				"type": "DETECTION",
				"asset_types": ["aws-s3-bucket"],
				"severity": "low",
				"query": {
					"xql": "config from cloud.resource where cloud.type = 'aws'"
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
			}`)

		case path == "/public_api/v1/rule/test-rule-id-404" && r.Method == http.MethodGet:
			// Simulate rule not found after it was deleted externally
			if deleted {
				w.WriteHeader(http.StatusNotFound)
				// Return empty body - SDK will handle 404 status
			} else {
				// First GET returns the rule
				w.WriteHeader(http.StatusOK)
				fmt.Fprintln(w, `{
					"id": "test-rule-id-404",
					"name": "Rule to be deleted",
					"description": "This rule will be deleted externally",
					"rule_class": "config",
					"type": "DETECTION",
					"asset_types": ["aws-s3-bucket"],
					"severity": "low",
					"query": {
						"xql": "config from cloud.resource where cloud.type = 'aws'"
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
				}`)
			}

		case path == "/public_api/v1/rule/test-rule-id-404" && r.Method == http.MethodDelete:
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
					resource "cortexcloud_cloudsec_rule" "test" {
						name        = "Rule to be deleted"
						description = "This rule will be deleted externally"
						class       = "config"
						asset_types = ["aws-s3-bucket"]
						severity    = "low"
						query = {
							xql = "config from cloud.resource where cloud.type = 'aws'"
						}
					}
				`, server.URL),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("cortexcloud_cloudsec_rule.test", "id", "test-rule-id-404"),
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

func TestUnitCloudSecRuleResource_ImportState(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		for strings.Contains(path, "//") {
			path = strings.ReplaceAll(path, "//", "/")
		}
		if strings.HasSuffix(path, "/") && path != "/" {
			path = strings.TrimSuffix(path, "/")
		}

		switch {
		case path == "/public_api/v1/rule" && r.Method == http.MethodPost:
			w.WriteHeader(http.StatusCreated)
			fmt.Fprintln(w, `{
				"id": "import-test-id",
				"name": "Imported Rule",
				"description": "Rule imported from existing infrastructure",
				"rule_class": "config",
				"type": "DETECTION",
				"asset_types": ["aws-ec2-instance"],
				"severity": "medium",
				"query": {
					"xql": "config from cloud.resource where cloud.type = 'aws'"
				},
				"enabled": true,
				"providers": ["aws"],
				"system_default": false,
				"created_by": "admin",
				"created_on": 1678886400000,
				"last_modified_by": "admin",
				"last_modified_on": 1678886400000,
				"deleted": false,
				"deleted_at": 0,
				"deleted_by": ""
			}`)

		case path == "/public_api/v1/rule/import-test-id" && r.Method == http.MethodGet:
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, `{
				"id": "import-test-id",
				"name": "Imported Rule",
				"description": "Rule imported from existing infrastructure",
				"rule_class": "config",
				"type": "DETECTION",
				"asset_types": ["aws-ec2-instance"],
				"severity": "medium",
				"query": {
					"xql": "config from cloud.resource where cloud.type = 'aws'"
				},
				"enabled": true,
				"providers": ["aws"],
				"system_default": false,
				"created_by": "admin",
				"created_on": 1678886400000,
				"last_modified_by": "admin",
				"last_modified_on": 1678886400000,
				"deleted": false,
				"deleted_at": 0,
				"deleted_by": ""
			}`)

		case path == "/public_api/v1/rule/import-test-id" && r.Method == http.MethodDelete:
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
					resource "cortexcloud_cloudsec_rule" "test" {
						name        = "Imported Rule"
						description = "Rule imported from existing infrastructure"
						class       = "config"
						asset_types = ["aws-ec2-instance"]
						severity    = "medium"
						query = {
							xql = "config from cloud.resource where cloud.type = 'aws'"
						}
					}
				`, server.URL),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("cortexcloud_cloudsec_rule.test", "id", "import-test-id"),
					resource.TestCheckResourceAttr("cortexcloud_cloudsec_rule.test", "name", "Imported Rule"),
				),
			},
			{
				ResourceName:      "cortexcloud_cloudsec_rule.test",
				ImportState:       true,
				ImportStateVerify: true,
				// Ignore computed fields that may differ
				ImportStateVerifyIgnore: []string{"created_on", "created_by", "last_modified_on", "last_modified_by"},
			},
		},
	})
}

// TestUnitCloudSecRuleResource_CreateWithoutMetadata verifies that creating a rule
// without specifying metadata does NOT cause "Provider produced inconsistent result
// after apply" when the API auto-populates metadata.issue with category and
// empty recommendation.
func TestUnitCloudSecRuleResource_CreateWithoutMetadata(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		for strings.Contains(path, "//") {
			path = strings.ReplaceAll(path, "//", "/")
		}
		if strings.HasSuffix(path, "/") && path != "/" {
			path = strings.TrimSuffix(path, "/")
		}

		// Response includes metadata with auto-populated issue/recommendation
		// even though the Terraform config does NOT specify metadata.
		// Without Computed: true on metadata, this causes:
		//   "Provider produced inconsistent result after apply"
		ruleResponse := `{
			"id": "test-rule-no-metadata",
			"name": "Rule Without Metadata",
			"description": "Rule created without metadata in config",
			"rule_class": "config",
			"type": "DETECTION",
			"asset_types": ["aws-s3-bucket"],
			"severity": "high",
			"query": {
				"xql": "config from cloud.resource where cloud.type = 'aws'"
			},
			"metadata": {
				"issue": {
					"recommendation": ""
				}
			},
			"compliance_metadata": [],
			"labels": [],
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
		}`

		switch {
		case path == "/public_api/v1/rule" && r.Method == http.MethodPost:
			w.WriteHeader(http.StatusCreated)
			fmt.Fprintln(w, ruleResponse)

		case path == "/public_api/v1/rule/test-rule-no-metadata" && r.Method == http.MethodGet:
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, ruleResponse)

		case path == "/public_api/v1/rule/test-rule-no-metadata" && r.Method == http.MethodDelete:
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
				// Config does NOT include metadata - this is the bug scenario
				Config: fmt.Sprintf(`
					provider "cortexcloud" {
						api_url    = "%s"
						api_key    = "test"
						api_key_id = 123
					}
					resource "cortexcloud_cloudsec_rule" "test" {
						name        = "Rule Without Metadata"
						description = "Rule created without metadata in config"
						class       = "config"
						asset_types = ["aws-s3-bucket"]
						severity    = "high"
						query = {
							xql = "config from cloud.resource where cloud.type = 'aws'"
						}
						enabled = true
					}
				`, server.URL),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("cortexcloud_cloudsec_rule.test", "id", "test-rule-no-metadata"),
					resource.TestCheckResourceAttr("cortexcloud_cloudsec_rule.test", "name", "Rule Without Metadata"),
					// Verify metadata was auto-populated by the API
					resource.TestCheckResourceAttr("cortexcloud_cloudsec_rule.test", "metadata.issue.recommendation", ""),
				),
			},
		},
	})
}

// TestUnitCloudSecRuleResource_MetadataNullOnRefresh verifies that when the API
// returns metadata with empty recommendation on CREATE but null metadata on GET
// (refresh), no drift is detected. This is the regression scenario reported on
// JP stack where metadata goes from {issue={recommendation=""}} to null.
func TestUnitCloudSecRuleResource_MetadataNullOnRefresh(t *testing.T) {
	getCallCount := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		for strings.Contains(path, "//") {
			path = strings.ReplaceAll(path, "//", "/")
		}
		if strings.HasSuffix(path, "/") && path != "/" {
			path = strings.TrimSuffix(path, "/")
		}

		// CREATE response includes metadata with empty recommendation
		createResponse := `{
			"id": "test-rule-metadata-drift",
			"name": "Rule Metadata Drift Test",
			"description": "Tests metadata null on refresh",
			"rule_class": "config",
			"type": "DETECTION",
			"asset_types": ["aws-s3-bucket"],
			"severity": "high",
			"query": {
				"xql": "config from cloud.resource where cloud.type = 'aws'"
			},
			"metadata": {
				"issue": {
					"recommendation": ""
				}
			},
			"compliance_metadata": [],
			"labels": [],
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
		}`

		// GET response returns null metadata (the regression scenario)
		getResponse := `{
			"id": "test-rule-metadata-drift",
			"name": "Rule Metadata Drift Test",
			"description": "Tests metadata null on refresh",
			"rule_class": "config",
			"type": "DETECTION",
			"asset_types": ["aws-s3-bucket"],
			"severity": "high",
			"query": {
				"xql": "config from cloud.resource where cloud.type = 'aws'"
			},
			"metadata": null,
			"compliance_metadata": [],
			"labels": [],
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
		}`

		switch {
		case path == "/public_api/v1/rule" && r.Method == http.MethodPost:
			w.WriteHeader(http.StatusCreated)
			fmt.Fprintln(w, createResponse)

		case path == "/public_api/v1/rule/test-rule-metadata-drift" && r.Method == http.MethodGet:
			getCallCount++
			w.WriteHeader(http.StatusOK)
			if getCallCount <= 1 {
				// First GET (after create) returns metadata
				fmt.Fprintln(w, createResponse)
			} else {
				// Subsequent GETs return null metadata (simulates the drift)
				fmt.Fprintln(w, getResponse)
			}

		case path == "/public_api/v1/rule/test-rule-metadata-drift" && r.Method == http.MethodDelete:
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
				// Step 1: Create the rule — API returns metadata with empty recommendation
				Config: fmt.Sprintf(`
					provider "cortexcloud" {
						api_url    = "%s"
						api_key    = "test"
						api_key_id = 123
					}
					resource "cortexcloud_cloudsec_rule" "test" {
						name        = "Rule Metadata Drift Test"
						description = "Tests metadata null on refresh"
						class       = "config"
						asset_types = ["aws-s3-bucket"]
						severity    = "high"
						query = {
							xql = "config from cloud.resource where cloud.type = 'aws'"
						}
						enabled = true
					}
				`, server.URL),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("cortexcloud_cloudsec_rule.test", "id", "test-rule-metadata-drift"),
					resource.TestCheckResourceAttr("cortexcloud_cloudsec_rule.test", "metadata.issue.recommendation", ""),
				),
			},
			{
				// Step 2: Re-apply the same config — the GET now returns null metadata.
				// Without the fix, this would fail with:
				//   "Objects have changed outside of Terraform"
				//   metadata: {issue={recommendation=""}} → null
				Config: fmt.Sprintf(`
					provider "cortexcloud" {
						api_url    = "%s"
						api_key    = "test"
						api_key_id = 123
					}
					resource "cortexcloud_cloudsec_rule" "test" {
						name        = "Rule Metadata Drift Test"
						description = "Tests metadata null on refresh"
						class       = "config"
						asset_types = ["aws-s3-bucket"]
						severity    = "high"
						query = {
							xql = "config from cloud.resource where cloud.type = 'aws'"
						}
						enabled = true
					}
				`, server.URL),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("cortexcloud_cloudsec_rule.test", "id", "test-rule-metadata-drift"),
					// Metadata should still be populated (empty recommendation), not null
					resource.TestCheckResourceAttr("cortexcloud_cloudsec_rule.test", "metadata.issue.recommendation", ""),
				),
			},
		},
	})
}

// TestUnitCloudSecRuleResource_MetadataWithNullIssue verifies that when the API
// returns non-null metadata but with a null issue field, the provider normalizes
// it to {issue={recommendation=""}} instead of panicking or producing drift.
// This covers the edge case where Metadata is present but Issue is nil.
func TestUnitCloudSecRuleResource_MetadataWithNullIssue(t *testing.T) {
	getCallCount := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		for strings.Contains(path, "//") {
			path = strings.ReplaceAll(path, "//", "/")
		}
		if strings.HasSuffix(path, "/") && path != "/" {
			path = strings.TrimSuffix(path, "/")
		}

		// CREATE response includes metadata with empty recommendation
		createResponse := `{
			"id": "test-rule-metadata-null-issue",
			"name": "Rule Metadata Null Issue Test",
			"description": "Tests metadata with null issue on refresh",
			"rule_class": "config",
			"type": "DETECTION",
			"asset_types": ["aws-s3-bucket"],
			"severity": "high",
			"query": {
				"xql": "config from cloud.resource where cloud.type = 'aws'"
			},
			"metadata": {
				"issue": {
					"recommendation": ""
				}
			},
			"compliance_metadata": [],
			"labels": [],
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
		}`

		// GET response returns metadata with null issue (the edge case)
		getResponse := `{
			"id": "test-rule-metadata-null-issue",
			"name": "Rule Metadata Null Issue Test",
			"description": "Tests metadata with null issue on refresh",
			"rule_class": "config",
			"type": "DETECTION",
			"asset_types": ["aws-s3-bucket"],
			"severity": "high",
			"query": {
				"xql": "config from cloud.resource where cloud.type = 'aws'"
			},
			"metadata": {
				"issue": null
			},
			"compliance_metadata": [],
			"labels": [],
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
		}`

		switch {
		case path == "/public_api/v1/rule" && r.Method == http.MethodPost:
			w.WriteHeader(http.StatusCreated)
			fmt.Fprintln(w, createResponse)

		case path == "/public_api/v1/rule/test-rule-metadata-null-issue" && r.Method == http.MethodGet:
			getCallCount++
			w.WriteHeader(http.StatusOK)
			if getCallCount <= 1 {
				// First GET (after create) returns full metadata
				fmt.Fprintln(w, createResponse)
			} else {
				// Subsequent GETs return metadata with null issue
				fmt.Fprintln(w, getResponse)
			}

		case path == "/public_api/v1/rule/test-rule-metadata-null-issue" && r.Method == http.MethodDelete:
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
				// Step 1: Create the rule — API returns metadata with empty recommendation
				Config: fmt.Sprintf(`
					provider "cortexcloud" {
						api_url    = "%s"
						api_key    = "test"
						api_key_id = 123
					}
					resource "cortexcloud_cloudsec_rule" "test" {
						name        = "Rule Metadata Null Issue Test"
						description = "Tests metadata with null issue on refresh"
						class       = "config"
						asset_types = ["aws-s3-bucket"]
						severity    = "high"
						query = {
							xql = "config from cloud.resource where cloud.type = 'aws'"
						}
						enabled = true
					}
				`, server.URL),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("cortexcloud_cloudsec_rule.test", "id", "test-rule-metadata-null-issue"),
					resource.TestCheckResourceAttr("cortexcloud_cloudsec_rule.test", "metadata.issue.recommendation", ""),
				),
			},
			{
				// Step 2: Re-apply the same config — the GET now returns metadata
				// with null issue. The provider should normalize this to
				// {issue={recommendation=""}} without drift.
				Config: fmt.Sprintf(`
					provider "cortexcloud" {
						api_url    = "%s"
						api_key    = "test"
						api_key_id = 123
					}
					resource "cortexcloud_cloudsec_rule" "test" {
						name        = "Rule Metadata Null Issue Test"
						description = "Tests metadata with null issue on refresh"
						class       = "config"
						asset_types = ["aws-s3-bucket"]
						severity    = "high"
						query = {
							xql = "config from cloud.resource where cloud.type = 'aws'"
						}
						enabled = true
					}
				`, server.URL),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("cortexcloud_cloudsec_rule.test", "id", "test-rule-metadata-null-issue"),
					// Metadata should still be populated (empty recommendation), not null
					resource.TestCheckResourceAttr("cortexcloud_cloudsec_rule.test", "metadata.issue.recommendation", ""),
				),
			},
		},
	})
}

func TestUnitCloudSecRuleResource_CustomControlWithoutStandard(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		for strings.Contains(path, "//") {
			path = strings.ReplaceAll(path, "//", "/")
		}
		if strings.HasSuffix(path, "/") && path != "/" {
			path = strings.TrimSuffix(path, "/")
		}

		switch {
		// Compliance API: GetControl — returns a custom control with NO standards
		case path == "/public_api/v1/compliance/get_control" && r.Method == http.MethodPost:
			var reqBody struct {
				RequestData struct {
					ID string `json:"id"`
				} `json:"request_data"`
			}
			if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, `{
				"reply": {
					"control": [{
						"CONTROL_ID": "%s",
						"CONTROL_NAME": "Orphan Custom Control",
						"DESCRIPTION": "A custom control not associated with any standard",
						"CATEGORY": "Access Control",
						"SUBCATEGORY": "1.1",
						"STANDARDS": [],
						"SEVERITY": "HIGH",
						"SUPPORTED": true,
						"INSERTION_TIME": 1640995200000,
						"MODIFICATION_TIME": 1672531200000,
						"CREATED_BY": "test-user",
						"ENABLED": true,
						"IS_CUSTOM": true,
						"STATUS": "active"
					}]
				}
			}`, reqBody.RequestData.ID)

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
					resource "cortexcloud_cloudsec_rule" "test" {
						name        = "Rule With Orphan Custom Control"
						class       = "config"
						asset_types = ["aws-s3-bucket"]
						severity    = "high"
						query = {
							xql = "config from cloud.resource where cloud.type = 'aws'"
						}
						compliance_metadata = [
							{
								control_id = "48e2f6a9fcc049579e9c6b8eda0bd123"
							}
						]
					}
				`, server.URL),
				ExpectError: regexp.MustCompile(`Compliance Control Not Associated with Standard`),
			},
		},
	})
}

// TestUnitCloudSecRuleResource_CustomControlWithStandard tests that creating a rule
// with a custom compliance control that IS associated with a standard succeeds.
func TestUnitCloudSecRuleResource_CustomControlWithStandard(t *testing.T) {
	ruleResponse := `{
		"id": "test-rule-custom-control",
		"name": "Rule With Custom Control",
		"description": "",
		"rule_class": "config",
		"type": "DETECTION",
		"asset_types": ["aws-s3-bucket"],
		"severity": "high",
		"query": {
			"xql": "config from cloud.resource where cloud.type = 'aws'"
		},
		"metadata": {
			"issue": {
				"recommendation": ""
			}
		},
		"compliance_metadata": [
			{
				"control_id": "48e2f6a9fcc049579e9c6b8eda0bd123",
				"control_name": "Custom Control With Standard",
				"standard_id": "custom-standard-id",
				"standard_name": "Custom Security Standard"
			}
		],
		"labels": [],
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
	}`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		urlPath := r.URL.Path
		for strings.Contains(urlPath, "//") {
			urlPath = strings.ReplaceAll(urlPath, "//", "/")
		}
		if strings.HasSuffix(urlPath, "/") && urlPath != "/" {
			urlPath = strings.TrimSuffix(urlPath, "/")
		}

		switch {
		// Compliance API: GetControl — returns a custom control WITH standards
		case urlPath == "/public_api/v1/compliance/get_control" && r.Method == http.MethodPost:
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, `{
				"reply": {
					"control": [{
						"CONTROL_ID": "48e2f6a9fcc049579e9c6b8eda0bd123",
						"CONTROL_NAME": "Custom Control With Standard",
						"DESCRIPTION": "A custom control associated with a standard",
						"CATEGORY": "Access Control",
						"SUBCATEGORY": "1.1",
						"STANDARDS": ["Custom Security Standard"],
						"SEVERITY": "HIGH",
						"SUPPORTED": true,
						"INSERTION_TIME": 1640995200000,
						"MODIFICATION_TIME": 1672531200000,
						"CREATED_BY": "test-user",
						"ENABLED": true,
						"IS_CUSTOM": true,
						"STATUS": "active"
					}]
				}
			}`)

		// CloudSec API: Create rule — success
		case urlPath == "/public_api/v1/rule" && r.Method == http.MethodPost:
			w.WriteHeader(http.StatusCreated)
			fmt.Fprintln(w, ruleResponse)

		// CloudSec API: Get rule (for Read after Create)
		case urlPath == "/public_api/v1/rule/test-rule-custom-control" && r.Method == http.MethodGet:
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, ruleResponse)

		// CloudSec API: Delete rule
		case urlPath == "/public_api/v1/rule/test-rule-custom-control" && r.Method == http.MethodDelete:
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
					resource "cortexcloud_cloudsec_rule" "test" {
						name        = "Rule With Custom Control"
						class       = "config"
						asset_types = ["aws-s3-bucket"]
						severity    = "high"
						query = {
							xql = "config from cloud.resource where cloud.type = 'aws'"
						}
						compliance_metadata = [
							{
								control_id = "48e2f6a9fcc049579e9c6b8eda0bd123"
							}
						]
					}
				`, server.URL),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("cortexcloud_cloudsec_rule.test", "id", "test-rule-custom-control"),
					resource.TestCheckResourceAttr("cortexcloud_cloudsec_rule.test", "compliance_metadata.0.control_id", "48e2f6a9fcc049579e9c6b8eda0bd123"),
					resource.TestCheckResourceAttr("cortexcloud_cloudsec_rule.test", "compliance_metadata.0.standard_name", "Custom Security Standard"),
				),
			},
		},
	})
}

// TestUnitCloudSecRuleResource_BuiltInControlSkipsValidation tests that built-in
// control IDs (e.g., "CIS-AWS-2.1.5") skip the pre-flight validation and are
// passed directly to the API without calling the Compliance API.
func TestUnitCloudSecRuleResource_BuiltInControlSkipsValidation(t *testing.T) {
	complianceAPICalled := false

	ruleResponse := `{
		"id": "test-rule-builtin-control",
		"name": "Rule With Built-in Control",
		"description": "",
		"rule_class": "config",
		"type": "DETECTION",
		"asset_types": ["aws-s3-bucket"],
		"severity": "high",
		"query": {
			"xql": "config from cloud.resource where cloud.type = 'aws'"
		},
		"metadata": {
			"issue": {
				"recommendation": ""
			}
		},
		"compliance_metadata": [
			{
				"control_id": "CIS-AWS-2.1.5",
				"control_name": "Ensure S3 Bucket Encryption",
				"standard_id": "cis-aws-id",
				"standard_name": "CIS AWS Foundations"
			}
		],
		"labels": [],
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
	}`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		urlPath := r.URL.Path
		for strings.Contains(urlPath, "//") {
			urlPath = strings.ReplaceAll(urlPath, "//", "/")
		}
		if strings.HasSuffix(urlPath, "/") && urlPath != "/" {
			urlPath = strings.TrimSuffix(urlPath, "/")
		}

		switch {
		// Compliance API: should NOT be called for built-in control IDs
		case urlPath == "/public_api/v1/compliance/get_control" && r.Method == http.MethodPost:
			complianceAPICalled = true
			http.Error(w, "compliance API should not be called for built-in controls", http.StatusInternalServerError)

		// CloudSec API: Create rule
		case urlPath == "/public_api/v1/rule" && r.Method == http.MethodPost:
			w.WriteHeader(http.StatusCreated)
			fmt.Fprintln(w, ruleResponse)

		// CloudSec API: Get rule
		case urlPath == "/public_api/v1/rule/test-rule-builtin-control" && r.Method == http.MethodGet:
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, ruleResponse)

		// CloudSec API: Delete rule
		case urlPath == "/public_api/v1/rule/test-rule-builtin-control" && r.Method == http.MethodDelete:
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
					resource "cortexcloud_cloudsec_rule" "test" {
						name        = "Rule With Built-in Control"
						class       = "config"
						asset_types = ["aws-s3-bucket"]
						severity    = "high"
						query = {
							xql = "config from cloud.resource where cloud.type = 'aws'"
						}
						compliance_metadata = [
							{
								control_id = "CIS-AWS-2.1.5"
							}
						]
					}
				`, server.URL),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("cortexcloud_cloudsec_rule.test", "id", "test-rule-builtin-control"),
					resource.TestCheckResourceAttr("cortexcloud_cloudsec_rule.test", "compliance_metadata.0.control_id", "CIS-AWS-2.1.5"),
				),
			},
		},
	})

	if complianceAPICalled {
		t.Error("Compliance API was called for a built-in control ID; it should have been skipped")
	}
}
