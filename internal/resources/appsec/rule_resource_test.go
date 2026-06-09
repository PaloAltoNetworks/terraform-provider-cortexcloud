// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package appsec_test

import (
	"encoding/json"
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

// TestUnitAppSecRuleResource_UppercaseNameAndDescriptionPreserved verifies that when
// a user provides UPPERCASE name and description values and the API returns lowercase
// values, the preserveCaseIfEqual logic in RefreshFromRemote prevents state drift
// by preserving the user's original casing.
func TestUnitAppSecRuleResource_UppercaseNameAndDescriptionPreserved(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		for strings.Contains(path, "//") {
			path = strings.ReplaceAll(path, "//", "/")
		}
		if strings.HasSuffix(path, "/") && path != "/" {
			path = strings.TrimSuffix(path, "/")
		}

		switch {
		case path == "/public_api/appsec/v1/rules" && r.Method == http.MethodPost:
			var reqBody map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}

			// API returns lowercased name and description (simulating known API behavior)
			w.WriteHeader(http.StatusCreated)
			fmt.Fprintln(w, `{
				"id": "rule-lowercase-test",
				"name": "my_uppercase_rule",
				"description": "this is an uppercase description",
				"severity": "HIGH",
				"scanner": "IAC",
				"category": "NETWORKING",
				"subCategory": "INGRESS_CONTROLS",
				"cloudProvider": "",
				"domain": "",
				"findingCategory": "",
				"isCustom": true,
				"isEnabled": true,
				"createdAt": {"value": "2024-01-01T00:00:00Z"},
				"updatedAt": {"value": "2024-01-01T00:00:00Z"}
			}`)

		case strings.HasPrefix(path, "/public_api/appsec/v1/rules/rule-lowercase-test") && r.Method == http.MethodGet:
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, `{
				"id": "rule-lowercase-test",
				"name": "my_uppercase_rule",
				"description": "this is an uppercase description",
				"severity": "HIGH",
				"scanner": "IAC",
				"category": "NETWORKING",
				"subCategory": "INGRESS_CONTROLS",
				"cloudProvider": "",
				"domain": "",
				"findingCategory": "",
				"isCustom": true,
				"isEnabled": true,
				"createdAt": {"value": "2024-01-01T00:00:00Z"},
				"updatedAt": {"value": "2024-01-01T00:00:00Z"}
			}`)

		case strings.HasPrefix(path, "/public_api/appsec/v1/rules/rule-lowercase-test") && r.Method == http.MethodDelete:
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
				// User provides UPPERCASE name and description.
				// API returns lowercase — preserveCaseIfEqual keeps user's casing.
				Config: fmt.Sprintf(`
					provider "cortexcloud" {
						api_url    = "%s"
						api_key    = "test"
						api_key_id = 123
					}
					resource "cortexcloud_appsec_rule" "test" {
						name         = "MY_UPPERCASE_RULE"
						description  = "This Is An Uppercase Description"
						severity     = "HIGH"
						scanner      = "IAC"
						category     = "NETWORKING"
						sub_category = "INGRESS_CONTROLS"
					}
				`, server.URL),
				Check: resource.ComposeAggregateTestCheckFunc(
					// name and description preserve user's UPPERCASE casing
					resource.TestCheckResourceAttr("cortexcloud_appsec_rule.test", "name", "MY_UPPERCASE_RULE"),
					resource.TestCheckResourceAttr("cortexcloud_appsec_rule.test", "description", "This Is An Uppercase Description"),
					// Other fields are not affected by the lowercase workaround
					resource.TestCheckResourceAttr("cortexcloud_appsec_rule.test", "severity", "HIGH"),
					resource.TestCheckResourceAttr("cortexcloud_appsec_rule.test", "scanner", "IAC"),
					resource.TestCheckResourceAttr("cortexcloud_appsec_rule.test", "category", "NETWORKING"),
					resource.TestCheckResourceAttr("cortexcloud_appsec_rule.test", "sub_category", "INGRESS_CONTROLS"),
					resource.TestCheckResourceAttrSet("cortexcloud_appsec_rule.test", "id"),
				),
			},
		},
	})
}

// TestUnitAppSecRuleResource_AlreadyLowercaseNoDrift verifies that when a user
// provides already-lowercase name and description, no drift occurs.
func TestUnitAppSecRuleResource_AlreadyLowercaseNoDrift(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		for strings.Contains(path, "//") {
			path = strings.ReplaceAll(path, "//", "/")
		}
		if strings.HasSuffix(path, "/") && path != "/" {
			path = strings.TrimSuffix(path, "/")
		}

		switch {
		case path == "/public_api/appsec/v1/rules" && r.Method == http.MethodPost:
			w.WriteHeader(http.StatusCreated)
			fmt.Fprintln(w, `{
				"id": "rule-already-lower",
				"name": "already_lowercase",
				"description": "already lowercase description",
				"severity": "HIGH",
				"scanner": "IAC",
				"category": "NETWORKING",
				"subCategory": "INGRESS_CONTROLS",
				"cloudProvider": "",
				"domain": "",
				"findingCategory": "",
				"isCustom": true,
				"isEnabled": true,
				"createdAt": {"value": "2024-01-01T00:00:00Z"},
				"updatedAt": {"value": "2024-01-01T00:00:00Z"}
			}`)

		case strings.HasPrefix(path, "/public_api/appsec/v1/rules/rule-already-lower") && r.Method == http.MethodGet:
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, `{
				"id": "rule-already-lower",
				"name": "already_lowercase",
				"description": "already lowercase description",
				"severity": "HIGH",
				"scanner": "IAC",
				"category": "NETWORKING",
				"subCategory": "INGRESS_CONTROLS",
				"cloudProvider": "",
				"domain": "",
				"findingCategory": "",
				"isCustom": true,
				"isEnabled": true,
				"createdAt": {"value": "2024-01-01T00:00:00Z"},
				"updatedAt": {"value": "2024-01-01T00:00:00Z"}
			}`)

		case strings.HasPrefix(path, "/public_api/appsec/v1/rules/rule-already-lower") && r.Method == http.MethodDelete:
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
					resource "cortexcloud_appsec_rule" "test" {
						name         = "already_lowercase"
						description  = "already lowercase description"
						severity     = "HIGH"
						scanner      = "IAC"
						category     = "NETWORKING"
						sub_category = "INGRESS_CONTROLS"
					}
				`, server.URL),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("cortexcloud_appsec_rule.test", "name", "already_lowercase"),
					resource.TestCheckResourceAttr("cortexcloud_appsec_rule.test", "description", "already lowercase description"),
				),
			},
		},
	})
}

// TestUnitAppSecRuleResource_MixedCaseUpdatePreservesUserCasing verifies that updating
// name and description with different casing works correctly — the user's new casing
// is preserved even though the API lowercases it.
func TestUnitAppSecRuleResource_MixedCaseUpdatePreservesUserCasing(t *testing.T) {
	callCount := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		for strings.Contains(path, "//") {
			path = strings.ReplaceAll(path, "//", "/")
		}
		if strings.HasSuffix(path, "/") && path != "/" {
			path = strings.TrimSuffix(path, "/")
		}

		switch {
		case path == "/public_api/appsec/v1/rules" && r.Method == http.MethodPost:
			w.WriteHeader(http.StatusCreated)
			// API lowercases name and description
			fmt.Fprintln(w, `{
				"id": "rule-mixed-case",
				"name": "initial_rule",
				"description": "initial description",
				"severity": "HIGH",
				"scanner": "IAC",
				"category": "NETWORKING",
				"subCategory": "INGRESS_CONTROLS",
				"cloudProvider": "",
				"domain": "",
				"findingCategory": "",
				"isCustom": true,
				"isEnabled": true,
				"createdAt": {"value": "2024-01-01T00:00:00Z"},
				"updatedAt": {"value": "2024-01-01T00:00:00Z"}
			}`)

		case strings.HasPrefix(path, "/public_api/appsec/v1/rules/rule-mixed-case") && r.Method == http.MethodGet:
			callCount++
			// SDK no longer does a GET before PATCH, so the threshold is lower.
			// GET calls: #1 = post-create read, #2 = step 1 refresh.
			// After update: #3+ = post-update reads.
			if callCount <= 2 {
				w.WriteHeader(http.StatusOK)
				fmt.Fprintln(w, `{
					"id": "rule-mixed-case",
					"name": "initial_rule",
					"description": "initial description",
					"severity": "HIGH",
					"scanner": "IAC",
					"category": "NETWORKING",
					"subCategory": "INGRESS_CONTROLS",
					"cloudProvider": "",
					"domain": "",
					"findingCategory": "",
					"isCustom": true,
					"isEnabled": true,
					"createdAt": {"value": "2024-01-01T00:00:00Z"},
					"updatedAt": {"value": "2024-01-01T00:00:00Z"}
				}`)
			} else {
				// After update — API returns lowercased new values
				w.WriteHeader(http.StatusOK)
				fmt.Fprintln(w, `{
					"id": "rule-mixed-case",
					"name": "updated_rule",
					"description": "updated description",
					"severity": "HIGH",
					"scanner": "IAC",
					"category": "NETWORKING",
					"subCategory": "INGRESS_CONTROLS",
					"cloudProvider": "",
					"domain": "",
					"findingCategory": "",
					"isCustom": true,
					"isEnabled": true,
					"createdAt": {"value": "2024-01-01T00:00:00Z"},
					"updatedAt": {"value": "2024-01-02T00:00:00Z"}
				}`)
			}

		case strings.HasPrefix(path, "/public_api/appsec/v1/rules/rule-mixed-case") && r.Method == http.MethodPatch:
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, `{
				"rule": {
					"id": "rule-mixed-case",
					"name": "updated_rule",
					"description": "updated description",
					"severity": "HIGH",
					"scanner": "IAC",
					"category": "NETWORKING",
					"subCategory": "INGRESS_CONTROLS",
					"cloudProvider": "",
					"domain": "",
					"findingCategory": "",
					"isCustom": true,
					"isEnabled": true,
					"createdAt": {"value": "2024-01-01T00:00:00Z"},
					"updatedAt": {"value": "2024-01-02T00:00:00Z"}
				}
			}`)

		case strings.HasPrefix(path, "/public_api/appsec/v1/rules/rule-mixed-case") && r.Method == http.MethodDelete:
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
				// Step 1: Create with UPPERCASE name/description
				Config: fmt.Sprintf(`
					provider "cortexcloud" {
						api_url    = "%s"
						api_key    = "test"
						api_key_id = 123
					}
					resource "cortexcloud_appsec_rule" "test" {
						name         = "INITIAL_RULE"
						description  = "Initial Description"
						severity     = "HIGH"
						scanner      = "IAC"
						category     = "NETWORKING"
						sub_category = "INGRESS_CONTROLS"
					}
				`, server.URL),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("cortexcloud_appsec_rule.test", "name", "INITIAL_RULE"),
					resource.TestCheckResourceAttr("cortexcloud_appsec_rule.test", "description", "Initial Description"),
				),
			},
			{
				// Step 2: Update with different UPPERCASE name/description
				Config: fmt.Sprintf(`
					provider "cortexcloud" {
						api_url    = "%s"
						api_key    = "test"
						api_key_id = 123
					}
					resource "cortexcloud_appsec_rule" "test" {
						name         = "UPDATED_RULE"
						description  = "Updated Description"
						severity     = "HIGH"
						scanner      = "IAC"
						category     = "NETWORKING"
						sub_category = "INGRESS_CONTROLS"
					}
				`, server.URL),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("cortexcloud_appsec_rule.test", "name", "UPDATED_RULE"),
					resource.TestCheckResourceAttr("cortexcloud_appsec_rule.test", "description", "Updated Description"),
				),
			},
		},
	})
}

// TestUnitAppSecRuleResource_AutoAddedFrameworkFiltered verifies that when the API
// auto-adds a companion framework (e.g., TERRAFORMPLAN when TERRAFORM is sent),
// the provider filters it out so Terraform state only contains the frameworks
// the user configured. Without this fix, Terraform would report:
// "block count changed from 1 to 2".
func TestUnitAppSecRuleResource_AutoAddedFrameworkFiltered(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		for strings.Contains(path, "//") {
			path = strings.ReplaceAll(path, "//", "/")
		}
		if strings.HasSuffix(path, "/") && path != "/" {
			path = strings.TrimSuffix(path, "/")
		}

		switch {
		case path == "/public_api/appsec/v1/rules" && r.Method == http.MethodPost:
			w.WriteHeader(http.StatusCreated)
			// API returns 2 frameworks even though only TERRAFORM was sent.
			// TERRAFORMPLAN is auto-added by the API.
			fmt.Fprintln(w, `{
				"id": "rule-fw-filter-test",
				"name": "tf-test-rule",
				"description": "test rule",
				"severity": "HIGH",
				"scanner": "IAC",
				"category": "AI_ML",
				"subCategory": "PUBLIC_EXPOSURE",
				"cloudProvider": "",
				"domain": "",
				"findingCategory": "",
				"isCustom": true,
				"isEnabled": true,
				"frameworks": [
					{
						"name": "TERRAFORM",
						"definition": "definition:\n  cond_type: attribute\n  resource_types:\n    - aws_security_group\n  attribute: ingress.cidr_blocks\n  operator: contains\n  value: \"0.0.0.0/0\"",
						"definitionLink": "",
						"remediationDescription": "Restrict ingress CIDR blocks"
					},
					{
						"name": "TERRAFORMPLAN",
						"definition": "definition:\n  cond_type: attribute\n  resource_types:\n    - aws_security_group\n  attribute: ingress.cidr_blocks\n  operator: contains\n  value: \"0.0.0.0/0\"",
						"definitionLink": "",
						"remediationDescription": "Restrict ingress CIDR blocks"
					}
				],
				"createdAt": {"value": "2024-01-01T00:00:00Z"},
				"updatedAt": {"value": "2024-01-01T00:00:00Z"}
			}`)

		case strings.HasPrefix(path, "/public_api/appsec/v1/rules/rule-fw-filter-test") && r.Method == http.MethodGet:
			w.WriteHeader(http.StatusOK)
			// GET also returns both frameworks
			fmt.Fprintln(w, `{
				"id": "rule-fw-filter-test",
				"name": "tf-test-rule",
				"description": "test rule",
				"severity": "HIGH",
				"scanner": "IAC",
				"category": "AI_ML",
				"subCategory": "PUBLIC_EXPOSURE",
				"cloudProvider": "",
				"domain": "",
				"findingCategory": "",
				"isCustom": true,
				"isEnabled": true,
				"frameworks": [
					{
						"name": "TERRAFORM",
						"definition": "definition:\n  cond_type: attribute\n  resource_types:\n    - aws_security_group\n  attribute: ingress.cidr_blocks\n  operator: contains\n  value: \"0.0.0.0/0\"",
						"definitionLink": "",
						"remediationDescription": "Restrict ingress CIDR blocks"
					},
					{
						"name": "TERRAFORMPLAN",
						"definition": "definition:\n  cond_type: attribute\n  resource_types:\n    - aws_security_group\n  attribute: ingress.cidr_blocks\n  operator: contains\n  value: \"0.0.0.0/0\"",
						"definitionLink": "",
						"remediationDescription": "Restrict ingress CIDR blocks"
					}
				],
				"createdAt": {"value": "2024-01-01T00:00:00Z"},
				"updatedAt": {"value": "2024-01-01T00:00:00Z"}
			}`)

		case strings.HasPrefix(path, "/public_api/appsec/v1/rules/rule-fw-filter-test") && r.Method == http.MethodDelete:
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
				// User configures 1 framework (TERRAFORM).
				// API returns 2 (TERRAFORM + TERRAFORMPLAN).
				// Provider must filter to only the user-configured framework.
				Config: fmt.Sprintf(`
					provider "cortexcloud" {
						api_url    = "%s"
						api_key    = "test"
						api_key_id = 123
					}
					resource "cortexcloud_appsec_rule" "test" {
						name         = "tf-test-rule"
						description  = "test rule"
						severity     = "HIGH"
						scanner      = "IAC"
						category     = "AI_ML"
						sub_category = "PUBLIC_EXPOSURE"

						frameworks {
							name                    = "TERRAFORM"
							definition              = "definition:\n  cond_type: attribute\n  resource_types:\n    - aws_security_group\n  attribute: ingress.cidr_blocks\n  operator: contains\n  value: \"0.0.0.0/0\""
							remediation_description = "Restrict ingress CIDR blocks"
						}
					}
				`, server.URL),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("cortexcloud_appsec_rule.test", "id", "rule-fw-filter-test"),
					// Only 1 framework should be in state (the user-configured one)
					resource.TestCheckResourceAttr("cortexcloud_appsec_rule.test", "frameworks.#", "1"),
					resource.TestCheckResourceAttr("cortexcloud_appsec_rule.test", "frameworks.0.name", "TERRAFORM"),
					resource.TestCheckResourceAttr("cortexcloud_appsec_rule.test", "frameworks.0.remediation_description", "Restrict ingress CIDR blocks"),
					// definition_link should be null (not set by user, API returns empty string)
					resource.TestCheckNoResourceAttr("cortexcloud_appsec_rule.test", "frameworks.0.definition_link"),
				),
			},
		},
	})
}

// TestUnitAppSecRuleResource_MultipleFrameworksAllConfigured verifies that when
// the user explicitly configures multiple frameworks and the API returns all of them,
// all frameworks are preserved in state (no incorrect filtering).
func TestUnitAppSecRuleResource_MultipleFrameworksAllConfigured(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		for strings.Contains(path, "//") {
			path = strings.ReplaceAll(path, "//", "/")
		}
		if strings.HasSuffix(path, "/") && path != "/" {
			path = strings.TrimSuffix(path, "/")
		}

		switch {
		case path == "/public_api/appsec/v1/rules" && r.Method == http.MethodPost:
			w.WriteHeader(http.StatusCreated)
			fmt.Fprintln(w, `{
				"id": "rule-multi-fw-test",
				"name": "multi-fw-rule",
				"description": "test rule with multiple frameworks",
				"severity": "HIGH",
				"scanner": "IAC",
				"category": "AI_ML",
				"subCategory": "PUBLIC_EXPOSURE",
				"cloudProvider": "",
				"domain": "",
				"findingCategory": "",
				"isCustom": true,
				"isEnabled": true,
				"frameworks": [
					{
						"name": "TERRAFORM",
						"definition": "definition:\n  cond_type: attribute\n  resource_types:\n    - aws_security_group",
						"definitionLink": "",
						"remediationDescription": "Fix terraform"
					},
					{
						"name": "CLOUDFORMATION",
						"definition": "definition:\n  cond_type: attribute\n  resource_types:\n    - AWS::EC2::SecurityGroup",
						"definitionLink": "",
						"remediationDescription": "Fix cloudformation"
					}
				],
				"createdAt": {"value": "2024-01-01T00:00:00Z"},
				"updatedAt": {"value": "2024-01-01T00:00:00Z"}
			}`)

		case strings.HasPrefix(path, "/public_api/appsec/v1/rules/rule-multi-fw-test") && r.Method == http.MethodGet:
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, `{
				"id": "rule-multi-fw-test",
				"name": "multi-fw-rule",
				"description": "test rule with multiple frameworks",
				"severity": "HIGH",
				"scanner": "IAC",
				"category": "AI_ML",
				"subCategory": "PUBLIC_EXPOSURE",
				"cloudProvider": "",
				"domain": "",
				"findingCategory": "",
				"isCustom": true,
				"isEnabled": true,
				"frameworks": [
					{
						"name": "TERRAFORM",
						"definition": "definition:\n  cond_type: attribute\n  resource_types:\n    - aws_security_group",
						"definitionLink": "",
						"remediationDescription": "Fix terraform"
					},
					{
						"name": "CLOUDFORMATION",
						"definition": "definition:\n  cond_type: attribute\n  resource_types:\n    - AWS::EC2::SecurityGroup",
						"definitionLink": "",
						"remediationDescription": "Fix cloudformation"
					}
				],
				"createdAt": {"value": "2024-01-01T00:00:00Z"},
				"updatedAt": {"value": "2024-01-01T00:00:00Z"}
			}`)

		case strings.HasPrefix(path, "/public_api/appsec/v1/rules/rule-multi-fw-test") && r.Method == http.MethodDelete:
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
				// User configures 2 frameworks, API returns exactly those 2.
				Config: fmt.Sprintf(`
					provider "cortexcloud" {
						api_url    = "%s"
						api_key    = "test"
						api_key_id = 123
					}
					resource "cortexcloud_appsec_rule" "test" {
						name         = "multi-fw-rule"
						description  = "test rule with multiple frameworks"
						severity     = "HIGH"
						scanner      = "IAC"
						category     = "AI_ML"
						sub_category = "PUBLIC_EXPOSURE"

						frameworks {
							name                    = "TERRAFORM"
							definition              = "definition:\n  cond_type: attribute\n  resource_types:\n    - aws_security_group"
							remediation_description = "Fix terraform"
						}

						frameworks {
							name                    = "CLOUDFORMATION"
							definition              = "definition:\n  cond_type: attribute\n  resource_types:\n    - AWS::EC2::SecurityGroup"
							remediation_description = "Fix cloudformation"
						}
					}
				`, server.URL),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("cortexcloud_appsec_rule.test", "id", "rule-multi-fw-test"),
					// Both frameworks should be in state
					resource.TestCheckResourceAttr("cortexcloud_appsec_rule.test", "frameworks.#", "2"),
					resource.TestCheckResourceAttr("cortexcloud_appsec_rule.test", "frameworks.0.name", "TERRAFORM"),
					resource.TestCheckResourceAttr("cortexcloud_appsec_rule.test", "frameworks.1.name", "CLOUDFORMATION"),
				),
			},
		},
	})
}
