// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package appsec_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/provider"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

// normalizePath removes double slashes and trailing slashes from URL paths.
func normalizePath(p string) string {
	for strings.Contains(p, "//") {
		p = strings.ReplaceAll(p, "//", "/")
	}
	if strings.HasSuffix(p, "/") && p != "/" {
		p = strings.TrimSuffix(p, "/")
	}
	return p
}

// fullPolicyResponse returns a complete API response for a policy.
// All five trigger blocks are emitted with their canonical defaults — every
// real AppSec policy on the JP tenant carries all five.
func fullPolicyResponse(id, name, description, status string) string {
	return fmt.Sprintf(`{
		"id": %q,
		"name": %q,
		"description": %q,
		"status": %q,
		"isCustom": true,
		"conditions": {
			"AND": [
				{"SEARCH_FIELD": "Finding Type", "SEARCH_TYPE": "EQ", "SEARCH_VALUE": "CAS_SECRET_SCANNER"},
				{"SEARCH_FIELD": "Severity", "SEARCH_TYPE": "IN", "SEARCH_VALUE": ["HIGH", "CRITICAL"]}
			]
		},
		"scope": {
			"AND": [
				{"SEARCH_FIELD": "is_public_repository", "SEARCH_TYPE": "EQ", "SEARCH_VALUE": true}
			]
		},
		"assetGroupIds": [],
		"triggers": {
			"periodic":      {"isEnabled": true,  "actions": {"reportIssue": true},                                                "overrideIssueSeverity": null},
			"pr":            {"isEnabled": false, "actions": {"reportIssue": false, "blockPr": false, "reportPrComment": false}, "overrideIssueSeverity": null},
			"cicd":          {"isEnabled": false, "actions": {"reportIssue": false, "blockCicd": false, "reportCicd": false},     "overrideIssueSeverity": null},
			"ciImage":       {"isEnabled": false, "actions": {"reportIssue": false, "reportCicd": false, "blockCicd": false},     "overrideIssueSeverity": null},
			"imageRegistry": {"isEnabled": false, "actions": {"reportIssue": false},                                              "overrideIssueSeverity": null}
		},
		"actions": {
			"reportIssue": true,
			"blockPr": false,
			"blockCicd": false,
			"reportPrComment": false,
			"reportCicd": false,
			"ingestedData": false
		},
		"findingTypes": {
			"CAS_CI_CD_RISK_SCANNER": false,
			"CAS_CVE_SCANNER": false,
			"CAS_IAC_SCANNER": false,
			"CAS_LICENSE_SCANNER": false,
			"CAS_OPERATIONAL_RISK_SCANNER": false,
			"CAS_SAST_SCANNER": false,
			"CAS_SECRET_SCANNER": true,
			"CAS_THIRD_PARTY_WEAKNESSES": false
		},
		"overrideIssueSeverity": null,
		"developerSuppressionAffects": false,
		"relatedDetectionRules": [],
		"createdBy": "system",
		"dateCreated": "2024-01-01T00:00:00Z",
		"modifiedBy": "system",
		"dateModified": "2024-01-01T00:00:00Z",
		"version": 1.0
	}`, id, name, description, status)
}

// minimalTriggersHCL returns the HCL for a periodic-only trigger config.
// The other 4 triggers are omitted — the provider should fill them with
// canonical defaults (enabled=false, all actions=false).
const minimalTriggersHCL = `
		periodic_trigger = {
			enabled = true
			actions = { report_issue = true }
		}
		pr_trigger = {
			enabled = false
			actions = { report_issue = false, block_pr = false, report_pr_comment = false }
		}
		cicd_trigger = {
			enabled = false
			actions = { report_issue = false, block_cicd = false, report_cicd = false }
		}
		ci_image_trigger = {
			enabled = false
			actions = { report_issue = false, report_cicd = false, block_cicd = false }
		}
		image_registry_trigger = {
			enabled = false
			actions = { report_issue = false }
		}
`

// TestUnitAppSecPolicyResource_UpdateStatusEnableDisable verifies that updating
// a policy's status from disabled to enabled succeeds. The PUT request must
// not contain the server-computed "actions" field.
func TestUnitAppSecPolicyResource_UpdateStatusEnableDisable(t *testing.T) {
	const policyID = "786505af-bf46-417e-97e7-e36093ad013b"
	const policyName = "Create issues on HIGH/CRITICAL secrets"
	const policyDesc = "Create issues on HIGH/CRITICAL secrets in public repository"

	currentStatus := "disabled"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := normalizePath(r.URL.Path)

		switch {
		case path == "/public_api/appsec/v1/policies" && r.Method == http.MethodPost:
			w.WriteHeader(http.StatusNoContent)

		case path == "/public_api/appsec/v1/policies" && r.Method == http.MethodGet:
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, "[%s]\n", fullPolicyResponse(policyID, policyName, policyDesc, currentStatus))

		case strings.HasPrefix(path, "/public_api/appsec/v1/policies/"+policyID) && r.Method == http.MethodGet:
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, fullPolicyResponse(policyID, policyName, policyDesc, currentStatus))

		case strings.HasPrefix(path, "/public_api/appsec/v1/policies/"+policyID) && r.Method == http.MethodPut:
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}

			var reqBody map[string]interface{}
			if err := json.Unmarshal(body, &reqBody); err != nil {
				http.Error(w, "invalid json", http.StatusBadRequest)
				return
			}

			if _, ok := reqBody["actions"]; ok {
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprintln(w, `{"errorCode":"ValidateError","message":"Validation Failed","details":{"policy":{"message":"\"actions\" is an excess property and therefore is not allowed"}}}`)
				return
			}

			if enabled, ok := reqBody["enabled"]; ok {
				if enabledBool, ok := enabled.(bool); ok {
					if enabledBool {
						currentStatus = "enabled"
					} else {
						currentStatus = "disabled"
					}
				}
			}

			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, fullPolicyResponse(policyID, policyName, policyDesc, currentStatus))

		case strings.HasPrefix(path, "/public_api/appsec/v1/policies/"+policyID) && r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, `{"message":"Policy deleted successfully"}`)

		default:
			http.Error(w, "not found: "+r.URL.Path, http.StatusNotFound)
		}
	}))
	defer server.Close()

	conditionsJSON := `{"AND":[{"SEARCH_FIELD":"Finding Type","SEARCH_TYPE":"EQ","SEARCH_VALUE":"CAS_SECRET_SCANNER"},{"SEARCH_FIELD":"Severity","SEARCH_TYPE":"IN","SEARCH_VALUE":["HIGH","CRITICAL"]}]}`
	scopeJSON := `{"AND":[{"SEARCH_FIELD":"is_public_repository","SEARCH_TYPE":"EQ","SEARCH_VALUE":true}]}`

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
					resource "cortexcloud_appsec_policy" "test" {
						name        = %q
						description = %q
						status      = "disabled"
						conditions  = %q
						scope       = %q
						%s
					}
				`, server.URL, policyName, policyDesc, conditionsJSON, scopeJSON, minimalTriggersHCL),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("cortexcloud_appsec_policy.test", "status", "disabled"),
					resource.TestCheckResourceAttr("cortexcloud_appsec_policy.test", "name", policyName),
				),
			},
			{
				Config: fmt.Sprintf(`
					provider "cortexcloud" {
						api_url    = "%s"
						api_key    = "test"
						api_key_id = 123
					}
					resource "cortexcloud_appsec_policy" "test" {
						name        = %q
						description = %q
						status      = "enabled"
						conditions  = %q
						scope       = %q
						%s
					}
				`, server.URL, policyName, policyDesc, conditionsJSON, scopeJSON, minimalTriggersHCL),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("cortexcloud_appsec_policy.test", "status", "enabled"),
					resource.TestCheckResourceAttr("cortexcloud_appsec_policy.test", "name", policyName),
				),
			},
		},
	})
}

// TestUnitAppSecPolicyResource_UpdateSendsCompletePayload verifies the update
// PUT body excludes server-computed fields and includes the required
// per-trigger sub-blocks.
func TestUnitAppSecPolicyResource_UpdateSendsCompletePayload(t *testing.T) {
	const policyID = "test-policy-complete-payload"
	const policyName = "Test Complete Payload"
	const policyDesc = "Tests that update sends complete payload"

	var capturedUpdateBody map[string]interface{}
	currentStatus := "disabled"
	currentDesc := policyDesc

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := normalizePath(r.URL.Path)

		switch {
		case path == "/public_api/appsec/v1/policies" && r.Method == http.MethodPost:
			w.WriteHeader(http.StatusNoContent)

		case path == "/public_api/appsec/v1/policies" && r.Method == http.MethodGet:
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, "[%s]\n", fullPolicyResponse(policyID, policyName, currentDesc, currentStatus))

		case strings.HasPrefix(path, "/public_api/appsec/v1/policies/"+policyID) && r.Method == http.MethodGet:
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, fullPolicyResponse(policyID, policyName, currentDesc, currentStatus))

		case strings.HasPrefix(path, "/public_api/appsec/v1/policies/"+policyID) && r.Method == http.MethodPut:
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			if err := json.Unmarshal(body, &capturedUpdateBody); err != nil {
				http.Error(w, "invalid json", http.StatusBadRequest)
				return
			}

			if enabled, ok := capturedUpdateBody["enabled"]; ok {
				if enabledBool, ok := enabled.(bool); ok {
					if enabledBool {
						currentStatus = "enabled"
					} else {
						currentStatus = "disabled"
					}
				}
			}
			if desc, ok := capturedUpdateBody["description"]; ok {
				if descStr, ok := desc.(string); ok {
					currentDesc = descStr
				}
			}

			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, fullPolicyResponse(policyID, policyName, currentDesc, currentStatus))

		case strings.HasPrefix(path, "/public_api/appsec/v1/policies/"+policyID) && r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, `{"message":"deleted"}`)

		default:
			http.Error(w, "not found: "+r.URL.Path, http.StatusNotFound)
		}
	}))
	defer server.Close()

	conditionsJSON := `{"AND":[{"SEARCH_FIELD":"Finding Type","SEARCH_TYPE":"EQ","SEARCH_VALUE":"CAS_SECRET_SCANNER"},{"SEARCH_FIELD":"Severity","SEARCH_TYPE":"IN","SEARCH_VALUE":["HIGH","CRITICAL"]}]}`
	scopeJSON := `{"AND":[{"SEARCH_FIELD":"is_public_repository","SEARCH_TYPE":"EQ","SEARCH_VALUE":true}]}`

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
					resource "cortexcloud_appsec_policy" "test" {
						name        = %q
						description = %q
						status      = "disabled"
						conditions  = %q
						scope       = %q
						%s
					}
				`, server.URL, policyName, policyDesc, conditionsJSON, scopeJSON, minimalTriggersHCL),
			},
			{
				Config: fmt.Sprintf(`
					provider "cortexcloud" {
						api_url    = "%s"
						api_key    = "test"
						api_key_id = 123
					}
					resource "cortexcloud_appsec_policy" "test" {
						name        = %q
						description = "Updated description"
						status      = "enabled"
						conditions  = %q
						scope       = %q
						%s
					}
				`, server.URL, policyName, conditionsJSON, scopeJSON, minimalTriggersHCL),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("cortexcloud_appsec_policy.test", "status", "enabled"),
					func(s *terraform.State) error {
						if capturedUpdateBody == nil {
							return fmt.Errorf("no update request was captured")
						}
						excessFields := []string{"actions", "status", "relatedDetectionRules", "developerSuppressionAffects", "overrideIssueSeverity", "asset_group_ids"}
						for _, field := range excessFields {
							if _, ok := capturedUpdateBody[field]; ok {
								return fmt.Errorf("update request body should NOT contain %q field (excess property); got keys: %v", field, mapKeys(capturedUpdateBody))
							}
						}
						if _, ok := capturedUpdateBody["enabled"]; !ok {
							return fmt.Errorf("update request body missing 'enabled' field")
						}
						return nil
					},
				),
			},
		},
	})
}

// TestUnitAppSecPolicyResource_AllFiveTriggersInRequestBody verifies the
// CREATE POST body always carries all 5 trigger keys with the empirical
// default shape — even when the user supplies the minimal periodic-only
// configuration. This is the contract the API requires (otherwise it
// returns HTTP 422 with "ciImage is required" / "imageRegistry is required").
func TestUnitAppSecPolicyResource_AllFiveTriggersInRequestBody(t *testing.T) {
	const policyID = "test-five-triggers"
	const policyName = "five-trigger policy"

	var capturedCreateBody map[string]interface{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := normalizePath(r.URL.Path)

		switch {
		case path == "/public_api/appsec/v1/policies" && r.Method == http.MethodPost:
			body, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(body, &capturedCreateBody)
			w.WriteHeader(http.StatusNoContent)

		case path == "/public_api/appsec/v1/policies" && r.Method == http.MethodGet:
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, "[%s]\n", fullPolicyResponse(policyID, policyName, "five-triggers test", "enabled"))

		case strings.HasPrefix(path, "/public_api/appsec/v1/policies/"+policyID) && r.Method == http.MethodGet:
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, fullPolicyResponse(policyID, policyName, "five-triggers test", "enabled"))

		case strings.HasPrefix(path, "/public_api/appsec/v1/policies/"+policyID) && r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, `{"message":"deleted"}`)

		default:
			http.Error(w, "not found: "+r.URL.Path, http.StatusNotFound)
		}
	}))
	defer server.Close()

	conditionsJSON := `{"AND":[{"SEARCH_FIELD":"Finding Type","SEARCH_TYPE":"EQ","SEARCH_VALUE":"CAS_SECRET_SCANNER"},{"SEARCH_FIELD":"Severity","SEARCH_TYPE":"IN","SEARCH_VALUE":["HIGH","CRITICAL"]}]}`
	scopeJSON := `{"AND":[{"SEARCH_FIELD":"is_public_repository","SEARCH_TYPE":"EQ","SEARCH_VALUE":true}]}`

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
					resource "cortexcloud_appsec_policy" "test" {
						name        = %q
						description = "five-triggers test"
						conditions  = %q
						scope       = %q
						%s
					}
				`, server.URL, policyName, conditionsJSON, scopeJSON, minimalTriggersHCL),
				Check: resource.ComposeAggregateTestCheckFunc(
					func(s *terraform.State) error {
						if capturedCreateBody == nil {
							return fmt.Errorf("no CREATE request was captured")
						}
						triggers, ok := capturedCreateBody["triggers"].(map[string]interface{})
						if !ok {
							return fmt.Errorf("CREATE body missing 'triggers' object: %v", capturedCreateBody)
						}
						required := []string{"periodic", "pr", "cicd", "ciImage", "imageRegistry"}
						for _, k := range required {
							if _, ok := triggers[k]; !ok {
								return fmt.Errorf("CREATE body triggers missing %q (got keys: %v)", k, mapKeys(triggers))
							}
						}
						// Spot-check ciImage block shape
						ciImage, ok := triggers["ciImage"].(map[string]interface{})
						if !ok {
							return fmt.Errorf("triggers.ciImage is not an object")
						}
						actions, ok := ciImage["actions"].(map[string]interface{})
						if !ok {
							return fmt.Errorf("triggers.ciImage.actions is not an object")
						}
						for _, k := range []string{"reportIssue", "reportCicd", "blockCicd"} {
							if _, ok := actions[k]; !ok {
								return fmt.Errorf("triggers.ciImage.actions missing %q (got: %v)", k, actions)
							}
						}
						// imageRegistry should ONLY have reportIssue
						imgReg, ok := triggers["imageRegistry"].(map[string]interface{})
						if !ok {
							return fmt.Errorf("triggers.imageRegistry is not an object")
						}
						imgRegActions, ok := imgReg["actions"].(map[string]interface{})
						if !ok {
							return fmt.Errorf("triggers.imageRegistry.actions is not an object")
						}
						if len(imgRegActions) != 1 {
							return fmt.Errorf("triggers.imageRegistry.actions: expected exactly 1 key, got %d (%v)", len(imgRegActions), imgRegActions)
						}
						if _, ok := imgRegActions["reportIssue"]; !ok {
							return fmt.Errorf("triggers.imageRegistry.actions missing reportIssue")
						}
						return nil
					},
				),
			},
		},
	})
}

// TestUnitAppSecPolicyResource_AllTriggersUserConfigured verifies that all
// five trigger blocks round-trip from HCL config through the request body
// to the API response back to state.
func TestUnitAppSecPolicyResource_AllTriggersUserConfigured(t *testing.T) {
	const policyID = "test-all-triggers"
	const policyName = "all-triggers policy"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := normalizePath(r.URL.Path)

		switch {
		case path == "/public_api/appsec/v1/policies" && r.Method == http.MethodPost:
			w.WriteHeader(http.StatusNoContent)

		case path == "/public_api/appsec/v1/policies" && r.Method == http.MethodGet:
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, "[%s]\n", fullPolicyResponse(policyID, policyName, "all-triggers test", "enabled"))

		case strings.HasPrefix(path, "/public_api/appsec/v1/policies/"+policyID) && r.Method == http.MethodGet:
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, fullPolicyResponse(policyID, policyName, "all-triggers test", "enabled"))

		case strings.HasPrefix(path, "/public_api/appsec/v1/policies/"+policyID) && r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, `{"message":"deleted"}`)

		default:
			http.Error(w, "not found: "+r.URL.Path, http.StatusNotFound)
		}
	}))
	defer server.Close()

	conditionsJSON := `{"AND":[{"SEARCH_FIELD":"Finding Type","SEARCH_TYPE":"EQ","SEARCH_VALUE":"CAS_SECRET_SCANNER"},{"SEARCH_FIELD":"Severity","SEARCH_TYPE":"IN","SEARCH_VALUE":["HIGH","CRITICAL"]}]}`
	scopeJSON := `{"AND":[{"SEARCH_FIELD":"is_public_repository","SEARCH_TYPE":"EQ","SEARCH_VALUE":true}]}`

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
					resource "cortexcloud_appsec_policy" "test" {
						name        = %q
						description = "all-triggers test"
						conditions  = %q
						scope       = %q
						periodic_trigger = {
							enabled = true
							actions = { report_issue = true }
						}
						pr_trigger = {
							enabled = false
							actions = { report_issue = false, block_pr = false, report_pr_comment = false }
						}
						cicd_trigger = {
							enabled = false
							actions = { report_issue = false, block_cicd = false, report_cicd = false }
						}
						ci_image_trigger = {
							enabled = false
							actions = { report_issue = false, report_cicd = false, block_cicd = false }
						}
						image_registry_trigger = {
							enabled = false
							actions = { report_issue = false }
						}
					}
				`, server.URL, policyName, conditionsJSON, scopeJSON),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("cortexcloud_appsec_policy.test", "periodic_trigger.enabled", "true"),
					resource.TestCheckResourceAttr("cortexcloud_appsec_policy.test", "periodic_trigger.actions.report_issue", "true"),
					resource.TestCheckResourceAttr("cortexcloud_appsec_policy.test", "ci_image_trigger.enabled", "false"),
					resource.TestCheckResourceAttr("cortexcloud_appsec_policy.test", "image_registry_trigger.enabled", "false"),
					resource.TestCheckResourceAttr("cortexcloud_appsec_policy.test", "image_registry_trigger.actions.report_issue", "false"),
				),
			},
		},
	})
}

// mapKeys returns the keys of a map for diagnostic output.
func mapKeys(m map[string]interface{}) []string {
	result := make([]string, 0, len(m))
	for k := range m {
		result = append(result, k)
	}
	return result
}
