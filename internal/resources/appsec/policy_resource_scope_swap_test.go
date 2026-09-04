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

// policyResponseWithAssetGroups returns a policy response whose scope and
// assetGroupIds are supplied by the caller, so a fake server can model the
// full-replace semantics of the real API.
func policyResponseWithAssetGroups(id, name, scopeJSON, assetGroupIDsJSON string) string {
	return fmt.Sprintf(`{
		"id": %q,
		"name": %q,
		"description": "swap scope and asset groups",
		"status": "enabled",
		"isCustom": true,
		"conditions": {
			"AND": [
				{"SEARCH_FIELD": "Finding Type", "SEARCH_TYPE": "EQ", "SEARCH_VALUE": "CAS_SECRET_SCANNER"}
			]
		},
		"scope": %s,
		"assetGroupIds": %s,
		"triggers": {
			"periodic":      {"isEnabled": true,  "actions": {"reportIssue": true},                                              "overrideIssueSeverity": null},
			"pr":            {"isEnabled": false, "actions": {"reportIssue": false, "blockPr": false, "reportPrComment": false}, "overrideIssueSeverity": null},
			"cicd":          {"isEnabled": false, "actions": {"reportIssue": false, "blockCicd": false, "reportCicd": false},    "overrideIssueSeverity": null},
			"ciImage":       {"isEnabled": false, "actions": {"reportIssue": false, "reportCicd": false, "blockCicd": false},    "overrideIssueSeverity": null},
			"imageRegistry": {"isEnabled": false, "actions": {"reportIssue": false},                                             "overrideIssueSeverity": null}
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
	}`, id, name, scopeJSON, assetGroupIDsJSON)
}

// TestUnitAppSecPolicyResource_SwapAssetGroupIdsForScope covers the case where
// a user replaces an asset-group association with a scope: asset_group_ids is
// deleted from the configuration and scope is added in the same apply.
//
// Because asset_group_ids is Optional+Computed, removing it leaves the planned
// value unknown, and an unknown is dropped from the update request. The
// previously associated asset groups therefore survived on the server and kept
// masking the new scope, so the change appeared to have no effect.
//
// The fake server models the real full-replace PUT semantics: an absent
// assetGroupIds key clears the association. The assertions check both the
// request that goes out and the state that comes back.
func TestUnitAppSecPolicyResource_SwapAssetGroupIdsForScope(t *testing.T) {
	const policyID = "test-policy-swap-scope"
	const policyName = "Swap asset groups for scope"

	var capturedUpdateBody map[string]interface{}
	var updateSeen bool

	// Server-side state, mutated by PUT exactly as the real API does.
	currentScope := "{}"
	currentAssetGroupIDs := "[56]"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := normalizePath(r.URL.Path)

		switch {
		case path == "/public_api/appsec/v1/policies" && r.Method == http.MethodPost:
			// Creation associates the policy with asset group 56 and no scope.
			currentScope = "{}"
			currentAssetGroupIDs = "[56]"
			w.WriteHeader(http.StatusNoContent)

		case path == "/public_api/appsec/v1/policies" && r.Method == http.MethodGet:
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, "[%s]\n", policyResponseWithAssetGroups(policyID, policyName, currentScope, currentAssetGroupIDs))

		case strings.HasPrefix(path, "/public_api/appsec/v1/policies/"+policyID) && r.Method == http.MethodGet:
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, policyResponseWithAssetGroups(policyID, policyName, currentScope, currentAssetGroupIDs))

		case strings.HasPrefix(path, "/public_api/appsec/v1/policies/"+policyID) && r.Method == http.MethodPut:
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			capturedUpdateBody = nil
			if err := json.Unmarshal(body, &capturedUpdateBody); err != nil {
				http.Error(w, "invalid json", http.StatusBadRequest)
				return
			}
			updateSeen = true

			// Full-replace semantics: an absent key clears the stored value.
			if raw, ok := capturedUpdateBody["assetGroupIds"]; ok {
				encoded, err := json.Marshal(raw)
				if err != nil {
					http.Error(w, "bad assetGroupIds", http.StatusBadRequest)
					return
				}
				currentAssetGroupIDs = string(encoded)
			} else {
				currentAssetGroupIDs = "[]"
			}

			if raw, ok := capturedUpdateBody["scope"]; ok {
				encoded, err := json.Marshal(raw)
				if err != nil {
					http.Error(w, "bad scope", http.StatusBadRequest)
					return
				}
				currentScope = string(encoded)
			} else {
				currentScope = "{}"
			}

			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, policyResponseWithAssetGroups(policyID, policyName, currentScope, currentAssetGroupIDs))

		case strings.HasPrefix(path, "/public_api/appsec/v1/policies/"+policyID) && r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, `{"message":"deleted"}`)

		default:
			http.Error(w, "not found: "+r.URL.Path, http.StatusNotFound)
		}
	}))
	defer server.Close()

	conditionsJSON := `{"AND":[{"SEARCH_FIELD":"Finding Type","SEARCH_TYPE":"EQ","SEARCH_VALUE":"CAS_SECRET_SCANNER"}]}`
	scopeJSON := `{"AND":[{"SEARCH_FIELD":"is_public_repository","SEARCH_TYPE":"EQ","SEARCH_VALUE":true}]}`

	resource.Test(t, resource.TestCase{
		IsUnitTest: true,
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"cortexcloud": providerserver.NewProtocol6WithError(provider.New("test", "test")()),
		},
		Steps: []resource.TestStep{
			// Step 1 - asset groups only, no scope.
			{
				Config: fmt.Sprintf(`
					provider "cortexcloud" {
						api_url    = "%s"
						api_key    = "test"
						api_key_id = 123
					}
					resource "cortexcloud_appsec_policy" "test" {
						name            = %q
						description     = "swap scope and asset groups"
						status          = "enabled"
						conditions      = %q
						asset_group_ids = [56]
						%s
					}
				`, server.URL, policyName, conditionsJSON, minimalTriggersHCL),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("cortexcloud_appsec_policy.test", "asset_group_ids.#", "1"),
					resource.TestCheckResourceAttr("cortexcloud_appsec_policy.test", "asset_group_ids.0", "56"),
				),
			},
			// Step 2 - the swap: asset_group_ids removed, scope added.
			{
				Config: fmt.Sprintf(`
					provider "cortexcloud" {
						api_url    = "%s"
						api_key    = "test"
						api_key_id = 123
					}
					resource "cortexcloud_appsec_policy" "test" {
						name        = %q
						description = "swap scope and asset groups"
						status      = "enabled"
						conditions  = %q
						scope       = %q
						%s
					}
				`, server.URL, policyName, conditionsJSON, scopeJSON, minimalTriggersHCL),
				Check: resource.ComposeAggregateTestCheckFunc(
					// The association must be gone from state, not resurrected.
					resource.TestCheckResourceAttr("cortexcloud_appsec_policy.test", "asset_group_ids.#", "0"),
					func(s *terraform.State) error {
						if !updateSeen || capturedUpdateBody == nil {
							return fmt.Errorf("no update request was captured")
						}
						// The whole point: the stale [56] must not be sent.
						// An empty slice is dropped by omitempty, so the key
						// being absent is what clears the association.
						if v, ok := capturedUpdateBody["assetGroupIds"]; ok {
							return fmt.Errorf("update body must not carry assetGroupIds when the attribute was removed from config; got %v", v)
						}
						if _, ok := capturedUpdateBody["scope"]; !ok {
							return fmt.Errorf("update body missing 'scope'; got keys: %v", mapKeys(capturedUpdateBody))
						}
						// And the server must genuinely have cleared it.
						if currentAssetGroupIDs != "[]" {
							return fmt.Errorf("server still holds assetGroupIds=%s, want []", currentAssetGroupIDs)
						}
						return nil
					},
				),
			},
		},
	})
}
