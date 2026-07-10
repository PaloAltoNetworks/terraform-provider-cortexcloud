// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package appsec_test

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

// ruleGetBody is the flat JSON body returned by the AppSec rule GET endpoint.
// The API never returns cspm_rule_id on read (it is a write-only field), which
// is why the data source schema must declare it as Computed so the shared
// RuleModel struct can be decoded without a struct/object mismatch.
const ruleGetBody = `{
	"id": "rule-cspm-ds-test",
	"name": "cspm mapped rule",
	"description": "rule mapped to a cspm rule",
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
}`

// TestUnitAppSecRuleDataSource_Read verifies the singular data source can read a
// rule without crashing. Before cspm_rule_id was added to the data source schema,
// this failed with "Struct defines fields not found in object: cspm_rule_id"
// because the shared RuleModel struct carries the field but the schema did not.
func TestUnitAppSecRuleDataSource_Read(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		for strings.Contains(path, "//") {
			path = strings.ReplaceAll(path, "//", "/")
		}

		switch {
		case strings.HasPrefix(path, "/public_api/appsec/v1/rules/rule-cspm-ds-test") && r.Method == http.MethodGet:
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, ruleGetBody)

		default:
			http.Error(w, "not found: "+r.URL.Path, http.StatusNotFound)
		}
	}))
	defer server.Close()

	resource.Test(t, resource.TestCase{
		IsUnitTest: true,
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"cortexcloud": providerserver.NewProtocol6WithError(provider.New("test", "test")()),
		},
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
					provider "cortexcloud" {
						api_url    = "%s"
						api_key    = "test"
						api_key_id = 123
					}
					data "cortexcloud_appsec_rule" "test" {
						id = "rule-cspm-ds-test"
					}
				`, server.URL),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("data.cortexcloud_appsec_rule.test", "id", "rule-cspm-ds-test"),
					resource.TestCheckResourceAttr("data.cortexcloud_appsec_rule.test", "name", "cspm mapped rule"),
					resource.TestCheckResourceAttr("data.cortexcloud_appsec_rule.test", "severity", "HIGH"),
					// cspm_rule_id is write-only; the API does not return it on read,
					// so the data source exposes it as null.
					resource.TestCheckNoResourceAttr("data.cortexcloud_appsec_rule.test", "cspm_rule_id"),
				),
			},
		},
	})
}

// TestUnitAppSecRulesDataSource_Read verifies the plural (list) data source can
// read rules without crashing. The list model's Rules field is []RuleModel, so
// the nested "rules" object in the schema must also declare cspm_rule_id.
func TestUnitAppSecRulesDataSource_Read(t *testing.T) {
	listBody := fmt.Sprintf(`{
		"offset": 0,
		"nextOffset": null,
		"rules": [%s]
	}`, ruleGetBody)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		for strings.Contains(path, "//") {
			path = strings.ReplaceAll(path, "//", "/")
		}
		if strings.HasSuffix(path, "/") && path != "/" {
			path = strings.TrimSuffix(path, "/")
		}

		switch {
		case path == "/public_api/appsec/v1/rules" && r.Method == http.MethodGet:
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, listBody)

		default:
			http.Error(w, "not found: "+r.URL.Path, http.StatusNotFound)
		}
	}))
	defer server.Close()

	resource.Test(t, resource.TestCase{
		IsUnitTest: true,
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"cortexcloud": providerserver.NewProtocol6WithError(provider.New("test", "test")()),
		},
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
					provider "cortexcloud" {
						api_url    = "%s"
						api_key    = "test"
						api_key_id = 123
					}
					data "cortexcloud_appsec_rules" "test" {
						is_custom = true
					}
				`, server.URL),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("data.cortexcloud_appsec_rules.test", "rules.#", "1"),
					resource.TestCheckResourceAttr("data.cortexcloud_appsec_rules.test", "rules.0.id", "rule-cspm-ds-test"),
					resource.TestCheckResourceAttr("data.cortexcloud_appsec_rules.test", "rules.0.name", "cspm mapped rule"),
					// cspm_rule_id is write-only; null in list output.
					resource.TestCheckNoResourceAttr("data.cortexcloud_appsec_rules.test", "rules.0.cspm_rule_id"),
				),
			},
		},
	})
}
