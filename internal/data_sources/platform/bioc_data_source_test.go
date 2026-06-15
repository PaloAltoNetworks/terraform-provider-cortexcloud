// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package platform_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"

	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/provider"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// biocStubGetServer returns an httptest.Server that, for every POST to
// /bioc/get, responds with the provided records (filtered by the inbound
// `filters` array). Other endpoints return 404.
func biocStubGetServer(t *testing.T, records []map[string]any) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/public_api/v1/bioc/get" || r.Method != http.MethodPost {
			http.Error(w, "unexpected: "+r.Method+" "+r.URL.Path, http.StatusNotFound)
			return
		}
		var body struct {
			RequestData struct {
				Filters []struct {
					Field    string `json:"field"`
					Operator string `json:"operator"`
					Value    any    `json:"value"`
				} `json:"filters"`
			} `json:"request_data"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		matches := []map[string]any{}
		for _, rec := range records {
			ok := true
			for _, f := range body.RequestData.Filters {
				if fmt.Sprint(rec[f.Field]) != fmt.Sprint(f.Value) {
					ok = false
					break
				}
			}
			if ok {
				matches = append(matches, rec)
			}
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"objects_count": len(matches),
			"objects_type":  "bioc",
			"objects":       matches,
		})
	}))
}

func newBIOCProviderFactories() map[string]func() (tfprotov6.ProviderServer, error) {
	return map[string]func() (tfprotov6.ProviderServer, error){
		"cortexcloud": providerserver.NewProtocol6WithError(provider.New("test", "test")()),
	}
}

func biocProviderBlock(serverURL string) string {
	return fmt.Sprintf(`
provider "cortexcloud" {
  api_url    = "%s"
  api_key    = "test"
  api_key_id = 1
}
`, serverURL)
}

// makeBIOCRecord is the test fixture used by single-lookup tests.
func makeBIOCRecord() map[string]any {
	return map[string]any{
		"rule_id":   float64(57),
		"name":      "test-bioc",
		"type":      "EXECUTION",
		"severity":  "SEV_040_HIGH",
		"status":    "ENABLED",
		"comment":   "audit",
		"is_xql":    true,
		"indicator": "dataset = xdr_data | filter event_type = 1",
		"mitre_tactic_id_and_name": []any{
			"TA0001 - Initial Access",
		},
		"mitre_technique_id_and_name": []any{
			"T1059 - Command and Scripting Interpreter",
		},
		"creation_time":     float64(1781000000000),
		"modification_time": float64(1781000001000),
		"source":            "Public API user (key #30)",
		"number_of_issues":  float64(7),
	}
}

// TestUnitBIOCDataSource_ByName covers the name lookup path. The data
// source returns the first match the API surfaces (BIOC names are not
// unique per tenant).
func TestUnitBIOCDataSource_ByName(t *testing.T) {
	srv := biocStubGetServer(t, []map[string]any{makeBIOCRecord()})
	defer srv.Close()

	resource.Test(t, resource.TestCase{
		IsUnitTest:               true,
		ProtoV6ProviderFactories: newBIOCProviderFactories(),
		Steps: []resource.TestStep{
			{
				Config: biocProviderBlock(srv.URL) + `
data "cortexcloud_bioc" "by_name" {
  name = "test-bioc"
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("data.cortexcloud_bioc.by_name", "rule_id", "57"),
					resource.TestCheckResourceAttr("data.cortexcloud_bioc.by_name", "type", "EXECUTION"),
					resource.TestCheckResourceAttr("data.cortexcloud_bioc.by_name", "severity", "SEV_040_HIGH"),
					// Status normalized to lowercase on read.
					resource.TestCheckResourceAttr("data.cortexcloud_bioc.by_name", "status", "enabled"),
					resource.TestCheckResourceAttr("data.cortexcloud_bioc.by_name", "is_xql", "true"),
					resource.TestCheckResourceAttr("data.cortexcloud_bioc.by_name", "xql_query", "dataset = xdr_data | filter event_type = 1"),
					// Read-only fields:
					resource.TestCheckResourceAttr("data.cortexcloud_bioc.by_name", "source", "Public API user (key #30)"),
					resource.TestCheckResourceAttr("data.cortexcloud_bioc.by_name", "number_of_issues", "7"),
					resource.TestCheckResourceAttr("data.cortexcloud_bioc.by_name", "creation_time", "1781000000000"),
				),
			},
		},
	})
}

// TestUnitBIOCDataSource_ByID covers the rule_id lookup path — the only
// safe identity-based lookup for BIOCs.
func TestUnitBIOCDataSource_ByID(t *testing.T) {
	srv := biocStubGetServer(t, []map[string]any{makeBIOCRecord()})
	defer srv.Close()

	resource.Test(t, resource.TestCase{
		IsUnitTest:               true,
		ProtoV6ProviderFactories: newBIOCProviderFactories(),
		Steps: []resource.TestStep{
			{
				Config: biocProviderBlock(srv.URL) + `
data "cortexcloud_bioc" "by_id" {
  rule_id = 57
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("data.cortexcloud_bioc.by_id", "name", "test-bioc"),
					resource.TestCheckResourceAttr("data.cortexcloud_bioc.by_id", "rule_id", "57"),
				),
			},
		},
	})
}

// TestUnitBIOCDataSource_ExactlyOneOf pins the ConfigValidator — setting
// both inputs is a config error, setting neither is too.
func TestUnitBIOCDataSource_ExactlyOneOf(t *testing.T) {
	srv := biocStubGetServer(t, []map[string]any{makeBIOCRecord()})
	defer srv.Close()

	resource.Test(t, resource.TestCase{
		IsUnitTest:               true,
		ProtoV6ProviderFactories: newBIOCProviderFactories(),
		Steps: []resource.TestStep{
			{
				Config: biocProviderBlock(srv.URL) + `
data "cortexcloud_bioc" "both" {
  name    = "test-bioc"
  rule_id = 57
}
`,
				ExpectError: regexp.MustCompile(`(?s)Invalid Attribute Combination`),
			},
		},
	})

	resource.Test(t, resource.TestCase{
		IsUnitTest:               true,
		ProtoV6ProviderFactories: newBIOCProviderFactories(),
		Steps: []resource.TestStep{
			{
				Config: biocProviderBlock(srv.URL) + `
data "cortexcloud_bioc" "neither" {}
`,
				ExpectError: regexp.MustCompile(`(?s)Missing Attribute Configuration`),
			},
		},
	})
}

// TestUnitBIOCsDataSource_NumericCoercion pins that the list data source
// coerces string filter values to JSON numbers for the `rule_id` field.
// Sending it as a string would produce a server-side type error.
func TestUnitBIOCsDataSource_NumericCoercion(t *testing.T) {
	var sawNumericValue bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/public_api/v1/bioc/get" {
			http.Error(w, "unexpected: "+r.URL.Path, http.StatusNotFound)
			return
		}
		var body struct {
			RequestData struct {
				Filters []struct {
					Field    string `json:"field"`
					Operator string `json:"operator"`
					Value    any    `json:"value"`
				} `json:"filters"`
			} `json:"request_data"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		for _, f := range body.RequestData.Filters {
			if f.Field == "rule_id" {
				if _, isNumber := f.Value.(float64); isNumber {
					sawNumericValue = true
				}
			}
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"objects_count": 1,
			"objects_type":  "bioc",
			"objects":       []map[string]any{makeBIOCRecord()},
		})
	}))
	defer srv.Close()

	resource.Test(t, resource.TestCase{
		IsUnitTest:               true,
		ProtoV6ProviderFactories: newBIOCProviderFactories(),
		Steps: []resource.TestStep{
			{
				Config: biocProviderBlock(srv.URL) + `
data "cortexcloud_biocs" "by_id" {
  filters = [
    { field = "rule_id", operator = "EQ", value = "57" },
  ]
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("data.cortexcloud_biocs.by_id", "biocs.#", "1"),
					resource.TestCheckResourceAttr("data.cortexcloud_biocs.by_id", "biocs.0.rule_id", "57"),
				),
			},
		},
	})

	if !sawNumericValue {
		t.Fatalf("expected rule_id filter to be sent as a JSON number, but the mock never observed one")
	}
}

// TestUnitBIOCsDataSource_BoolCoercion pins that the list data source
// coerces string filter values to JSON booleans for the `is_xql` field.
func TestUnitBIOCsDataSource_BoolCoercion(t *testing.T) {
	var sawBoolValue bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/public_api/v1/bioc/get" {
			http.Error(w, "unexpected: "+r.URL.Path, http.StatusNotFound)
			return
		}
		var body struct {
			RequestData struct {
				Filters []struct {
					Field    string `json:"field"`
					Operator string `json:"operator"`
					Value    any    `json:"value"`
				} `json:"filters"`
			} `json:"request_data"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		for _, f := range body.RequestData.Filters {
			if f.Field == "is_xql" {
				if _, isBool := f.Value.(bool); isBool {
					sawBoolValue = true
				}
			}
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"objects_count": 0, "objects": []map[string]any{}, "objects_type": "bioc",
		})
	}))
	defer srv.Close()

	resource.Test(t, resource.TestCase{
		IsUnitTest:               true,
		ProtoV6ProviderFactories: newBIOCProviderFactories(),
		Steps: []resource.TestStep{
			{
				Config: biocProviderBlock(srv.URL) + `
data "cortexcloud_biocs" "xql_only" {
  filters = [
    { field = "is_xql", operator = "EQ", value = "true" },
  ]
}
`,
				Check: resource.TestCheckResourceAttr("data.cortexcloud_biocs.xql_only", "biocs.#", "0"),
			},
		},
	})

	if !sawBoolValue {
		t.Fatalf("expected is_xql filter to be sent as a JSON bool, but the mock never observed one")
	}
}

// TestUnitBIOCsDataSource_BadNumeric pins the validation: a non-numeric
// value for rule_id is rejected at apply-time with a clean attribute
// error rather than a 500 from the API.
func TestUnitBIOCsDataSource_BadNumeric(t *testing.T) {
	srv := biocStubGetServer(t, nil)
	defer srv.Close()

	resource.Test(t, resource.TestCase{
		IsUnitTest:               true,
		ProtoV6ProviderFactories: newBIOCProviderFactories(),
		Steps: []resource.TestStep{
			{
				Config: biocProviderBlock(srv.URL) + `
data "cortexcloud_biocs" "bad" {
  filters = [
    { field = "rule_id", operator = "EQ", value = "not-a-number" },
  ]
}
`,
				ExpectError: regexp.MustCompile(`Invalid Numeric Filter Value`),
			},
		},
	})
}
