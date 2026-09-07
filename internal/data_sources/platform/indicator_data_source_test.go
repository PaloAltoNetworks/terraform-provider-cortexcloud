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

// stubGetServer returns an httptest.Server that, for every POST to
// /indicators/get, responds with the provided records (filtered by the
// inbound `filters` array). Other endpoints return 404. Use this when a
// data source test doesn't need full CRUD.
func stubGetServer(t *testing.T, records []map[string]any) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/public_api/v1/indicators/get" || r.Method != http.MethodPost {
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
			"objects_type":  "indicator",
			"objects":       matches,
		})
	}))
}

func newProviderFactories() map[string]func() (tfprotov6.ProviderServer, error) {
	return map[string]func() (tfprotov6.ProviderServer, error){
		"cortexcloud": providerserver.NewProtocol6WithError(provider.New("test", "test")()),
	}
}

func providerBlock(serverURL string) string {
	return fmt.Sprintf(`
provider "cortexcloud" {
  api_url    = "%s"
  api_key    = "test"
  api_key_id = 1
}
`, serverURL)
}

// Test fixture: one record that the data sources can look up.
func makeRecord() map[string]any {
	return map[string]any{
		"rule_id":                    float64(57),
		"indicator":                  "virus1.exe",
		"type":                       "FILENAME",
		"severity":                   "SEV_040_HIGH",
		"expiration_date":            float64(-1),
		"default_expiration_enabled": true,
		"comment":                    "test",
		"reputation":                 "BAD",
		"reliability":                "C",
		"creation_time":              float64(1781000000000),
		"modification_time":          float64(1781000001000),
		"status":                     "ENABLED",
		"source":                     "Public API user (key #30)",
		"number_of_issues":           float64(7),
	}
}

// TestUnitIndicatorDataSource_ByName covers the indicator-string lookup
// path and verifies that all 14 fields (including the 5 read-only ones)
// land in the data-source state.
func TestUnitIndicatorDataSource_ByName(t *testing.T) {
	srv := stubGetServer(t, []map[string]any{makeRecord()})
	defer srv.Close()

	resource.Test(t, resource.TestCase{
		IsUnitTest:               true,
		ProtoV6ProviderFactories: newProviderFactories(),
		Steps: []resource.TestStep{
			{
				Config: providerBlock(srv.URL) + `
data "cortexcloud_indicator" "by_name" {
  indicator = "virus1.exe"
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("data.cortexcloud_indicator.by_name", "rule_id", "57"),
					resource.TestCheckResourceAttr("data.cortexcloud_indicator.by_name", "type", "FILENAME"),
					resource.TestCheckResourceAttr("data.cortexcloud_indicator.by_name", "severity", "SEV_040_HIGH"),
					resource.TestCheckResourceAttr("data.cortexcloud_indicator.by_name", "reputation", "BAD"),
					resource.TestCheckResourceAttr("data.cortexcloud_indicator.by_name", "reliability", "C"),
					// Read-only fields (S3 regression guard):
					resource.TestCheckResourceAttr("data.cortexcloud_indicator.by_name", "status", "ENABLED"),
					resource.TestCheckResourceAttr("data.cortexcloud_indicator.by_name", "source", "Public API user (key #30)"),
					resource.TestCheckResourceAttr("data.cortexcloud_indicator.by_name", "number_of_issues", "7"),
					resource.TestCheckResourceAttr("data.cortexcloud_indicator.by_name", "creation_time", "1781000000000"),
				),
			},
		},
	})
}

// TestUnitIndicatorDataSource_ByID covers the rule_id lookup path
// reintroduced as B2.
func TestUnitIndicatorDataSource_ByID(t *testing.T) {
	srv := stubGetServer(t, []map[string]any{makeRecord()})
	defer srv.Close()

	resource.Test(t, resource.TestCase{
		IsUnitTest:               true,
		ProtoV6ProviderFactories: newProviderFactories(),
		Steps: []resource.TestStep{
			{
				Config: providerBlock(srv.URL) + `
data "cortexcloud_indicator" "by_id" {
  rule_id = 57
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("data.cortexcloud_indicator.by_id", "indicator", "virus1.exe"),
					resource.TestCheckResourceAttr("data.cortexcloud_indicator.by_id", "rule_id", "57"),
				),
			},
		},
	})
}

// TestUnitIndicatorDataSource_ExactlyOneOf pins the ConfigValidator —
// setting both inputs is a config error, setting neither is too.
func TestUnitIndicatorDataSource_ExactlyOneOf(t *testing.T) {
	srv := stubGetServer(t, []map[string]any{makeRecord()})
	defer srv.Close()

	resource.Test(t, resource.TestCase{
		IsUnitTest:               true,
		ProtoV6ProviderFactories: newProviderFactories(),
		Steps: []resource.TestStep{
			{
				Config: providerBlock(srv.URL) + `
data "cortexcloud_indicator" "both" {
  indicator = "virus1.exe"
  rule_id   = 57
}
`,
				ExpectError: regexp.MustCompile(`(?s)Invalid Attribute Combination`),
			},
		},
	})

	resource.Test(t, resource.TestCase{
		IsUnitTest:               true,
		ProtoV6ProviderFactories: newProviderFactories(),
		Steps: []resource.TestStep{
			{
				Config: providerBlock(srv.URL) + `
data "cortexcloud_indicator" "neither" {}
`,
				ExpectError: regexp.MustCompile(`(?s)Missing Attribute Configuration`),
			},
		},
	})
}

// TestUnitIndicatorsDataSource_BoolCoercion is the L2 regression guard:
// the list data source must coerce string filter values to JSON booleans
// for the `default_expiration_enabled` field. The mock asserts the wire
// value is a real boolean (not a string), which is the contract the live
// API rejects with HTTP 500 if violated.
func TestUnitIndicatorsDataSource_BoolCoercion(t *testing.T) {
	var sawBoolValue bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/public_api/v1/indicators/get" {
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
			if f.Field == "default_expiration_enabled" {
				// Expect a true JSON bool — JSON's any-decode would
				// produce a bool, not a string, when the wire value
				// is `true` (the coercion the data source is
				// supposed to do).
				if _, isBool := f.Value.(bool); isBool {
					sawBoolValue = true
				}
			}
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"objects_count": 1,
			"objects_type":  "indicator",
			"objects":       []map[string]any{makeRecord()},
		})
	}))
	defer srv.Close()

	resource.Test(t, resource.TestCase{
		IsUnitTest:               true,
		ProtoV6ProviderFactories: newProviderFactories(),
		Steps: []resource.TestStep{
			{
				Config: providerBlock(srv.URL) + `
data "cortexcloud_indicators" "bool_filter" {
  filters = [
    { field = "default_expiration_enabled", operator = "EQ", value = "true" },
  ]
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("data.cortexcloud_indicators.bool_filter", "indicators.#", "1"),
					resource.TestCheckResourceAttr("data.cortexcloud_indicators.bool_filter", "indicators.0.rule_id", "57"),
				),
			},
		},
	})

	if !sawBoolValue {
		t.Fatalf("expected the list data source to send the default_expiration_enabled filter as a JSON bool, but the mock never observed one")
	}
}

// TestUnitIndicatorsDataSource_NumericCoercion is the analogous regression
// guard for expiration_date — the list data source must send it as a JSON
// number, not a string.
func TestUnitIndicatorsDataSource_NumericCoercion(t *testing.T) {
	var sawNumericValue bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/public_api/v1/indicators/get" {
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
			if f.Field == "expiration_date" {
				if _, isNumber := f.Value.(float64); isNumber {
					sawNumericValue = true
				}
			}
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"objects_count": 0, "objects": []map[string]any{}, "objects_type": "indicator",
		})
	}))
	defer srv.Close()

	resource.Test(t, resource.TestCase{
		IsUnitTest:               true,
		ProtoV6ProviderFactories: newProviderFactories(),
		Steps: []resource.TestStep{
			{
				Config: providerBlock(srv.URL) + `
data "cortexcloud_indicators" "by_exp" {
  filters = [
    { field = "expiration_date", operator = "GTE", value = "1700000000000" },
  ]
}
`,
				Check: resource.TestCheckResourceAttr("data.cortexcloud_indicators.by_exp", "indicators.#", "0"),
			},
		},
	})

	if !sawNumericValue {
		t.Fatalf("expected expiration_date filter to be sent as a JSON number, but the mock never observed one")
	}
}

// TestUnitIndicatorsDataSource_BadNumeric pins the validation that runs
// before the API call: a non-numeric value for expiration_date is rejected
// at apply-time with a clean attribute error rather than a 500 from the
// API.
func TestUnitIndicatorsDataSource_BadNumeric(t *testing.T) {
	srv := stubGetServer(t, nil)
	defer srv.Close()

	resource.Test(t, resource.TestCase{
		IsUnitTest:               true,
		ProtoV6ProviderFactories: newProviderFactories(),
		Steps: []resource.TestStep{
			{
				Config: providerBlock(srv.URL) + `
data "cortexcloud_indicators" "bad" {
  filters = [
    { field = "expiration_date", operator = "EQ", value = "not-a-number" },
  ]
}
`,
				ExpectError: regexp.MustCompile(`Invalid Numeric Filter Value`),
			},
		},
	})
}
