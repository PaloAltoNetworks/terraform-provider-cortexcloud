// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package platform_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sync"
	"testing"

	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/provider"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// indicatorMockServer is a tiny in-memory backing store that speaks the
// Cortex indicator API surface (`/insert`, `/get`, `/delete`). It's not a
// full reimplementation — only the fields and behaviors this provider's
// resource exercises are modeled.
type indicatorMockServer struct {
	mu     sync.Mutex
	byName map[string]map[string]any // indicator-string -> record
	nextID int
}

func newIndicatorMockServer() *indicatorMockServer {
	return &indicatorMockServer{
		byName: map[string]map[string]any{},
		nextID: 100,
	}
}

func (m *indicatorMockServer) handler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/public_api/v1/indicators/insert":
			m.handleInsert(t, w, r)
		case "/public_api/v1/indicators/get":
			m.handleGet(t, w, r)
		case "/public_api/v1/indicators/delete":
			m.handleDelete(t, w, r)
		default:
			http.Error(w, "unexpected path: "+r.URL.Path, http.StatusNotFound)
		}
	}
}

func (m *indicatorMockServer) handleInsert(t *testing.T, w http.ResponseWriter, r *http.Request) {
	t.Helper()
	var body struct {
		RequestData []map[string]any `json:"request_data"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	added := []map[string]any{}
	updated := []map[string]any{}

	for _, in := range body.RequestData {
		name, _ := in["indicator"].(string)
		var ruleID int
		if rid, ok := in["rule_id"].(float64); ok && rid > 0 {
			ruleID = int(rid)
		}

		// Upsert semantics: rule_id keys an overwrite; otherwise insert.
		if ruleID > 0 {
			// Locate existing by id (across all stored records).
			for storedName, rec := range m.byName {
				if int(rec["rule_id"].(float64)) == ruleID {
					// Allow indicator-string rename via rule_id key.
					rec = copyRecord(in, ruleID)
					delete(m.byName, storedName)
					m.byName[name] = rec
					updated = append(updated, map[string]any{
						"id":     ruleID,
						"status": fmt.Sprintf("Updated the indicator with the ID: %d successfully", ruleID),
					})
					break
				}
			}
		} else {
			m.nextID++
			ruleID = m.nextID
			m.byName[name] = copyRecord(in, ruleID)
			added = append(added, map[string]any{
				"id":     ruleID,
				"status": fmt.Sprintf("Created a new indicator with the ID: %d successfully", ruleID),
			})
		}
	}

	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"added_objects":   added,
		"updated_objects": updated,
		"errors":          []any{},
	})
}

// copyRecord normalizes the incoming request payload into the canonical
// stored shape — copy known fields, default missing numerics/strings, stamp
// the server-managed read-only fields (creation_time, etc.).
func copyRecord(in map[string]any, ruleID int) map[string]any {
	out := map[string]any{
		"rule_id":                    float64(ruleID),
		"indicator":                  in["indicator"],
		"type":                       in["type"],
		"severity":                   in["severity"],
		"expiration_date":            firstNonNil(in["expiration_date"], float64(-1)),
		"default_expiration_enabled": firstNonNil(in["default_expiration_enabled"], false),
		"comment":                    firstNonNil(in["comment"], ""),
		"reputation":                 firstNonNil(in["reputation"], "UNKNOWN"),
		"reliability":                firstNonNil(in["reliability"], ""),
		"creation_time":              float64(1781000000000),
		"modification_time":          float64(1781000000001),
		"status":                     "ENABLED",
		"source":                     "Public API user (key #1)",
		"number_of_issues":           float64(0),
	}
	return out
}

func firstNonNil(a, b any) any {
	if a == nil {
		return b
	}
	if s, ok := a.(string); ok && s == "" {
		return b
	}
	return a
}

func (m *indicatorMockServer) handleGet(t *testing.T, w http.ResponseWriter, r *http.Request) {
	t.Helper()
	var body struct {
		RequestData struct {
			Filters []struct {
				Field    string `json:"field"`
				Operator string `json:"operator"`
				Value    any    `json:"value"`
			} `json:"filters"`
			ExtendedView bool `json:"extended_view"`
		} `json:"request_data"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	matches := []map[string]any{}
	for _, rec := range m.byName {
		if recordMatches(rec, body.RequestData.Filters) {
			matches = append(matches, rec)
		}
	}

	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"objects_count": len(matches),
		"objects_type":  "indicator",
		"objects":       matches,
	})
}

func recordMatches(rec map[string]any, filters []struct {
	Field    string `json:"field"`
	Operator string `json:"operator"`
	Value    any    `json:"value"`
}) bool {
	for _, f := range filters {
		got := rec[f.Field]
		switch f.Operator {
		case "EQ":
			if fmt.Sprint(got) != fmt.Sprint(f.Value) {
				return false
			}
		default:
			// Mock only models EQ — anything else is treated as
			// matching everything for simplicity.
		}
	}
	return true
}

func (m *indicatorMockServer) handleDelete(t *testing.T, w http.ResponseWriter, r *http.Request) {
	t.Helper()
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

	m.mu.Lock()
	defer m.mu.Unlock()

	deletedIDs := []int{}
	for name, rec := range m.byName {
		if recordMatches(rec, body.RequestData.Filters) {
			deletedIDs = append(deletedIDs, int(rec["rule_id"].(float64)))
			delete(m.byName, name)
		}
	}

	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"objects_count": len(deletedIDs),
		"objects":       deletedIDs,
	})
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

// TestUnitIndicatorResource_Lifecycle covers the steady-state CRUD path:
// create with all fields populated → read-back hydrates the 5 read-only
// fields → in-place update (rule_id-keyed upsert preserves rule_id) →
// implicit delete on test-case teardown.
func TestUnitIndicatorResource_Lifecycle(t *testing.T) {
	mock := newIndicatorMockServer()
	srv := httptest.NewServer(mock.handler(t))
	defer srv.Close()

	const cfgTmpl = `
resource "cortexcloud_indicator" "test" {
  indicator       = "evil.example.com"
  type            = "DOMAIN_NAME"
  severity        = "%s"
  expiration_date = -1
  default_expiration_enabled = true
  reputation      = "BAD"
  reliability     = "C"
  comment         = "%s"
}
`

	resource.Test(t, resource.TestCase{
		IsUnitTest:               true,
		ProtoV6ProviderFactories: newProviderFactories(),
		Steps: []resource.TestStep{
			{
				Config: providerBlock(srv.URL) + fmt.Sprintf(cfgTmpl, "SEV_020_LOW", "initial"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("cortexcloud_indicator.test", "indicator", "evil.example.com"),
					resource.TestCheckResourceAttr("cortexcloud_indicator.test", "id", "evil.example.com"),
					resource.TestCheckResourceAttr("cortexcloud_indicator.test", "type", "DOMAIN_NAME"),
					resource.TestCheckResourceAttr("cortexcloud_indicator.test", "severity", "SEV_020_LOW"),
					resource.TestCheckResourceAttr("cortexcloud_indicator.test", "comment", "initial"),
					// Read-only fields hydrated from the server stub.
					resource.TestCheckResourceAttr("cortexcloud_indicator.test", "status", "ENABLED"),
					resource.TestCheckResourceAttr("cortexcloud_indicator.test", "source", "Public API user (key #1)"),
					resource.TestCheckResourceAttrSet("cortexcloud_indicator.test", "rule_id"),
					resource.TestCheckResourceAttrSet("cortexcloud_indicator.test", "creation_time"),
				),
			},
			// In-place update (severity + comment change). rule_id must
			// be stable across the upsert.
			{
				Config: providerBlock(srv.URL) + fmt.Sprintf(cfgTmpl, "SEV_050_CRITICAL", "updated"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("cortexcloud_indicator.test", "severity", "SEV_050_CRITICAL"),
					resource.TestCheckResourceAttr("cortexcloud_indicator.test", "comment", "updated"),
					// rule_id is set to 101 because it's the first record
					// the mock allocates (nextID starts at 100, ++ = 101).
					resource.TestCheckResourceAttr("cortexcloud_indicator.test", "rule_id", "101"),
				),
			},
		},
	})
}

// TestUnitIndicatorResource_Rename covers the delete-old + insert-new
// branch of Update: when the `indicator` string changes, the provider
// deletes the old record by name and inserts a fresh one (no rule_id), so
// the new record gets a new rule_id.
func TestUnitIndicatorResource_Rename(t *testing.T) {
	mock := newIndicatorMockServer()
	srv := httptest.NewServer(mock.handler(t))
	defer srv.Close()

	const cfgTmpl = `
resource "cortexcloud_indicator" "test" {
  indicator = "%s"
  type      = "DOMAIN_NAME"
  severity  = "SEV_020_LOW"
}
`

	resource.Test(t, resource.TestCase{
		IsUnitTest:               true,
		ProtoV6ProviderFactories: newProviderFactories(),
		Steps: []resource.TestStep{
			{
				Config: providerBlock(srv.URL) + fmt.Sprintf(cfgTmpl, "old.example.com"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("cortexcloud_indicator.test", "indicator", "old.example.com"),
					resource.TestCheckResourceAttr("cortexcloud_indicator.test", "rule_id", "101"),
				),
			},
			{
				Config: providerBlock(srv.URL) + fmt.Sprintf(cfgTmpl, "new.example.com"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("cortexcloud_indicator.test", "indicator", "new.example.com"),
					// Rename takes the delete-then-insert path, so the new
					// record gets a freshly allocated rule_id (102).
					resource.TestCheckResourceAttr("cortexcloud_indicator.test", "rule_id", "102"),
				),
			},
		},
	})
}

// TestUnitIndicatorResource_AdoptOnCollision pre-plants a record in the
// mock store, then runs Create — the provider should detect the existing
// record via FindIndicatorByName, adopt its rule_id, and upsert in place
// rather than failing with "IOC indicator exists".
func TestUnitIndicatorResource_AdoptOnCollision(t *testing.T) {
	mock := newIndicatorMockServer()
	// Pre-plant a record with rule_id=42.
	mock.byName["preplanted.example.com"] = map[string]any{
		"rule_id":                    float64(42),
		"indicator":                  "preplanted.example.com",
		"type":                       "DOMAIN_NAME",
		"severity":                   "SEV_020_LOW",
		"expiration_date":            float64(-1),
		"default_expiration_enabled": true,
		"comment":                    "out-of-band",
		"reputation":                 "UNKNOWN",
		"reliability":                "",
		"creation_time":              float64(1780000000000),
		"modification_time":          float64(1780000000001),
		"status":                     "ENABLED",
		"source":                     "out-of-band-creator",
		"number_of_issues":           float64(0),
	}

	srv := httptest.NewServer(mock.handler(t))
	defer srv.Close()

	resource.Test(t, resource.TestCase{
		IsUnitTest:               true,
		ProtoV6ProviderFactories: newProviderFactories(),
		Steps: []resource.TestStep{
			{
				Config: providerBlock(srv.URL) + `
resource "cortexcloud_indicator" "test" {
  indicator = "preplanted.example.com"
  type      = "DOMAIN_NAME"
  severity  = "SEV_030_MEDIUM"
  comment   = "tf-managed now"
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("cortexcloud_indicator.test", "rule_id", "42"),
					resource.TestCheckResourceAttr("cortexcloud_indicator.test", "severity", "SEV_030_MEDIUM"),
					resource.TestCheckResourceAttr("cortexcloud_indicator.test", "comment", "tf-managed now"),
				),
			},
		},
	})
}

// TestUnitIndicatorResource_ValidatorRejectsUnknownType pins the
// stringvalidator.OneOf wiring: an unknown `type` value is rejected at
// plan-time without reaching the API.
func TestUnitIndicatorResource_ValidatorRejectsUnknownType(t *testing.T) {
	mock := newIndicatorMockServer()
	srv := httptest.NewServer(mock.handler(t))
	defer srv.Close()

	resource.Test(t, resource.TestCase{
		IsUnitTest:               true,
		ProtoV6ProviderFactories: newProviderFactories(),
		Steps: []resource.TestStep{
			{
				Config: providerBlock(srv.URL) + `
resource "cortexcloud_indicator" "test" {
  indicator = "x"
  type      = "BOGUS_TYPE"
  severity  = "SEV_020_LOW"
}
`,
				ExpectError: regexp.MustCompile(`Attribute type value must be one of`),
			},
		},
	})
}
