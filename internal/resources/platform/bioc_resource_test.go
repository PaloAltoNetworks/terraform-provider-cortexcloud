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

// biocMockServer is an in-memory backing store that speaks the Cortex BIOC
// API surface (`/insert`, `/get`, `/delete`). Unlike the IOC mock, records
// are keyed by rule_id (the canonical identity) since BIOC names are not
// unique per tenant.
type biocMockServer struct {
	mu     sync.Mutex
	byID   map[int]map[string]any
	nextID int
}

func newBIOCMockServer() *biocMockServer {
	return &biocMockServer{
		byID:   map[int]map[string]any{},
		nextID: 100,
	}
}

func (m *biocMockServer) handler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/public_api/v1/bioc/insert":
			m.handleInsert(t, w, r)
		case "/public_api/v1/bioc/get":
			m.handleGet(t, w, r)
		case "/public_api/v1/bioc/delete":
			m.handleDelete(t, w, r)
		default:
			http.Error(w, "unexpected path: "+r.URL.Path, http.StatusNotFound)
		}
	}
}

func (m *biocMockServer) handleInsert(t *testing.T, w http.ResponseWriter, r *http.Request) {
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
		var ruleID int
		if rid, ok := in["rule_id"].(float64); ok && rid > 0 {
			ruleID = int(rid)
		}

		if ruleID > 0 {
			if _, found := m.byID[ruleID]; found {
				m.byID[ruleID] = copyBIOCRecord(in, ruleID, false)
				updated = append(updated, map[string]any{
					"id":     ruleID,
					"status": fmt.Sprintf("Updated a bioc with the ID: %d successfully", ruleID),
				})
				continue
			}
		}

		m.nextID++
		ruleID = m.nextID
		m.byID[ruleID] = copyBIOCRecord(in, ruleID, true)
		added = append(added, map[string]any{
			"id":     ruleID,
			"status": fmt.Sprintf("Created a new bioc with the ID: %d successfully", ruleID),
		})
	}

	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"added_objects":   added,
		"updated_objects": updated,
		"errors":          []any{},
	})
}

// copyBIOCRecord normalizes the incoming payload into the stored shape and
// stamps the server-managed read-only fields. The `[""]` rewrite for empty
// mitre arrays mirrors live-API behavior so the model's RefreshFromRemote
// path is exercised correctly.
func copyBIOCRecord(in map[string]any, ruleID int, isNew bool) map[string]any {
	mitreTactic := emptyMitre(in["mitre_tactic_id_and_name"])
	mitreTech := emptyMitre(in["mitre_technique_id_and_name"])

	rec := map[string]any{
		"rule_id":                     float64(ruleID),
		"name":                        in["name"],
		"type":                        in["type"],
		"severity":                    in["severity"],
		"status":                      in["status"],
		"comment":                     firstNonNilAny(in["comment"], ""),
		"is_xql":                      firstNonNilAny(in["is_xql"], false),
		"indicator":                   in["indicator"],
		"mitre_tactic_id_and_name":    mitreTactic,
		"mitre_technique_id_and_name": mitreTech,
		"modification_time":           float64(1781000000001),
		"source":                      "Public API user (key #1)",
		"number_of_issues":            float64(0),
	}
	if isNew {
		rec["creation_time"] = float64(1781000000000)
	} else {
		rec["creation_time"] = float64(1781000000000)
	}
	return rec
}

// emptyMitre mirrors the server-side `[]` -> `[""]` rewrite observed
// against the live API. The provider's RefreshFromRemote collapses this
// back to an empty list.
func emptyMitre(v any) []any {
	if v == nil {
		return []any{""}
	}
	arr, ok := v.([]any)
	if !ok || len(arr) == 0 {
		return []any{""}
	}
	return arr
}

func firstNonNilAny(a, b any) any {
	if a == nil {
		return b
	}
	if s, ok := a.(string); ok && s == "" {
		return b
	}
	return a
}

func (m *biocMockServer) handleGet(t *testing.T, w http.ResponseWriter, r *http.Request) {
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
	for _, rec := range m.byID {
		if biocRecordMatches(rec, body.RequestData.Filters) {
			matches = append(matches, rec)
		}
	}

	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"objects_count": len(matches),
		"objects_type":  "bioc",
		"objects":       matches,
	})
}

func biocRecordMatches(rec map[string]any, filters []struct {
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
			// Mock only models EQ.
		}
	}
	return true
}

func (m *biocMockServer) handleDelete(t *testing.T, w http.ResponseWriter, r *http.Request) {
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
	for id, rec := range m.byID {
		if biocRecordMatches(rec, body.RequestData.Filters) {
			deletedIDs = append(deletedIDs, id)
			delete(m.byID, id)
		}
	}

	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"objects_count": len(deletedIDs),
		"objects":       deletedIDs,
	})
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

// TestUnitBIOCResource_XQLLifecycle covers the steady-state CRUD path with
// the XQL indicator form: create with xql_query set → read-back hydrates
// read-only fields → in-place update keeps rule_id stable.
func TestUnitBIOCResource_XQLLifecycle(t *testing.T) {
	mock := newBIOCMockServer()
	srv := httptest.NewServer(mock.handler(t))
	defer srv.Close()

	const cfgTmpl = `
resource "cortexcloud_bioc" "test" {
  name      = "xql-test"
  type      = "EXECUTION"
  severity  = "%s"
  status    = "enabled"
  comment   = "%s"
  xql_query = "dataset = xdr_data | filter event_type = 1"
}
`

	resource.Test(t, resource.TestCase{
		IsUnitTest:               true,
		ProtoV6ProviderFactories: newBIOCProviderFactories(),
		Steps: []resource.TestStep{
			{
				Config: biocProviderBlock(srv.URL) + fmt.Sprintf(cfgTmpl, "SEV_020_LOW", "initial"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("cortexcloud_bioc.test", "name", "xql-test"),
					resource.TestCheckResourceAttr("cortexcloud_bioc.test", "type", "EXECUTION"),
					resource.TestCheckResourceAttr("cortexcloud_bioc.test", "severity", "SEV_020_LOW"),
					resource.TestCheckResourceAttr("cortexcloud_bioc.test", "comment", "initial"),
					resource.TestCheckResourceAttr("cortexcloud_bioc.test", "is_xql", "true"),
					resource.TestCheckResourceAttr("cortexcloud_bioc.test", "xql_query", "dataset = xdr_data | filter event_type = 1"),
					resource.TestCheckResourceAttr("cortexcloud_bioc.test", "rule_id", "101"),
					resource.TestCheckResourceAttr("cortexcloud_bioc.test", "id", "101"),
					resource.TestCheckResourceAttr("cortexcloud_bioc.test", "source", "Public API user (key #1)"),
					// Server normalized [] -> [""]; provider collapses back.
					resource.TestCheckResourceAttr("cortexcloud_bioc.test", "mitre_tactic_id_and_name.#", "0"),
				),
			},
			// In-place update (severity + comment). rule_id must stay 101.
			{
				Config: biocProviderBlock(srv.URL) + fmt.Sprintf(cfgTmpl, "SEV_050_CRITICAL", "updated"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("cortexcloud_bioc.test", "severity", "SEV_050_CRITICAL"),
					resource.TestCheckResourceAttr("cortexcloud_bioc.test", "comment", "updated"),
					resource.TestCheckResourceAttr("cortexcloud_bioc.test", "rule_id", "101"),
				),
			},
		},
	})
}

// TestUnitBIOCResource_RenameInPlace covers the name-change path: when
// `name` changes, the provider submits the existing rule_id as the upsert
// key, so the record is overwritten in place and keeps its rule_id rather
// than being recreated.
func TestUnitBIOCResource_RenameInPlace(t *testing.T) {
	mock := newBIOCMockServer()
	srv := httptest.NewServer(mock.handler(t))
	defer srv.Close()

	const cfgTmpl = `
resource "cortexcloud_bioc" "test" {
  name      = "%s"
  type      = "EXECUTION"
  severity  = "SEV_020_LOW"
  status    = "enabled"
  xql_query = "dataset = xdr_data"
}
`

	resource.Test(t, resource.TestCase{
		IsUnitTest:               true,
		ProtoV6ProviderFactories: newBIOCProviderFactories(),
		Steps: []resource.TestStep{
			{
				Config: biocProviderBlock(srv.URL) + fmt.Sprintf(cfgTmpl, "old-name"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("cortexcloud_bioc.test", "name", "old-name"),
					resource.TestCheckResourceAttr("cortexcloud_bioc.test", "rule_id", "101"),
				),
			},
			{
				Config: biocProviderBlock(srv.URL) + fmt.Sprintf(cfgTmpl, "new-name"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("cortexcloud_bioc.test", "name", "new-name"),
					// Rename takes the rule_id-keyed upsert path; rule_id 101 preserved.
					resource.TestCheckResourceAttr("cortexcloud_bioc.test", "rule_id", "101"),
				),
			},
		},
	})
}

// TestUnitBIOCResource_StructuredDefinition covers the non-XQL indicator
// form: the definition string round-trips through canonicalization and
// is_xql is derived as false.
func TestUnitBIOCResource_StructuredDefinition(t *testing.T) {
	mock := newBIOCMockServer()
	srv := httptest.NewServer(mock.handler(t))
	defer srv.Close()

	resource.Test(t, resource.TestCase{
		IsUnitTest:               true,
		ProtoV6ProviderFactories: newBIOCProviderFactories(),
		Steps: []resource.TestStep{
			{
				Config: biocProviderBlock(srv.URL) + `
resource "cortexcloud_bioc" "test" {
  name     = "structured-test"
  type     = "EXECUTION"
  severity = "SEV_020_LOW"
  status   = "disabled"
  definition = jsonencode({
    runOnCGO          = true
    investigationType = "PROCESS_EXECUTION_EVENT"
    investigation = {
      PROCESS_EXECUTION_EVENT = {
        filter = {
          AND = [{
            SEARCH_FIELD = "action_process_username"
            SEARCH_TYPE  = "EQ"
            SEARCH_VALUE = "test"
          }]
        }
      }
    }
  })
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("cortexcloud_bioc.test", "is_xql", "false"),
					resource.TestCheckResourceAttrSet("cortexcloud_bioc.test", "definition"),
					// xql_query stays null when definition is set.
					resource.TestCheckNoResourceAttr("cortexcloud_bioc.test", "xql_query"),
				),
			},
		},
	})
}

// TestUnitBIOCResource_ExactlyOneOfIndicator pins the schema-level
// validator: configuring both xql_query and definition is rejected at
// plan time without reaching the API.
func TestUnitBIOCResource_ExactlyOneOfIndicator(t *testing.T) {
	mock := newBIOCMockServer()
	srv := httptest.NewServer(mock.handler(t))
	defer srv.Close()

	resource.Test(t, resource.TestCase{
		IsUnitTest:               true,
		ProtoV6ProviderFactories: newBIOCProviderFactories(),
		Steps: []resource.TestStep{
			{
				Config: biocProviderBlock(srv.URL) + `
resource "cortexcloud_bioc" "test" {
  name       = "x"
  type       = "EXECUTION"
  severity   = "SEV_020_LOW"
  xql_query  = "dataset = xdr_data"
  definition = "{}"
}
`,
				ExpectError: regexp.MustCompile(`(?i)Exactly one of these attributes`),
			},
			{
				// Neither set is also rejected.
				Config: biocProviderBlock(srv.URL) + `
resource "cortexcloud_bioc" "test" {
  name     = "x"
  type     = "EXECUTION"
  severity = "SEV_020_LOW"
}
`,
				ExpectError: regexp.MustCompile(`(?i)Exactly one of these attributes`),
			},
		},
	})
}

// TestUnitBIOCResource_ValidatorRejectsUnknownType pins the
// stringvalidator.OneOf wiring on `type`.
func TestUnitBIOCResource_ValidatorRejectsUnknownType(t *testing.T) {
	mock := newBIOCMockServer()
	srv := httptest.NewServer(mock.handler(t))
	defer srv.Close()

	resource.Test(t, resource.TestCase{
		IsUnitTest:               true,
		ProtoV6ProviderFactories: newBIOCProviderFactories(),
		Steps: []resource.TestStep{
			{
				Config: biocProviderBlock(srv.URL) + `
resource "cortexcloud_bioc" "test" {
  name      = "x"
  type      = "BOGUS_TYPE"
  severity  = "SEV_020_LOW"
  xql_query = "dataset = xdr_data"
}
`,
				ExpectError: regexp.MustCompile(`Attribute type value must be one of`),
			},
		},
	})
}
