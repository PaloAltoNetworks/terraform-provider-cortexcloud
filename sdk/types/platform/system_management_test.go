// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package types

import (
	"encoding/json"
	"strings"
	"testing"
)

// datasets_rows presence is coupled to the tenant's dataset-SBAC capability, so
// a nil pointer must marshal as an ABSENT key (via omitempty), not a JSON null
// (a null is rejected the same as a populated block). These tests lock that in.

func TestEditScopeRequestData_NilDatasetsRowsIsOmitted(t *testing.T) {
	req := EditScopeRequestData{
		Endpoints:   &EditEndpoints{},
		CasesIssues: &EditCasesIssues{},
		Assets:      &EditAssets{},
		// DatasetsRows intentionally left nil.
	}

	b, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	got := string(b)

	// The key must be entirely ABSENT. The other scope fields lack omitempty
	// by design and serialize as null when nil; only datasets_rows must
	// disappear (a null datasets_rows is rejected by the API exactly like a
	// populated block on a disabled tenant).
	if strings.Contains(got, "datasets_rows") {
		t.Errorf("expected datasets_rows key to be omitted for a nil pointer, got: %s", got)
	}
}

func TestEditScopeRequestData_PopulatedDatasetsRowsIsPresent(t *testing.T) {
	req := EditScopeRequestData{
		Endpoints:   &EditEndpoints{},
		CasesIssues: &EditCasesIssues{},
		Assets:      &EditAssets{},
		DatasetsRows: &EditDatasetsRows{
			DefaultFilterMode: "see_all",
			Filters:           []Filter{},
		},
	}

	b, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	// Round-trip and assert the block is present and preserved.
	var decoded EditScopeRequestData
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if decoded.DatasetsRows == nil {
		t.Fatalf("expected datasets_rows to be present after round-trip, got nil; payload: %s", string(b))
	}
	if decoded.DatasetsRows.DefaultFilterMode != "see_all" {
		t.Errorf("default_filter_mode not preserved: got %q", decoded.DatasetsRows.DefaultFilterMode)
	}
	if !strings.Contains(string(b), "datasets_rows") {
		t.Errorf("expected datasets_rows key in payload, got: %s", string(b))
	}
}

func TestScope_NilDatasetsRowsIsOmitted(t *testing.T) {
	// The read Scope type carries omitempty so a re-marshalled Scope omits a nil
	// datasets_rows rather than emitting null.
	s := Scope{
		Assets:      &Assets{},
		Endpoints:   &Endpoints{},
		CasesIssues: &CasesIssues{},
		// DatasetsRows intentionally left nil.
	}

	b, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	if strings.Contains(string(b), "datasets_rows") {
		t.Errorf("expected datasets_rows key to be omitted for a nil pointer, got: %s", string(b))
	}
}

func TestScope_DatasetsRowsRoundTripFromDisabledTenant(t *testing.T) {
	// A disabled-SBAC GET omits datasets_rows; the pointer must stay nil (no drift).
	const disabledTenantResponse = `{
		"assets": {"mode": "see_all", "asset_groups": []},
		"endpoints": {"endpoint_groups": {"mode": "see_all", "tags": []}, "endpoint_tags": {"mode": "any", "tags": []}},
		"cases_issues": {"mode": "see_all", "tags": []}
	}`

	var s Scope
	if err := json.Unmarshal([]byte(disabledTenantResponse), &s); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if s.DatasetsRows != nil {
		t.Errorf("expected DatasetsRows to remain nil when absent from the response, got: %+v", s.DatasetsRows)
	}

	// An enabled tenant's response includes the block; it must populate.
	const enabledTenantResponse = `{
		"assets": {"mode": "see_all", "asset_groups": []},
		"datasets_rows": {"default_filter_mode": "see_all", "filters": []},
		"endpoints": {"endpoint_groups": {"mode": "see_all", "tags": []}, "endpoint_tags": {"mode": "any", "tags": []}},
		"cases_issues": {"mode": "see_all", "tags": []}
	}`

	var s2 Scope
	if err := json.Unmarshal([]byte(enabledTenantResponse), &s2); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if s2.DatasetsRows == nil {
		t.Fatalf("expected DatasetsRows to be populated when present in the response")
	}
	if s2.DatasetsRows.DefaultFilterMode != "see_all" {
		t.Errorf("default_filter_mode not parsed: got %q", s2.DatasetsRows.DefaultFilterMode)
	}
}
