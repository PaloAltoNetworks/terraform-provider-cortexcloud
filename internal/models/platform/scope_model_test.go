// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package models

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	platformtypes "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/types/platform"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// TestToEditRequest_DatasetsRowsOmittedWhenNil: an unconfigured block leaves
// DatasetsRows nil so the omitempty field is dropped from the request.
func TestToEditRequest_DatasetsRowsOmittedWhenNil(t *testing.T) {
	m := &ScopeModel{
		EntityType: types.StringValue("user-group"),
		EntityID:   types.StringValue("00000000-0000-0000-0000-000000000000"),
		// DatasetsRows intentionally nil (user omitted the block).
	}

	req := m.ToEditRequest()

	if req.DatasetsRows != nil {
		t.Fatalf("expected DatasetsRows to be nil when the block is omitted, got %+v", req.DatasetsRows)
	}

	// The request must serialize WITHOUT a datasets_rows key (not as null).
	b, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	if strings.Contains(string(b), "datasets_rows") {
		t.Fatalf("expected marshaled request to omit datasets_rows entirely, got: %s", string(b))
	}
}

// TestToEditRequest_DatasetsRowsSentWhenConfigured: a configured block is built
// and appears in the request.
func TestToEditRequest_DatasetsRowsSentWhenConfigured(t *testing.T) {
	m := &ScopeModel{
		EntityType: types.StringValue("user-group"),
		EntityID:   types.StringValue("00000000-0000-0000-0000-000000000000"),
		DatasetsRows: &DatasetsRowsModel{
			DefaultFilterMode: types.StringValue("no_scope"),
			Filters: []FilterModel{
				{
					Dataset: types.StringValue("amazon_aws_raw"),
					Filter:  types.StringValue("severity = \"high\""),
				},
			},
		},
	}

	req := m.ToEditRequest()

	if req.DatasetsRows == nil {
		t.Fatal("expected DatasetsRows to be non-nil when the block is configured")
	}
	if req.DatasetsRows.DefaultFilterMode != "no_scope" {
		t.Fatalf("expected default_filter_mode 'no_scope', got %q", req.DatasetsRows.DefaultFilterMode)
	}
	if len(req.DatasetsRows.Filters) != 1 {
		t.Fatalf("expected 1 filter, got %d", len(req.DatasetsRows.Filters))
	}
	if req.DatasetsRows.Filters[0].Dataset != "amazon_aws_raw" {
		t.Fatalf("unexpected filter dataset: %q", req.DatasetsRows.Filters[0].Dataset)
	}

	b, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	if !strings.Contains(string(b), "datasets_rows") {
		t.Fatalf("expected marshaled request to include datasets_rows, got: %s", string(b))
	}
}

// TestToEditRequest_DatasetsRowsConfiguredEmptyFilters verifies a configured
// block with no filters still sends datasets_rows with an empty (non-null)
// filters array.
func TestToEditRequest_DatasetsRowsConfiguredEmptyFilters(t *testing.T) {
	m := &ScopeModel{
		EntityType: types.StringValue("user-group"),
		EntityID:   types.StringValue("00000000-0000-0000-0000-000000000000"),
		DatasetsRows: &DatasetsRowsModel{
			DefaultFilterMode: types.StringValue("see_all"),
			Filters:           nil,
		},
	}

	req := m.ToEditRequest()
	if req.DatasetsRows == nil {
		t.Fatal("expected DatasetsRows non-nil for a configured block")
	}
	if req.DatasetsRows.Filters == nil {
		t.Fatal("expected Filters to be an empty slice, not nil (must marshal as [])")
	}

	b, _ := json.Marshal(req.DatasetsRows)
	if !strings.Contains(string(b), `"filters":[]`) {
		t.Fatalf("expected filters to marshal as [], got: %s", string(b))
	}
}

// TestEditScopeRequestData_NilDatasetsRowsMarshalsWithoutKey guards the SDK
// contract: a nil DatasetsRows must be omitted (needs the omitempty tag).
func TestEditScopeRequestData_NilDatasetsRowsMarshalsWithoutKey(t *testing.T) {
	req := platformtypes.EditScopeRequestData{
		Assets: &platformtypes.EditAssets{Mode: "no_scope", AssetGroupIDs: []int{}},
		// DatasetsRows nil
	}
	b, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	if strings.Contains(string(b), "datasets_rows") {
		t.Fatalf("SDK regression: nil DatasetsRows must be omitted (needs omitempty), got: %s", string(b))
	}
}

// TestRefreshFromRemote_DisabledTenantLeavesDatasetsRowsNil: when the backend
// omits datasets_rows, the model stays nil (no drift).
func TestRefreshFromRemote_DisabledTenantLeavesDatasetsRowsNil(t *testing.T) {
	m := &ScopeModel{}
	remote := &platformtypes.Scope{
		Assets: &platformtypes.Assets{Mode: "no_scope"},
		// DatasetsRows intentionally nil (backend omits it when SBAC disabled).
		Endpoints:   &platformtypes.Endpoints{},
		CasesIssues: &platformtypes.CasesIssues{Mode: "no_scope"},
	}

	var diags diag.Diagnostics
	m.RefreshFromRemote(context.Background(), &diags, remote)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %+v", diags)
	}
	if m.DatasetsRows != nil {
		t.Fatalf("expected DatasetsRows to stay nil when remote omits it, got %+v", m.DatasetsRows)
	}
}

// TestRefreshFromRemote_EnabledTenantPopulatesDatasetsRows: when the backend
// returns datasets_rows, the model is populated.
func TestRefreshFromRemote_EnabledTenantPopulatesDatasetsRows(t *testing.T) {
	m := &ScopeModel{}
	remote := &platformtypes.Scope{
		Assets: &platformtypes.Assets{Mode: "no_scope"},
		DatasetsRows: &platformtypes.DatasetsRows{
			DefaultFilterMode: "no_scope",
			Filters:           nil,
		},
		Endpoints:   &platformtypes.Endpoints{},
		CasesIssues: &platformtypes.CasesIssues{Mode: "no_scope"},
	}

	var diags diag.Diagnostics
	m.RefreshFromRemote(context.Background(), &diags, remote)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %+v", diags)
	}
	if m.DatasetsRows == nil {
		t.Fatal("expected DatasetsRows populated when remote returns it")
	}
	if m.DatasetsRows.DefaultFilterMode.ValueString() != "no_scope" {
		t.Fatalf("unexpected default_filter_mode: %q", m.DatasetsRows.DefaultFilterMode.ValueString())
	}
}
