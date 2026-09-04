// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package models

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	appsecTypes "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/types/appsec"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func TestPreserveJSONIfEqual(t *testing.T) {
	tests := []struct {
		name        string
		current     types.String
		remoteJSON  string
		expectValue string
		expectNull  bool
	}{
		{
			name:        "same key order — preserves current",
			current:     types.StringValue(`{"a":"1","b":"2"}`),
			remoteJSON:  `{"a":"1","b":"2"}`,
			expectValue: `{"a":"1","b":"2"}`,
		},
		{
			name:        "different key order — preserves current (semantically equal)",
			current:     types.StringValue(`{"b":"2","a":"1"}`),
			remoteJSON:  `{"a":"1","b":"2"}`,
			expectValue: `{"b":"2","a":"1"}`,
		},
		{
			name:        "different values — uses remote",
			current:     types.StringValue(`{"a":"1","b":"2"}`),
			remoteJSON:  `{"a":"1","b":"3"}`,
			expectValue: `{"a":"1","b":"3"}`,
		},
		{
			name:        "null current — uses remote",
			current:     types.StringNull(),
			remoteJSON:  `{"a":"1"}`,
			expectValue: `{"a":"1"}`,
		},
		{
			name:        "unknown current — uses remote",
			current:     types.StringUnknown(),
			remoteJSON:  `{"a":"1"}`,
			expectValue: `{"a":"1"}`,
		},
		{
			name:        "nested objects with different key order — preserves current",
			current:     types.StringValue(`{"AND":[{"SEARCH_FIELD":"a"},{"SEARCH_FIELD":"b"}]}`),
			remoteJSON:  `{"AND":[{"SEARCH_FIELD":"a"},{"SEARCH_FIELD":"b"}]}`,
			expectValue: `{"AND":[{"SEARCH_FIELD":"a"},{"SEARCH_FIELD":"b"}]}`,
		},
		{
			name:        "invalid current JSON — uses remote",
			current:     types.StringValue(`{invalid json`),
			remoteJSON:  `{"a":"1"}`,
			expectValue: `{"a":"1"}`,
		},
		{
			name:        "arrays with different order — uses remote (arrays are order-sensitive)",
			current:     types.StringValue(`{"AND":[{"SEARCH_FIELD":"b"},{"SEARCH_FIELD":"a"}]}`),
			remoteJSON:  `{"AND":[{"SEARCH_FIELD":"a"},{"SEARCH_FIELD":"b"}]}`,
			expectValue: `{"AND":[{"SEARCH_FIELD":"a"},{"SEARCH_FIELD":"b"}]}`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := preserveJSONIfEqual(tc.current, tc.remoteJSON)
			if tc.expectNull {
				if !got.IsNull() {
					t.Errorf("preserveJSONIfEqual() = %q, want null", got.ValueString())
				}
				return
			}
			if got.ValueString() != tc.expectValue {
				t.Errorf("preserveJSONIfEqual() = %q, want %q", got.ValueString(), tc.expectValue)
			}
		})
	}
}

func TestPolicyModelRefreshFromRemote_Version(t *testing.T) {
	tests := []struct {
		name          string
		remoteVersion float64
		expectValue   float64
	}{
		{
			name:          "version is mapped from remote",
			remoteVersion: 2.0,
			expectValue:   2.0,
		},
		{
			name:          "version zero is mapped",
			remoteVersion: 0,
			expectValue:   0,
		},
		{
			name:          "version fractional is mapped",
			remoteVersion: 1.5,
			expectValue:   1.5,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			diags := diag.Diagnostics{}

			remote := &appsecTypes.Policy{
				ID:          "test-id",
				Name:        "test-policy",
				Description: "test",
				Status:      "enabled",
				Version:     tc.remoteVersion,
				Conditions:  appsecTypes.PolicyCondition{},
				Triggers:    appsecTypes.PolicyTriggers{},
			}

			var model PolicyModel
			model.RefreshFromRemote(ctx, &diags, remote)

			if diags.HasError() {
				t.Fatalf("RefreshFromRemote() returned errors: %v", diags.Errors())
			}

			if model.Version.IsNull() || model.Version.IsUnknown() {
				t.Fatalf("Version is null/unknown, want %v", tc.expectValue)
			}

			if model.Version.ValueFloat64() != tc.expectValue {
				t.Errorf("Version = %v, want %v", model.Version.ValueFloat64(), tc.expectValue)
			}
		})
	}
}

// TestPolicyModelRefreshFromRemote_AllFiveTriggers exercises the round-trip
// from a fully-populated SDK PolicyTriggers struct through RefreshFromRemote
// into the model's five typed Object fields.
func TestPolicyModelRefreshFromRemote_AllFiveTriggers(t *testing.T) {
	ctx := context.Background()
	diags := diag.Diagnostics{}
	high := "High"

	remote := &appsecTypes.Policy{
		ID:         "test-id",
		Name:       "all-triggers",
		Status:     "enabled",
		Conditions: appsecTypes.PolicyCondition{},
		Triggers: appsecTypes.PolicyTriggers{
			Periodic: appsecTypes.PolicyTriggerConfig{
				IsEnabled:             true,
				OverrideIssueSeverity: &high,
				Actions:               appsecTypes.TriggerActions{ReportIssue: true},
			},
			PR: appsecTypes.PolicyTriggerConfig{
				IsEnabled: false,
				Actions: appsecTypes.TriggerActions{
					ReportIssue:     false,
					BlockPR:         true,
					ReportPRComment: false,
				},
			},
			CICD: appsecTypes.PolicyTriggerConfig{
				IsEnabled: true,
				Actions: appsecTypes.TriggerActions{
					ReportIssue: true,
					BlockCICD:   true,
					ReportCICD:  false,
				},
			},
			CIImage: appsecTypes.PolicyTriggerConfig{
				IsEnabled: false,
				Actions: appsecTypes.TriggerActions{
					ReportIssue: false,
					ReportCICD:  true,
					BlockCICD:   false,
				},
			},
			ImageRegistry: appsecTypes.PolicyTriggerConfig{
				IsEnabled: true,
				Actions:   appsecTypes.TriggerActions{ReportIssue: true},
			},
		},
	}

	var model PolicyModel
	model.RefreshFromRemote(ctx, &diags, remote)
	if diags.HasError() {
		t.Fatalf("RefreshFromRemote() errors: %v", diags.Errors())
	}

	// Every trigger object must be non-null.
	for name, obj := range map[string]types.Object{
		"periodic":       model.PeriodicTrigger,
		"pr":             model.PRTrigger,
		"cicd":           model.CICDTrigger,
		"ci_image":       model.CIImageTrigger,
		"image_registry": model.ImageRegistryTrigger,
	} {
		if obj.IsNull() || obj.IsUnknown() {
			t.Errorf("%s trigger is null/unknown after refresh", name)
		}
	}

	// Round-trip through ToCreateRequest and confirm SDK values.
	req := model.ToCreateRequest(ctx, &diags)
	if diags.HasError() {
		t.Fatalf("ToCreateRequest() errors: %v", diags.Errors())
	}
	if !req.Triggers.Periodic.IsEnabled {
		t.Error("Periodic.IsEnabled lost in round-trip")
	}
	if req.Triggers.Periodic.OverrideIssueSeverity == nil || *req.Triggers.Periodic.OverrideIssueSeverity != "High" {
		t.Errorf("Periodic.OverrideIssueSeverity round-trip mismatch: got %v", req.Triggers.Periodic.OverrideIssueSeverity)
	}
	if !req.Triggers.PR.Actions.BlockPR {
		t.Error("PR.Actions.BlockPR lost in round-trip")
	}
	if !req.Triggers.CICD.Actions.BlockCICD {
		t.Error("CICD.Actions.BlockCICD lost in round-trip")
	}
	if !req.Triggers.CIImage.Actions.ReportCICD {
		t.Error("CIImage.Actions.ReportCICD lost in round-trip")
	}
	if !req.Triggers.ImageRegistry.IsEnabled {
		t.Error("ImageRegistry.IsEnabled lost in round-trip")
	}
}

// TestPolicyModel_ToCreateRequest_OmittedTriggersGetCanonicalDefaults
// verifies that when a user omits trigger blocks (model fields are null),
// the SDK request still emits canonical defaults so the API doesn't reject
// the body for missing keys.
func TestPolicyModel_ToCreateRequest_OmittedTriggersGetCanonicalDefaults(t *testing.T) {
	ctx := context.Background()
	diags := diag.Diagnostics{}

	model := PolicyModel{
		Name:                 types.StringValue("p"),
		Description:          types.StringValue(""),
		Conditions:           types.StringValue(`{"SEARCH_FIELD":"x","SEARCH_TYPE":"EQ","SEARCH_VALUE":"y"}`),
		Scope:                types.StringNull(),
		PeriodicTrigger:      types.ObjectNull(PeriodicTriggerAttrTypes),
		PRTrigger:            types.ObjectNull(PRTriggerAttrTypes),
		CICDTrigger:          types.ObjectNull(CICDTriggerAttrTypes),
		CIImageTrigger:       types.ObjectNull(CIImageTriggerAttrTypes),
		ImageRegistryTrigger: types.ObjectNull(ImageRegistryTriggerAttrTypes),
	}

	req := model.ToCreateRequest(ctx, &diags)
	if diags.HasError() {
		t.Fatalf("ToCreateRequest() errors: %v", diags.Errors())
	}

	// All five triggers should be present (zero-valued, isEnabled=false).
	for name, cfg := range map[string]appsecTypes.PolicyTriggerConfig{
		"periodic":       req.Triggers.Periodic,
		"pr":             req.Triggers.PR,
		"cicd":           req.Triggers.CICD,
		"ci_image":       req.Triggers.CIImage,
		"image_registry": req.Triggers.ImageRegistry,
	} {
		if cfg.IsEnabled {
			t.Errorf("%s default IsEnabled should be false", name)
		}
	}
}

// An empty asset_group_ids list must convert to a non-nil, zero-length slice.
//
// This is the load-bearing property behind clearing asset-group targeting. The
// resource's mergeServerFields back-fills AssetGroupIds only when the field is
// nil; a non-nil empty slice makes it skip itself, and encoding/json then drops
// the key via omitempty. Because the API's PUT is a full replacement, an absent
// key clears the association.
//
// If this ever regressed to nil, the back-fill would restore the previous asset
// groups and the request would silently carry both scoping mechanisms.
func TestPolicyModel_ToUpdateRequest_EmptyAssetGroupIdsIsNonNilEmptySlice(t *testing.T) {
	ctx := context.Background()
	diags := diag.Diagnostics{}

	model := newPolicyModelForAssetGroupTests(types.ListValueMust(types.Int64Type, []attr.Value{}))

	req := model.ToUpdateRequest(ctx, &diags)
	if diags.HasError() {
		t.Fatalf("ToUpdateRequest() errors: %v", diags.Errors())
	}

	if req.AssetGroupIds == nil {
		t.Fatal("AssetGroupIds is nil; must be a non-nil empty slice so mergeServerFields does not back-fill it")
	}
	if len(req.AssetGroupIds) != 0 {
		t.Errorf("AssetGroupIds = %v, want zero length", req.AssetGroupIds)
	}
}

// Negative control for the test above: a populated list must still be carried
// through. Without this, an implementation that always returned an empty slice
// would pass the suite while silently discarding the user's asset groups.
func TestPolicyModel_ToUpdateRequest_PopulatedAssetGroupIdsArePreserved(t *testing.T) {
	ctx := context.Background()
	diags := diag.Diagnostics{}

	model := newPolicyModelForAssetGroupTests(types.ListValueMust(types.Int64Type, []attr.Value{
		types.Int64Value(56),
		types.Int64Value(57),
	}))

	req := model.ToUpdateRequest(ctx, &diags)
	if diags.HasError() {
		t.Fatalf("ToUpdateRequest() errors: %v", diags.Errors())
	}

	want := []int{56, 57}
	if len(req.AssetGroupIds) != len(want) {
		t.Fatalf("AssetGroupIds = %v, want %v", req.AssetGroupIds, want)
	}
	for i, id := range want {
		if req.AssetGroupIds[i] != id {
			t.Errorf("AssetGroupIds[%d] = %d, want %d", i, req.AssetGroupIds[i], id)
		}
	}
}

// A null asset_group_ids must leave the field nil, preserving the existing
// back-fill behaviour for users who never manage asset groups in Terraform.
func TestPolicyModel_ToUpdateRequest_NullAssetGroupIdsStaysNil(t *testing.T) {
	ctx := context.Background()
	diags := diag.Diagnostics{}

	model := newPolicyModelForAssetGroupTests(types.ListNull(types.Int64Type))

	req := model.ToUpdateRequest(ctx, &diags)
	if diags.HasError() {
		t.Fatalf("ToUpdateRequest() errors: %v", diags.Errors())
	}

	if req.AssetGroupIds != nil {
		t.Errorf("AssetGroupIds = %v, want nil so mergeServerFields still back-fills", req.AssetGroupIds)
	}
}

// An empty asset_group_ids must not reach the wire at all. omitempty cannot
// distinguish an empty slice from an absent one, which is precisely what lets
// the full-replacement PUT clear the association.
func TestPolicyModel_ToUpdateRequest_EmptyAssetGroupIdsOmittedFromJSON(t *testing.T) {
	ctx := context.Background()
	diags := diag.Diagnostics{}

	model := newPolicyModelForAssetGroupTests(types.ListValueMust(types.Int64Type, []attr.Value{}))

	req := model.ToUpdateRequest(ctx, &diags)
	if diags.HasError() {
		t.Fatalf("ToUpdateRequest() errors: %v", diags.Errors())
	}

	body, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	if strings.Contains(string(body), "assetGroupIds") {
		t.Errorf("request body contains assetGroupIds, want it omitted: %s", body)
	}
}

// newPolicyModelForAssetGroupTests builds a minimal valid model, varying only
// asset_group_ids, so these tests exercise one dimension at a time.
func newPolicyModelForAssetGroupTests(assetGroupIds types.List) PolicyModel {
	return PolicyModel{
		Name:                 types.StringValue("p"),
		Description:          types.StringValue(""),
		Status:               types.StringValue("enabled"),
		Conditions:           types.StringValue(`{"SEARCH_FIELD":"x","SEARCH_TYPE":"EQ","SEARCH_VALUE":"y"}`),
		Scope:                types.StringValue(`{"AND":[{"SEARCH_FIELD":"repository_name","SEARCH_TYPE":"EQ","SEARCH_VALUE":"example/repo"}]}`),
		AssetGroupIds:        assetGroupIds,
		PeriodicTrigger:      types.ObjectNull(PeriodicTriggerAttrTypes),
		PRTrigger:            types.ObjectNull(PRTriggerAttrTypes),
		CICDTrigger:          types.ObjectNull(CICDTriggerAttrTypes),
		CIImageTrigger:       types.ObjectNull(CIImageTriggerAttrTypes),
		ImageRegistryTrigger: types.ObjectNull(ImageRegistryTriggerAttrTypes),
	}
}
