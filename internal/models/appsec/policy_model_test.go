// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package models

import (
	"context"
	"testing"

	appsecTypes "github.com/PaloAltoNetworks/cortex-cloud-go/types/appsec"
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
