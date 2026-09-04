// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package cloudsec

import (
	"context"
	"errors"
	"strings"
	"testing"

	cloudsecModels "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/cloudsec"
	cloudsecTypes "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/types/cloudsec"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// newRuleMatchingObject builds a rule_matching types.Object with the supplied
// type and rules list for use in validateRuleMatching tests.
func newRuleMatchingObject(t *testing.T, ruleType string, rules attr.Value) types.Object {
	t.Helper()
	attrTypes := cloudsecModels.GetRuleMatchingAttrTypes()
	obj, diags := types.ObjectValue(attrTypes, map[string]attr.Value{
		"type":            types.StringValue(ruleType),
		"rules":           rules,
		"filter_criteria": types.ObjectNull(cloudsecModels.GetFilterCriteriaAttrTypes()),
	})
	if diags.HasError() {
		t.Fatalf("failed to build rule_matching object: %v", diags)
	}
	return obj
}

// TestValidateRuleMatching_UnknownRulesDeferred verifies that an unknown
// (computed-at-apply) rules list does NOT produce a plan-time error, while a
// null rules list still does, when rule_matching.type is RULES.
func TestValidateRuleMatching_UnknownRulesDeferred(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name      string
		rules     attr.Value
		wantError bool
	}{
		{
			name:      "unknown rules deferred to apply time",
			rules:     types.SetUnknown(types.StringType),
			wantError: false,
		},
		{
			name:      "null rules still errors at plan time",
			rules:     types.SetNull(types.StringType),
			wantError: true,
		},
		{
			name: "known rules pass validation",
			rules: func() attr.Value {
				sv, _ := types.SetValue(types.StringType, []attr.Value{types.StringValue("rule-1")})
				return sv
			}(),
			wantError: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			model := &cloudsecModels.CloudSecPolicyResourceModel{
				RuleMatching: newRuleMatchingObject(t, "RULES", tc.rules),
			}
			diags := diag.Diagnostics{}

			validateRuleMatching(ctx, model, &diags)

			if diags.HasError() != tc.wantError {
				t.Errorf("HasError()=%v, want %v; diags=%v", diags.HasError(), tc.wantError, diags)
			}
		})
	}
}

// TestCloudSecRuleCreateErrorDetail verifies the actionable compliance guidance
// is appended only when both an HTTP 400 error and compliance_metadata are
// present, and omitted otherwise.
func TestCloudSecRuleCreateErrorDetail(t *testing.T) {
	const guidance = "This request included compliance_metadata"

	withMetadata := []cloudsecTypes.ComplianceMetadataInput{
		{ControlID: "48e2f6a9fcc049579e9c6b8eda0bd123"},
	}

	tests := []struct {
		name         string
		err          error
		cm           []cloudsecTypes.ComplianceMetadataInput
		wantGuidance bool
	}{
		{
			name:         "400 with compliance_metadata appends guidance",
			err:          errors.New("API request failed with status 400: bad request"),
			cm:           withMetadata,
			wantGuidance: true,
		},
		{
			name:         "400 without compliance_metadata omits guidance",
			err:          errors.New("API request failed with status 400: bad request"),
			cm:           nil,
			wantGuidance: false,
		},
		{
			name:         "non-400 with compliance_metadata omits guidance",
			err:          errors.New("API request failed with status 500: server error"),
			cm:           withMetadata,
			wantGuidance: false,
		},
		{
			name:         "non-400 without compliance_metadata omits guidance",
			err:          errors.New("API request failed with status 500: server error"),
			cm:           nil,
			wantGuidance: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := cloudSecRuleCreateErrorDetail(tc.err, tc.cm)

			if !strings.Contains(got, tc.err.Error()) {
				t.Errorf("error detail %q should always contain the underlying error %q", got, tc.err.Error())
			}

			hasGuidance := strings.Contains(got, guidance)
			if hasGuidance != tc.wantGuidance {
				t.Errorf("guidance present=%v, want %v; detail=%q", hasGuidance, tc.wantGuidance, got)
			}
		})
	}
}
