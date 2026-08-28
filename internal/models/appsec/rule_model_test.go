// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package models

import (
	"context"
	"testing"

	appsecTypes "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/types/appsec"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func TestStripDefinitionMetadata(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "no metadata — unchanged",
			input:    "definition:\n  cond_type: attribute\n  resource_types:\n    - aws_security_group\n  attribute: ingress.cidr_blocks\n  operator: contains\n  value: \"0.0.0.0/0\"",
			expected: "definition:\n  cond_type: attribute\n  resource_types:\n    - aws_security_group\n  attribute: ingress.cidr_blocks\n  operator: contains\n  value: \"0.0.0.0/0\"",
		},
		{
			name:     "metadata appended — stripped",
			input:    "definition:\n  cond_type: attribute\n  resource_types:\n    - aws_security_group\n  attribute: ingress.cidr_blocks\n  operator: contains\n  value: 0.0.0.0/0\nmetadata:\n  name: tf-auto-appsec-rule-test\n  category: ai and machine learning\n  severity: critical\n  guidelines: Automated test rule - UPDATED",
			expected: "definition:\n  cond_type: attribute\n  resource_types:\n    - aws_security_group\n  attribute: ingress.cidr_blocks\n  operator: contains\n  value: 0.0.0.0/0",
		},
		{
			name:     "empty string — unchanged",
			input:    "",
			expected: "",
		},
		{
			name:     "metadata at very start — stripped entirely",
			input:    "metadata:\n  name: test",
			expected: "",
		},
		{
			name:     "metadata with trailing whitespace before marker",
			input:    "definition:\n  cond_type: attribute\n  value: test  \nmetadata:\n  name: foo",
			expected: "definition:\n  cond_type: attribute\n  value: test",
		},
		{
			name:     "metadata keyword inside value — not stripped",
			input:    "definition:\n  cond_type: attribute\n  value: \"metadata: something\"",
			expected: "definition:\n  cond_type: attribute\n  value: \"metadata: something\"",
		},
		{
			name:     "metadata with Windows line endings",
			input:    "definition:\r\n  cond_type: attribute\r\n  value: test\r\nmetadata:\r\n  name: foo",
			expected: "definition:\r\n  cond_type: attribute\r\n  value: test",
		},
		{
			name:     "trailing newline stripped",
			input:    "definition:\n  cond_type: attribute\n  value: 0.0.0.0/0\n",
			expected: "definition:\n  cond_type: attribute\n  value: 0.0.0.0/0",
		},
		{
			name:     "trailing whitespace and newlines stripped",
			input:    "definition:\n  value: test\n\n  \n",
			expected: "definition:\n  value: test",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := stripDefinitionMetadata(tc.input)
			if got != tc.expected {
				t.Errorf("stripDefinitionMetadata() =\n%q\nwant:\n%q", got, tc.expected)
			}
		})
	}
}

func TestPreserveDefinitionIfEqual(t *testing.T) {
	tests := []struct {
		name             string
		configured       types.String
		normalizedRemote string
		expectValue      string
		expectNull       bool
	}{
		{
			name:             "matching after normalization — preserves configured (with trailing newline)",
			configured:       types.StringValue("definition:\n  value: test\n"),
			normalizedRemote: "definition:\n  value: test",
			expectValue:      "definition:\n  value: test\n",
		},
		{
			name:             "matching after metadata strip — preserves configured",
			configured:       types.StringValue("definition:\n  value: test"),
			normalizedRemote: "definition:\n  value: test",
			expectValue:      "definition:\n  value: test",
		},
		{
			name:             "different content — uses remote",
			configured:       types.StringValue("definition:\n  value: old"),
			normalizedRemote: "definition:\n  value: new",
			expectValue:      "definition:\n  value: new",
		},
		{
			name:             "null configured — uses remote",
			configured:       types.StringNull(),
			normalizedRemote: "definition:\n  value: test",
			expectValue:      "definition:\n  value: test",
		},
		{
			name:             "unknown configured — uses remote",
			configured:       types.StringUnknown(),
			normalizedRemote: "definition:\n  value: test",
			expectValue:      "definition:\n  value: test",
		},
		{
			name:             "YAML quote difference — preserves configured (quoted vs unquoted)",
			configured:       types.StringValue("definition:\n  cond_type: attribute\n  resource_types:\n    - aws_security_group\n  attribute: ingress.cidr_blocks\n  operator: contains\n  value: \"0.0.0.0/0\""),
			normalizedRemote: "definition:\n  cond_type: attribute\n  resource_types:\n    - aws_security_group\n  attribute: ingress.cidr_blocks\n  operator: contains\n  value: 0.0.0.0/0",
			expectValue:      "definition:\n  cond_type: attribute\n  resource_types:\n    - aws_security_group\n  attribute: ingress.cidr_blocks\n  operator: contains\n  value: \"0.0.0.0/0\"",
		},
		{
			name:             "YAML quote difference with trailing newline — preserves configured",
			configured:       types.StringValue("definition:\n  value: \"0.0.0.0/0\"\n"),
			normalizedRemote: "definition:\n  value: 0.0.0.0/0",
			expectValue:      "definition:\n  value: \"0.0.0.0/0\"\n",
		},
		{
			name:             "genuinely different YAML — uses remote",
			configured:       types.StringValue("definition:\n  value: \"10.0.0.0/8\""),
			normalizedRemote: "definition:\n  value: 0.0.0.0/0",
			expectValue:      "definition:\n  value: 0.0.0.0/0",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := preserveDefinitionIfEqual(tc.configured, tc.normalizedRemote)
			if got.IsNull() {
				if !tc.expectNull {
					t.Errorf("preserveDefinitionIfEqual() returned null, want %q", tc.expectValue)
				}
				return
			}
			if got.ValueString() != tc.expectValue {
				t.Errorf("preserveDefinitionIfEqual() = %q, want %q", got.ValueString(), tc.expectValue)
			}
		})
	}
}

// buildFrameworkList is a test helper that constructs a Terraform list value
// containing a single framework object with the given definition.
func buildFrameworkList(t *testing.T) types.List {
	t.Helper()

	fwObj, diags := types.ObjectValue(
		frameworkAttrTypes(),
		map[string]attr.Value{
			"name":                    types.StringValue("TERRAFORM"),
			"definition":              types.StringValue("definition:\n  value: test"),
			"definition_link":         types.StringNull(),
			"remediation_description": types.StringNull(),
			"remediation_ids":         types.ListNull(types.StringType),
			"resource_types":          types.ListNull(types.StringType),
		},
	)
	if diags.HasError() {
		t.Fatalf("failed to build framework object: %v", diags)
	}
	list, listDiags := types.ListValue(types.ObjectType{AttrTypes: frameworkAttrTypes()}, []attr.Value{fwObj})
	if listDiags.HasError() {
		t.Fatalf("failed to build framework list: %v", listDiags)
	}
	return list
}

func TestRuleModel_ToCreateRequest_CspmRuleId(t *testing.T) {
	ctx := context.Background()

	t.Run("maps top-level cspm_rule_id to the SDK request", func(t *testing.T) {
		m := &RuleModel{
			Name:       types.StringValue("mapped-rule"),
			Severity:   types.StringValue("HIGH"),
			Scanner:    types.StringValue("IAC"),
			CspmRuleId: types.StringValue("ff6a26a5-f036-4d3a-a650-d5de1d568bab"),
			Frameworks: buildFrameworkList(t),
		}
		var diags diag.Diagnostics
		req := m.ToCreateRequest(ctx, &diags)
		if diags.HasError() {
			t.Fatalf("unexpected diagnostics: %v", diags)
		}
		if req.CspmRuleId == nil {
			t.Fatal("expected CspmRuleId to be set, got nil")
		}
		if *req.CspmRuleId != "ff6a26a5-f036-4d3a-a650-d5de1d568bab" {
			t.Errorf("CspmRuleId = %q, want %q", *req.CspmRuleId, "ff6a26a5-f036-4d3a-a650-d5de1d568bab")
		}
	})

	t.Run("omits cspm_rule_id when unset", func(t *testing.T) {
		m := &RuleModel{
			Name:       types.StringValue("unmapped-rule"),
			Severity:   types.StringValue("LOW"),
			Scanner:    types.StringValue("IAC"),
			CspmRuleId: types.StringNull(),
			Frameworks: buildFrameworkList(t),
		}
		var diags diag.Diagnostics
		req := m.ToCreateRequest(ctx, &diags)
		if diags.HasError() {
			t.Fatalf("unexpected diagnostics: %v", diags)
		}
		if req.CspmRuleId != nil {
			t.Errorf("expected CspmRuleId to be nil, got %q", *req.CspmRuleId)
		}
	})
}

func TestRuleModel_RefreshFromRemote_NewFields(t *testing.T) {
	ctx := context.Background()

	cspmRuleId := "ff6a26a5-f036-4d3a-a650-d5de1d568bab"
	m := &RuleModel{
		// cspm_rule_id is write-only: the API never returns it, so the value
		// configured in state must be preserved across a refresh.
		CspmRuleId: types.StringValue(cspmRuleId),
		// Pre-populate frameworks so the name filter keeps the remote framework.
		Frameworks: buildFrameworkList(t),
	}

	detectionMethod := "IaC Security"
	remote := &appsecTypes.Rule{
		Id:               "rule-1",
		Name:             "rule",
		ShortDescription: "short desc",
		DocLink:          "https://docs.example/rule",
		DetectionMethod:  &detectionMethod,
		FindingDocs:      "finding docs",
		FindingTypeId:    30040031,
		Owner:            "CAS",
		MitreTactics:     []string{"TA0001"},
		MitreTechniques:  []string{"T1190"},
		Frameworks: []appsecTypes.FrameworkData{
			{
				Name:           "TERRAFORM",
				Definition:     "definition:\n  value: test",
				RemediationIds: []string{"rem-1", "rem-2"},
				ResourceTypes:  []string{"aws_s3_bucket"},
			},
		},
	}

	var diags diag.Diagnostics
	m.RefreshFromRemote(ctx, &diags, remote)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", diags)
	}

	if m.ShortDescription.ValueString() != "short desc" {
		t.Errorf("ShortDescription = %q, want %q", m.ShortDescription.ValueString(), "short desc")
	}

	// cspm_rule_id must be preserved from state, not overwritten by the read.
	if m.CspmRuleId.ValueString() != cspmRuleId {
		t.Errorf("cspm_rule_id = %q, want %q (should be preserved from state)", m.CspmRuleId.ValueString(), cspmRuleId)
	}

	// Read-only fields from the API doc response schema.
	if m.DocLink.ValueString() != "https://docs.example/rule" {
		t.Errorf("doc_link = %q, want %q", m.DocLink.ValueString(), "https://docs.example/rule")
	}
	if m.DetectionMethod.ValueString() != "IaC Security" {
		t.Errorf("detection_method = %q, want %q", m.DetectionMethod.ValueString(), "IaC Security")
	}
	if m.FindingDocs.ValueString() != "finding docs" {
		t.Errorf("finding_docs = %q, want %q", m.FindingDocs.ValueString(), "finding docs")
	}
	if m.FindingTypeID.ValueInt64() != 30040031 {
		t.Errorf("finding_type_id = %d, want %d", m.FindingTypeID.ValueInt64(), 30040031)
	}
	if m.Owner.ValueString() != "CAS" {
		t.Errorf("owner = %q, want %q", m.Owner.ValueString(), "CAS")
	}
	var mitreTactics []string
	diags = m.MitreTactics.ElementsAs(ctx, &mitreTactics, false)
	if diags.HasError() {
		t.Fatalf("failed to read mitre_tactics: %v", diags)
	}
	if len(mitreTactics) != 1 || mitreTactics[0] != "TA0001" {
		t.Errorf("mitre_tactics = %v, want [TA0001]", mitreTactics)
	}
	var mitreTechniques []string
	diags = m.MitreTechniques.ElementsAs(ctx, &mitreTechniques, false)
	if diags.HasError() {
		t.Fatalf("failed to read mitre_techniques: %v", diags)
	}
	if len(mitreTechniques) != 1 || mitreTechniques[0] != "T1190" {
		t.Errorf("mitre_techniques = %v, want [T1190]", mitreTechniques)
	}

	var frameworks []FrameworkModel
	diags = m.Frameworks.ElementsAs(ctx, &frameworks, false)
	if diags.HasError() {
		t.Fatalf("failed to read frameworks: %v", diags)
	}
	if len(frameworks) != 1 {
		t.Fatalf("expected 1 framework, got %d", len(frameworks))
	}

	var remIds []string
	diags = frameworks[0].RemediationIds.ElementsAs(ctx, &remIds, false)
	if diags.HasError() {
		t.Fatalf("failed to read remediation_ids: %v", diags)
	}
	if len(remIds) != 2 || remIds[0] != "rem-1" || remIds[1] != "rem-2" {
		t.Errorf("remediation_ids = %v, want [rem-1 rem-2]", remIds)
	}

	var resTypes []string
	diags = frameworks[0].ResourceTypes.ElementsAs(ctx, &resTypes, false)
	if diags.HasError() {
		t.Fatalf("failed to read resource_types: %v", diags)
	}
	if len(resTypes) != 1 || resTypes[0] != "aws_s3_bucket" {
		t.Errorf("resource_types = %v, want [aws_s3_bucket]", resTypes)
	}
}
