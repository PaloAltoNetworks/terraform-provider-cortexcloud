// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package models

import (
	"testing"

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
