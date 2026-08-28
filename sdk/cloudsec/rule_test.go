// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package cloudsec

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/enums"
	types "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/types/cloudsec"
)

func TestCreateRuleRequest_Validation(t *testing.T) {
	tests := []struct {
		name    string
		request types.CreateRuleRequest
		wantErr bool
	}{
		{
			name: "valid request",
			request: types.CreateRuleRequest{
				Name:       "Test Rule",
				Class:      enums.RuleClassConfig.String(),
				AssetTypes: []string{"aws-s3-bucket"},
				Severity:   enums.CloudSecSeverityHigh.String(),
				Query: types.QueryRequest{
					XQL: "config from cloud.resource where cloud.type = 'aws'",
				},
			},
			wantErr: false,
		},
		{
			name: "request with metadata",
			request: types.CreateRuleRequest{
				Name:       "Test Rule with Metadata",
				Class:      enums.RuleClassConfig.String(),
				AssetTypes: []string{"aws-s3-bucket"},
				Severity:   enums.CloudSecSeverityCritical.String(),
				Query: types.QueryRequest{
					XQL: "config from cloud.resource where cloud.type = 'aws'",
				},
				Metadata: &types.MetadataRequest{
					Issue: &types.IssueRequest{
						Recommendation: "Fix the issue by...",
					},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Basic validation checks
			if tt.request.Name == "" && !tt.wantErr {
				t.Error("Expected name to be set")
			}
			if tt.request.Class == "" && !tt.wantErr {
				t.Error("Expected class to be set")
			}
			if len(tt.request.AssetTypes) == 0 && !tt.wantErr {
				t.Error("Expected asset_types to be set")
			}
			if tt.request.Severity == "" && !tt.wantErr {
				t.Error("Expected severity to be set")
			}
			if tt.request.Query.XQL == "" && !tt.wantErr {
				t.Error("Expected query.xql to be set")
			}
		})
	}
}

func TestFilterCriteria_Structure(t *testing.T) {
	tests := []struct {
		name   string
		filter types.FilterCriteria
	}{
		{
			name: "simple EQ filter",
			filter: types.FilterCriteria{
				SearchField: "id",
				SearchType:  enums.SearchTypeEqualTo.String(),
				SearchValue: "test-id",
			},
		},
		{
			name: "OR filter",
			filter: types.FilterCriteria{
				OR: []types.FilterCriteria{
					{
						SearchField: "severity",
						SearchType:  enums.SearchTypeEqualTo.String(),
						SearchValue: enums.CloudSecSeverityHigh.String(),
					},
					{
						SearchField: "severity",
						SearchType:  enums.SearchTypeEqualTo.String(),
						SearchValue: enums.CloudSecSeverityCritical.String(),
					},
				},
			},
		},
		{
			name: "AND filter",
			filter: types.FilterCriteria{
				AND: []types.FilterCriteria{
					{
						SearchField: "enabled",
						SearchType:  enums.SearchTypeEqualTo.String(),
						SearchValue: true,
					},
					{
						SearchField: "system_default",
						SearchType:  enums.SearchTypeEqualTo.String(),
						SearchValue: false,
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Verify filter structure is valid
			if tt.filter.SearchField == "" && len(tt.filter.AND) == 0 && len(tt.filter.OR) == 0 {
				t.Error("Filter must have either SearchField or AND/OR criteria")
			}
		})
	}
}

// TestCreateRuleRequest_ComplianceMetadata_JSONSerialization verifies that ComplianceMetadata
// serializes as "compliance_metadata" with control_id objects in the JSON payload.
func TestCreateRuleRequest_ComplianceMetadata_JSONSerialization(t *testing.T) {
	req := types.CreateRuleRequest{
		Name:       "test-rule",
		Class:      enums.RuleClassConfig.String(),
		AssetTypes: []string{"aws-s3-bucket"},
		Severity:   enums.CloudSecSeverityHigh.String(),
		Query:      types.QueryRequest{XQL: "config from cloud.resource where cloud.type = 'aws'"},
		ComplianceMetadata: []types.ComplianceMetadataInput{
			{ControlID: "abc123"},
			{ControlID: "def456", StandardID: "std-001"},
		},
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Failed to marshal CreateRuleRequest: %v", err)
	}

	jsonStr := string(data)

	// Must contain "compliance_metadata" key
	if !strings.Contains(jsonStr, `"compliance_metadata"`) {
		t.Errorf("Expected JSON to contain \"compliance_metadata\", got: %s", jsonStr)
	}

	// Must NOT contain "controlIds" key (old broken field name)
	if strings.Contains(jsonStr, `"controlIds"`) {
		t.Errorf("JSON must NOT contain \"controlIds\" (old broken field name), got: %s", jsonStr)
	}

	// Verify the values are correct
	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Failed to unmarshal JSON: %v", err)
	}

	cm, ok := parsed["compliance_metadata"].([]interface{})
	if !ok {
		t.Fatalf("compliance_metadata is not an array: %v", parsed["compliance_metadata"])
	}
	if len(cm) != 2 {
		t.Errorf("Expected 2 compliance_metadata entries, got %d", len(cm))
	}

	first, ok := cm[0].(map[string]interface{})
	if !ok {
		t.Fatalf("First compliance_metadata entry is not an object: %v", cm[0])
	}
	if first["control_id"] != "abc123" {
		t.Errorf("Expected first control_id to be \"abc123\", got: %v", first["control_id"])
	}
	// standard_id should be omitted when not set (omitempty)
	if _, hasStdID := first["standard_id"]; hasStdID {
		t.Errorf("Expected standard_id to be omitted for first entry (omitempty), got: %v", first["standard_id"])
	}

	second, ok := cm[1].(map[string]interface{})
	if !ok {
		t.Fatalf("Second compliance_metadata entry is not an object: %v", cm[1])
	}
	if second["control_id"] != "def456" {
		t.Errorf("Expected second control_id to be \"def456\", got: %v", second["control_id"])
	}
	if second["standard_id"] != "std-001" {
		t.Errorf("Expected second standard_id to be \"std-001\", got: %v", second["standard_id"])
	}
}

// TestUpdateRuleRequest_ComplianceMetadata_JSONSerialization verifies that ComplianceMetadata
// serializes as "compliance_metadata" in UpdateRuleRequest as well.
func TestUpdateRuleRequest_ComplianceMetadata_JSONSerialization(t *testing.T) {
	req := types.UpdateRuleRequest{
		ComplianceMetadata: []types.ComplianceMetadataInput{
			{ControlID: "abc123"},
		},
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Failed to marshal UpdateRuleRequest: %v", err)
	}

	jsonStr := string(data)

	if !strings.Contains(jsonStr, `"compliance_metadata"`) {
		t.Errorf("Expected JSON to contain \"compliance_metadata\", got: %s", jsonStr)
	}

	if strings.Contains(jsonStr, `"controlIds"`) {
		t.Errorf("JSON must NOT contain \"controlIds\", got: %s", jsonStr)
	}
}

// TestCreateRuleRequest_ComplianceMetadata_OmittedWhenEmpty verifies that compliance_metadata
// is omitted from JSON when empty (omitempty behavior).
func TestCreateRuleRequest_ComplianceMetadata_OmittedWhenEmpty(t *testing.T) {
	req := types.CreateRuleRequest{
		Name:       "test-rule",
		Class:      enums.RuleClassConfig.String(),
		AssetTypes: []string{"aws-s3-bucket"},
		Severity:   enums.CloudSecSeverityHigh.String(),
		Query:      types.QueryRequest{XQL: "config from cloud.resource where cloud.type = 'aws'"},
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Failed to marshal CreateRuleRequest: %v", err)
	}

	jsonStr := string(data)

	if strings.Contains(jsonStr, `"compliance_metadata"`) {
		t.Errorf("Expected compliance_metadata to be omitted when empty, got: %s", jsonStr)
	}

	if strings.Contains(jsonStr, `"controlIds"`) {
		t.Errorf("Expected controlIds to not appear at all, got: %s", jsonStr)
	}
}

func TestSearchRulesRequest_Pagination(t *testing.T) {
	request := types.SearchRulesRequest{
		SearchFrom: 0,
		SearchTo:   50,
		Sort: []types.SortCriteria{
			{Field: "name", Order: enums.SortOrderASC.String()},
		},
	}

	if request.SearchFrom < 0 {
		t.Error("SearchFrom should not be negative")
	}
	if request.SearchTo <= request.SearchFrom {
		t.Error("SearchTo should be greater than SearchFrom")
	}
	if len(request.Sort) > 0 && request.Sort[0].Field == "" {
		t.Error("Sort field should not be empty")
	}
}
