// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package models

import (
	"context"
	"encoding/json"
	"testing"

	cloudsecTypes "github.com/PaloAltoNetworks/cortex-cloud-go/types/cloudsec"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// minimalRuleResponse returns a RuleResponse with the minimum required fields
// to avoid nil-pointer panics in FromSDKResponse.
func minimalRuleResponse() *cloudsecTypes.RuleResponse {
	return &cloudsecTypes.RuleResponse{
		ID:       "test-id",
		Name:     "test-rule",
		Severity: "high",
		Class:    "config",
		Type:     "custom",
		Query:    &cloudsecTypes.QueryResponse{XQL: "dataset = test"},
		Metadata: &cloudsecTypes.MetadataResponse{
			Issue: &cloudsecTypes.IssueResponse{Recommendation: "fix it"},
		},
	}
}

// buildComplianceList creates a types.List with compliance_metadata elements
// for use as a pre-existing model value (simulating the plan/prior state).
func buildComplianceList(t *testing.T, items []map[string]string) types.List {
	t.Helper()
	elems := make([]attr.Value, 0, len(items))
	for _, item := range items {
		obj, d := types.ObjectValue(
			GetComplianceMetadataAttrTypes(),
			map[string]attr.Value{
				"control_id":    types.StringValue(item["control_id"]),
				"standard_id":   types.StringValue(item["standard_id"]),
				"standard_name": types.StringValue(item["standard_name"]),
				"control_name":  types.StringValue(item["control_name"]),
			},
		)
		if d.HasError() {
			t.Fatalf("building compliance object: %s", d.Errors())
		}
		elems = append(elems, obj)
	}
	list, d := types.ListValue(
		types.ObjectType{AttrTypes: GetComplianceMetadataAttrTypes()},
		elems,
	)
	if d.HasError() {
		t.Fatalf("building compliance list: %s", d.Errors())
	}
	return list
}

// buildComplianceListWithUnknowns creates a types.List where control_id is known
// but computed fields (standard_id, standard_name, control_name) are Unknown,
// simulating what the plan looks like when the user only specifies control_id.
func buildComplianceListWithUnknowns(t *testing.T, controlIDs []string) types.List {
	t.Helper()
	elems := make([]attr.Value, 0, len(controlIDs))
	for _, cid := range controlIDs {
		obj, d := types.ObjectValue(
			GetComplianceMetadataAttrTypes(),
			map[string]attr.Value{
				"control_id":    types.StringValue(cid),
				"standard_id":   types.StringUnknown(),
				"standard_name": types.StringUnknown(),
				"control_name":  types.StringUnknown(),
			},
		)
		if d.HasError() {
			t.Fatalf("building compliance object with unknowns: %s", d.Errors())
		}
		elems = append(elems, obj)
	}
	list, d := types.ListValue(
		types.ObjectType{AttrTypes: GetComplianceMetadataAttrTypes()},
		elems,
	)
	if d.HasError() {
		t.Fatalf("building compliance list with unknowns: %s", d.Errors())
	}
	return list
}

func TestFromSDKResponse_ComplianceMetadata_PreservesPlanOnEmptyRemote(t *testing.T) {
	// Simulate the eventual-consistency scenario:
	// The model already has compliance_metadata from the plan (the write succeeded),
	// but the GET response returns an empty slice (not yet propagated).
	// All fields are known (e.g., from a prior state).

	ctx := context.Background()
	diags := diag.Diagnostics{}

	planList := buildComplianceList(t, []map[string]string{
		{
			"control_id":    "ctrl-123",
			"standard_id":   "std-456",
			"standard_name": "Test Standard",
			"control_name":  "Test Control",
		},
	})

	model := &CloudSecRuleResourceModel{
		ComplianceMetadata: planList,
	}

	remote := minimalRuleResponse()
	remote.ComplianceMetadata = []cloudsecTypes.ComplianceMetadata{} // empty = eventual consistency

	model.FromSDKResponse(ctx, &diags, remote)

	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %s", diags.Errors())
	}

	// The model should preserve the plan value, not overwrite with null.
	if model.ComplianceMetadata.IsNull() {
		t.Fatal("expected compliance_metadata to be preserved from plan, got null")
	}
	if model.ComplianceMetadata.IsUnknown() {
		t.Fatal("expected compliance_metadata to be preserved from plan, got unknown")
	}
	if len(model.ComplianceMetadata.Elements()) != 1 {
		t.Fatalf("expected 1 compliance_metadata element, got %d", len(model.ComplianceMetadata.Elements()))
	}

	// Verify the preserved values are correct
	elem := model.ComplianceMetadata.Elements()[0]
	obj, ok := elem.(types.Object)
	if !ok {
		t.Fatal("expected element to be types.Object")
	}
	attrs := obj.Attributes()
	if cid, ok := attrs["control_id"].(types.String); !ok || cid.ValueString() != "ctrl-123" {
		t.Fatalf("expected control_id='ctrl-123', got %v", attrs["control_id"])
	}
	if sid, ok := attrs["standard_id"].(types.String); !ok || sid.ValueString() != "std-456" {
		t.Fatalf("expected standard_id='std-456', got %v", attrs["standard_id"])
	}
}

func TestFromSDKResponse_ComplianceMetadata_PreservesPlanWithUnknowns(t *testing.T) {
	// Simulate the real-world scenario: user specifies only control_id in config,
	// computed fields are Unknown in the plan. The GET returns empty.
	// The fix should rebuild the list with empty strings for unknown computed fields.

	ctx := context.Background()
	diags := diag.Diagnostics{}

	planList := buildComplianceListWithUnknowns(t, []string{"ctrl-abc"})

	model := &CloudSecRuleResourceModel{
		ComplianceMetadata: planList,
	}

	remote := minimalRuleResponse()
	remote.ComplianceMetadata = []cloudsecTypes.ComplianceMetadata{} // empty = eventual consistency

	model.FromSDKResponse(ctx, &diags, remote)

	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %s", diags.Errors())
	}

	if model.ComplianceMetadata.IsNull() {
		t.Fatal("expected compliance_metadata to be preserved, got null")
	}
	if len(model.ComplianceMetadata.Elements()) != 1 {
		t.Fatalf("expected 1 element, got %d", len(model.ComplianceMetadata.Elements()))
	}

	// Verify the control_id is preserved and computed fields are empty strings (not unknown)
	elem := model.ComplianceMetadata.Elements()[0]
	obj, ok := elem.(types.Object)
	if !ok {
		t.Fatal("expected element to be types.Object")
	}
	attrs := obj.Attributes()
	if cid, ok := attrs["control_id"].(types.String); !ok || cid.ValueString() != "ctrl-abc" {
		t.Fatalf("expected control_id='ctrl-abc', got %v", attrs["control_id"])
	}
	// Computed fields should be empty strings, NOT unknown
	if sid, ok := attrs["standard_id"].(types.String); !ok || sid.IsUnknown() {
		t.Fatal("expected standard_id to be a known value (empty string), got unknown")
	} else if sid.ValueString() != "" {
		t.Fatalf("expected standard_id='', got '%s'", sid.ValueString())
	}
	if sn, ok := attrs["standard_name"].(types.String); !ok || sn.IsUnknown() {
		t.Fatal("expected standard_name to be a known value (empty string), got unknown")
	}
	if cn, ok := attrs["control_name"].(types.String); !ok || cn.IsUnknown() {
		t.Fatal("expected control_name to be a known value (empty string), got unknown")
	}
}

func TestFromSDKResponse_ComplianceMetadata_SetsNullWhenBothEmpty(t *testing.T) {
	// When neither the plan nor the remote has compliance_metadata,
	// the result should be null (no false preservation).

	ctx := context.Background()
	diags := diag.Diagnostics{}

	model := &CloudSecRuleResourceModel{
		ComplianceMetadata: types.ListNull(types.ObjectType{AttrTypes: GetComplianceMetadataAttrTypes()}),
	}

	remote := minimalRuleResponse()
	remote.ComplianceMetadata = nil

	model.FromSDKResponse(ctx, &diags, remote)

	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %s", diags.Errors())
	}

	if !model.ComplianceMetadata.IsNull() {
		t.Fatal("expected compliance_metadata to be null when both plan and remote are empty")
	}
}

func TestFromSDKResponse_ComplianceMetadata_UsesRemoteWhenPopulated(t *testing.T) {
	// When the remote has compliance_metadata, it should be used
	// regardless of what the model had before.

	ctx := context.Background()
	diags := diag.Diagnostics{}

	model := &CloudSecRuleResourceModel{
		ComplianceMetadata: types.ListNull(types.ObjectType{AttrTypes: GetComplianceMetadataAttrTypes()}),
	}

	remote := minimalRuleResponse()
	remote.ComplianceMetadata = []cloudsecTypes.ComplianceMetadata{
		{
			ControlID:    "ctrl-abc",
			StandardID:   "std-def",
			StandardName: "Remote Standard",
			ControlName:  "Remote Control",
		},
	}

	model.FromSDKResponse(ctx, &diags, remote)

	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %s", diags.Errors())
	}

	if model.ComplianceMetadata.IsNull() {
		t.Fatal("expected compliance_metadata to be populated from remote, got null")
	}
	if len(model.ComplianceMetadata.Elements()) != 1 {
		t.Fatalf("expected 1 compliance_metadata element from remote, got %d", len(model.ComplianceMetadata.Elements()))
	}
}

// buildBaseModel creates a CloudSecRuleResourceModel with all fields populated
// for use as a baseline in ToSDKUpdateRequest tests.
func buildBaseModel(t *testing.T) CloudSecRuleResourceModel {
	t.Helper()

	assetTypes, d := types.ListValueFrom(context.Background(), types.StringType, []string{"aws-s3-bucket"})
	if d.HasError() {
		t.Fatalf("building asset_types: %s", d.Errors())
	}

	issueObj, d := types.ObjectValue(GetIssueAttrTypes(), map[string]attr.Value{
		"recommendation": types.StringValue("fix it"),
	})
	if d.HasError() {
		t.Fatalf("building issue: %s", d.Errors())
	}

	metadataObj, d := types.ObjectValue(GetMetadataAttrTypes(), map[string]attr.Value{
		"issue": issueObj,
	})
	if d.HasError() {
		t.Fatalf("building metadata: %s", d.Errors())
	}

	queryObj, d := types.ObjectValue(GetQueryAttrTypes(), map[string]attr.Value{
		"xql": types.StringValue("dataset = test"),
	})
	if d.HasError() {
		t.Fatalf("building query: %s", d.Errors())
	}

	labels, d := types.SetValueFrom(context.Background(), types.StringType, []string{"security"})
	if d.HasError() {
		t.Fatalf("building labels: %s", d.Errors())
	}

	cmList := buildComplianceList(t, []map[string]string{
		{
			"control_id":    "ctrl-123",
			"standard_id":   "std-456",
			"standard_name": "Test Standard",
			"control_name":  "Test Control",
		},
	})

	return CloudSecRuleResourceModel{
		ID:                 types.StringValue("test-id"),
		Name:               types.StringValue("test-rule"),
		Description:        types.StringValue("test description"),
		Class:              types.StringValue("config"),
		Type:               types.StringValue("DETECTION"),
		AssetTypes:         assetTypes,
		Severity:           types.StringValue("high"),
		Query:              queryObj,
		Metadata:           metadataObj,
		ComplianceMetadata: cmList,
		Labels:             labels,
		Enabled:            types.BoolValue(true),
	}
}

// marshalUpdateRequest serializes an UpdateRuleRequest to JSON for field-presence assertions.
func marshalUpdateRequest(t *testing.T, req cloudsecTypes.UpdateRuleRequest) map[string]json.RawMessage {
	t.Helper()
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshaling update request: %v", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatalf("unmarshaling update request: %v", err)
	}
	return fields
}

func TestToSDKUpdateRequest_OnlyChangedFields(t *testing.T) {
	// When only name and severity change, only those + rule_class should be in the request.
	ctx := context.Background()
	diags := diag.Diagnostics{}

	prior := buildBaseModel(t)
	plan := buildBaseModel(t)
	plan.Name = types.StringValue("updated-name")
	plan.Severity = types.StringValue("critical")

	req := plan.ToSDKUpdateRequest(ctx, &diags, &prior)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %s", diags.Errors())
	}

	// Verify changed fields are present
	if req.Name != "updated-name" {
		t.Fatalf("expected name='updated-name', got '%s'", req.Name)
	}
	if req.Severity != "critical" {
		t.Fatalf("expected severity='critical', got '%s'", req.Severity)
	}
	// rule_class always present
	if req.Class != "config" {
		t.Fatalf("expected rule_class='config', got '%s'", req.Class)
	}

	// Verify unchanged fields are NOT present (zero values due to omitempty)
	if req.Description != "" {
		t.Fatalf("expected description to be empty (unchanged), got '%s'", req.Description)
	}
	if req.Type != "" {
		t.Fatalf("expected type to be empty (unchanged), got '%s'", req.Type)
	}
	if req.AssetTypes != nil {
		t.Fatalf("expected asset_types to be nil (unchanged), got %v", req.AssetTypes)
	}
	if req.Query != nil {
		t.Fatalf("expected query to be nil (unchanged), got %v", req.Query)
	}
	if req.Metadata != nil {
		t.Fatalf("expected metadata to be nil (unchanged), got %v", req.Metadata)
	}
	if req.ComplianceMetadata != nil {
		t.Fatalf("expected compliance_metadata to be nil (unchanged), got %v", req.ComplianceMetadata)
	}
	if req.Labels != nil {
		t.Fatalf("expected labels to be nil (unchanged), got %v", req.Labels)
	}
	if req.Enabled != nil {
		t.Fatalf("expected enabled to be nil (unchanged), got %v", req.Enabled)
	}

	// Also verify via JSON serialization that only expected fields appear
	fields := marshalUpdateRequest(t, req)
	if _, ok := fields["description"]; ok {
		t.Fatal("description should not be in JSON (unchanged)")
	}
	if _, ok := fields["query"]; ok {
		t.Fatal("query should not be in JSON (unchanged)")
	}
}

func TestToSDKUpdateRequest_NoChanges(t *testing.T) {
	// When plan equals state, only rule_class should be in the request.
	ctx := context.Background()
	diags := diag.Diagnostics{}

	prior := buildBaseModel(t)
	plan := buildBaseModel(t)

	req := plan.ToSDKUpdateRequest(ctx, &diags, &prior)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %s", diags.Errors())
	}

	// rule_class always present
	if req.Class != "config" {
		t.Fatalf("expected rule_class='config', got '%s'", req.Class)
	}

	// Everything else should be zero/nil
	if req.Name != "" {
		t.Fatalf("expected name to be empty, got '%s'", req.Name)
	}
	if req.Description != "" {
		t.Fatalf("expected description to be empty, got '%s'", req.Description)
	}
	if req.Type != "" {
		t.Fatalf("expected type to be empty, got '%s'", req.Type)
	}
	if req.Severity != "" {
		t.Fatalf("expected severity to be empty, got '%s'", req.Severity)
	}
	if req.AssetTypes != nil {
		t.Fatalf("expected asset_types to be nil, got %v", req.AssetTypes)
	}
	if req.Query != nil {
		t.Fatalf("expected query to be nil, got %v", req.Query)
	}
	if req.Metadata != nil {
		t.Fatalf("expected metadata to be nil, got %v", req.Metadata)
	}
	if req.ComplianceMetadata != nil {
		t.Fatalf("expected compliance_metadata to be nil, got %v", req.ComplianceMetadata)
	}
	if req.Labels != nil {
		t.Fatalf("expected labels to be nil, got %v", req.Labels)
	}
	if req.Enabled != nil {
		t.Fatalf("expected enabled to be nil, got %v", req.Enabled)
	}

	// JSON should only contain rule_class
	fields := marshalUpdateRequest(t, req)
	if len(fields) != 1 {
		t.Fatalf("expected exactly 1 field in JSON (rule_class), got %d: %v", len(fields), fields)
	}
	if _, ok := fields["rule_class"]; !ok {
		t.Fatal("expected rule_class in JSON")
	}
}

func TestToSDKUpdateRequest_ComplianceMetadataChangeAlone(t *testing.T) {
	// When only compliance_metadata changes, metadata should NOT be included.
	// This is the key scenario for the API bug workaround.
	ctx := context.Background()
	diags := diag.Diagnostics{}

	prior := buildBaseModel(t)
	plan := buildBaseModel(t)

	// Change compliance_metadata to a different control
	plan.ComplianceMetadata = buildComplianceList(t, []map[string]string{
		{
			"control_id":    "ctrl-999",
			"standard_id":   "std-888",
			"standard_name": "New Standard",
			"control_name":  "New Control",
		},
	})

	req := plan.ToSDKUpdateRequest(ctx, &diags, &prior)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %s", diags.Errors())
	}

	// compliance_metadata should be present
	if req.ComplianceMetadata == nil {
		t.Fatal("expected compliance_metadata to be present")
	}
	if len(req.ComplianceMetadata) != 1 {
		t.Fatalf("expected 1 compliance_metadata entry, got %d", len(req.ComplianceMetadata))
	}
	if req.ComplianceMetadata[0].ControlID != "ctrl-999" {
		t.Fatalf("expected control_id='ctrl-999', got '%s'", req.ComplianceMetadata[0].ControlID)
	}

	// metadata should NOT be present (unchanged)
	if req.Metadata != nil {
		t.Fatal("expected metadata to be nil (unchanged) — sending both triggers API bug")
	}

	// rule_class always present
	if req.Class != "config" {
		t.Fatalf("expected rule_class='config', got '%s'", req.Class)
	}

	// Other fields should not be present
	if req.Name != "" {
		t.Fatalf("expected name to be empty (unchanged), got '%s'", req.Name)
	}
}

func TestToSDKUpdateRequest_MetadataChangeAlone(t *testing.T) {
	// When only metadata changes, compliance_metadata should NOT be included.
	ctx := context.Background()
	diags := diag.Diagnostics{}

	prior := buildBaseModel(t)
	plan := buildBaseModel(t)

	// Change metadata recommendation
	newIssueObj, d := types.ObjectValue(GetIssueAttrTypes(), map[string]attr.Value{
		"recommendation": types.StringValue("new recommendation"),
	})
	if d.HasError() {
		t.Fatalf("building issue: %s", d.Errors())
	}
	newMetadataObj, d := types.ObjectValue(GetMetadataAttrTypes(), map[string]attr.Value{
		"issue": newIssueObj,
	})
	if d.HasError() {
		t.Fatalf("building metadata: %s", d.Errors())
	}
	plan.Metadata = newMetadataObj

	req := plan.ToSDKUpdateRequest(ctx, &diags, &prior)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %s", diags.Errors())
	}

	// metadata should be present with new value
	if req.Metadata == nil {
		t.Fatal("expected metadata to be present")
	}
	if req.Metadata.Issue == nil {
		t.Fatal("expected metadata.issue to be present")
	}
	if req.Metadata.Issue.Recommendation != "new recommendation" {
		t.Fatalf("expected recommendation='new recommendation', got '%s'", req.Metadata.Issue.Recommendation)
	}

	// compliance_metadata should NOT be present (unchanged)
	if req.ComplianceMetadata != nil {
		t.Fatal("expected compliance_metadata to be nil (unchanged)")
	}

	// rule_class always present
	if req.Class != "config" {
		t.Fatalf("expected rule_class='config', got '%s'", req.Class)
	}
}

func TestToSDKUpdateRequest_ClassAlwaysIncluded(t *testing.T) {
	// Verify rule_class is always present even when nothing changes,
	// and also when class itself changes.
	ctx := context.Background()
	diags := diag.Diagnostics{}

	// Sub-test 1: No changes at all — class still present
	t.Run("no_changes", func(t *testing.T) {
		prior := buildBaseModel(t)
		plan := buildBaseModel(t)

		req := plan.ToSDKUpdateRequest(ctx, &diags, &prior)
		if diags.HasError() {
			t.Fatalf("unexpected diagnostics: %s", diags.Errors())
		}

		if req.Class != "config" {
			t.Fatalf("expected rule_class='config', got '%s'", req.Class)
		}

		fields := marshalUpdateRequest(t, req)
		if _, ok := fields["rule_class"]; !ok {
			t.Fatal("rule_class must always be in JSON output")
		}
	})

	// Sub-test 2: Class changes — new value used
	t.Run("class_changes", func(t *testing.T) {
		prior := buildBaseModel(t)
		plan := buildBaseModel(t)
		plan.Class = types.StringValue("runtime")

		req := plan.ToSDKUpdateRequest(ctx, &diags, &prior)
		if diags.HasError() {
			t.Fatalf("unexpected diagnostics: %s", diags.Errors())
		}

		if req.Class != "runtime" {
			t.Fatalf("expected rule_class='runtime', got '%s'", req.Class)
		}
	})
}
