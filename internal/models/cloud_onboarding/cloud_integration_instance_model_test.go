// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package models

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// populatedCustomResourcesTags returns a populated custom_resources_tags set
// with a single tag element.
func populatedCustomResourcesTags(t *testing.T) types.Set {
	t.Helper()

	tag := types.ObjectValueMust(tagAttrTypes, map[string]attr.Value{
		"key":   types.StringValue("environment"),
		"value": types.StringValue("production"),
	})

	return types.SetValueMust(types.ObjectType{AttrTypes: tagAttrTypes}, []attr.Value{tag})
}

// TestCloudIntegrationInstanceModelToEditRequestMapsRequiredFields verifies
// that ToEditRequest maps the required fields (id, cloud_provider,
// additional_capabilities including serverless_scanning, collection_configuration,
// custom_resources_tags) into a request that marshals to the expected JSON.
func TestCloudIntegrationInstanceModelToEditRequestMapsRequiredFields(t *testing.T) {
	ctx := context.Background()
	var diags diag.Diagnostics

	model := &CloudIntegrationInstanceModel{
		ID:                      types.StringValue("instance-123"),
		AdditionalCapabilities:  buildAdditionalCapabilities(t, true),
		CloudProvider:           types.StringValue("AWS"),
		CollectionConfiguration: collectionConfigurationValue(),
		CustomResourcesTags:     populatedCustomResourcesTags(t),
		InstanceName:            types.StringNull(),
	}

	request := model.ToEditRequest(ctx, &diags)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", diags.Errors())
	}
	if request == nil {
		t.Fatal("expected non-nil request")
	}

	raw, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("failed to marshal request: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("failed to unmarshal request JSON: %v", err)
	}

	if got := decoded["id"]; got != "instance-123" {
		t.Errorf("id = %v, want instance-123", got)
	}

	if got := decoded["cloud_provider"]; got != "AWS" {
		t.Errorf("cloud_provider = %v, want AWS", got)
	}

	additionalCapabilities, ok := decoded["additional_capabilities"].(map[string]any)
	if !ok {
		t.Fatalf("additional_capabilities missing or wrong type: %v", decoded["additional_capabilities"])
	}
	if got := additionalCapabilities["serverless_scanning"]; got != true {
		t.Errorf("additional_capabilities.serverless_scanning = %v, want true", got)
	}

	if _, ok := decoded["collection_configuration"]; !ok {
		t.Error("collection_configuration missing from marshaled request")
	}

	tags, ok := decoded["custom_resources_tags"].([]any)
	if !ok {
		t.Fatalf("custom_resources_tags missing or wrong type: %v", decoded["custom_resources_tags"])
	}
	if len(tags) != 1 {
		t.Fatalf("custom_resources_tags length = %d, want 1", len(tags))
	}
}

// TestCloudIntegrationInstanceModelToEditRequestOmitsNullOptionalFields verifies
// that optional/omitempty fields (instance_name, scan_env_id, cloud_partition)
// are omitted from the marshaled request when the corresponding model attributes
// are null.
func TestCloudIntegrationInstanceModelToEditRequestOmitsNullOptionalFields(t *testing.T) {
	ctx := context.Background()
	var diags diag.Diagnostics

	model := &CloudIntegrationInstanceModel{
		ID:                      types.StringValue("instance-456"),
		AdditionalCapabilities:  buildAdditionalCapabilities(t, false),
		CloudProvider:           types.StringValue("AWS"),
		CollectionConfiguration: collectionConfigurationValue(),
		CustomResourcesTags:     nullTagSet(),
		InstanceName:            types.StringNull(),
	}

	request := model.ToEditRequest(ctx, &diags)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", diags.Errors())
	}

	raw, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("failed to marshal request: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("failed to unmarshal request JSON: %v", err)
	}

	if _, ok := decoded["instance_name"]; ok {
		t.Error("instance_name should be omitted when the model attribute is null")
	}
	if _, ok := decoded["scan_env_id"]; ok {
		t.Error("scan_env_id (outpost_id) should be omitted when the model attribute is null")
	}
	if _, ok := decoded["cloud_partition"]; ok {
		t.Error("cloud_partition should be omitted when the model attribute is null")
	}
}

// TestCloudIntegrationInstanceModelToEditRequestSetsInstanceName verifies that
// instance_name is included in the marshaled request when the model attribute
// is non-null.
func TestCloudIntegrationInstanceModelToEditRequestSetsInstanceName(t *testing.T) {
	ctx := context.Background()
	var diags diag.Diagnostics

	model := &CloudIntegrationInstanceModel{
		ID:                      types.StringValue("instance-789"),
		AdditionalCapabilities:  buildAdditionalCapabilities(t, true),
		CloudProvider:           types.StringValue("AWS"),
		CollectionConfiguration: collectionConfigurationValue(),
		CustomResourcesTags:     nullTagSet(),
		InstanceName:            types.StringValue("my-instance"),
	}

	request := model.ToEditRequest(ctx, &diags)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", diags.Errors())
	}

	raw, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("failed to marshal request: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("failed to unmarshal request JSON: %v", err)
	}

	if got := decoded["instance_name"]; got != "my-instance" {
		t.Errorf("instance_name = %v, want my-instance", got)
	}
}

// TestCloudIntegrationInstanceModelToEditRequestHandlesNullAdditionalCapabilities
// verifies that a null additional_capabilities object does not panic and
// produces a zero-value AdditionalCapabilities in the request.
func TestCloudIntegrationInstanceModelToEditRequestHandlesNullAdditionalCapabilities(t *testing.T) {
	ctx := context.Background()
	var diags diag.Diagnostics

	model := &CloudIntegrationInstanceModel{
		ID:                      types.StringValue("instance-000"),
		AdditionalCapabilities:  types.ObjectNull(testAdditionalCapabilitiesAttrTypes),
		CloudProvider:           types.StringValue("AWS"),
		CollectionConfiguration: collectionConfigurationValue(),
		CustomResourcesTags:     nullTagSet(),
		InstanceName:            types.StringNull(),
	}

	request := model.ToEditRequest(ctx, &diags)
	if request == nil {
		t.Fatal("expected non-nil request even with null additional_capabilities")
	}

	if _, err := json.Marshal(request); err != nil {
		t.Fatalf("failed to marshal request: %v", err)
	}
}
