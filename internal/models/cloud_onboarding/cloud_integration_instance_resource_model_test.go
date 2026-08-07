// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package models

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	cloudOnboardingTypes "github.com/PaloAltoNetworks/cortex-cloud-go/types/cloudonboarding"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// fullScopeModificationsAttrTypes mirrors the SDK ScopeModifications struct
// (accounts, projects, subscriptions, regions) which the resource schema must
// expose so that the terraform-plugin-framework object conversion matches the
// struct field-for-field.
func fullScopeModificationsAttrTypes() map[string]attr.Type {
	genericType := types.ObjectType{AttrTypes: map[string]attr.Type{
		"enabled":          types.BoolType,
		"type":             types.StringType,
		"account_ids":      types.SetType{ElemType: types.StringType},
		"project_ids":      types.SetType{ElemType: types.StringType},
		"subscription_ids": types.SetType{ElemType: types.StringType},
	}}
	regionsType := types.ObjectType{AttrTypes: map[string]attr.Type{
		"enabled": types.BoolType,
		"type":    types.StringType,
		"regions": types.SetType{ElemType: types.StringType},
	}}
	return map[string]attr.Type{
		"accounts":      genericType,
		"projects":      genericType,
		"subscriptions": genericType,
		"regions":       regionsType,
	}
}

// fullScopeModificationsValue returns a scope_modifications object populated with
// a disabled regions block and null generic blocks, matching the SDK struct.
func fullScopeModificationsValue() types.Object {
	attrTypes := fullScopeModificationsAttrTypes()
	regions := types.ObjectValueMust(
		attrTypes["regions"].(types.ObjectType).AttrTypes,
		map[string]attr.Value{
			"enabled": types.BoolValue(false),
			"type":    types.StringNull(),
			"regions": types.SetNull(types.StringType),
		},
	)
	genericType := attrTypes["accounts"].(types.ObjectType)
	return types.ObjectValueMust(attrTypes, map[string]attr.Value{
		"accounts":      types.ObjectNull(genericType.AttrTypes),
		"projects":      types.ObjectNull(genericType.AttrTypes),
		"subscriptions": types.ObjectNull(genericType.AttrTypes),
		"regions":       regions,
	})
}

// TestCloudIntegrationInstanceResourceModelToEditRequestMapsRequiredFields
// verifies that the resource model's ToEditRequest maps the required fields
// (id, cloud_provider, additional_capabilities including serverless_scanning,
// collection_configuration, custom_resources_tags) into a request that marshals
// to the expected JSON.
func TestCloudIntegrationInstanceResourceModelToEditRequestMapsRequiredFields(t *testing.T) {
	ctx := context.Background()
	var diags diag.Diagnostics

	model := &CloudIntegrationInstanceResourceModel{
		ID:                      types.StringValue("instance-123"),
		AdditionalCapabilities:  buildAdditionalCapabilities(t, true),
		CloudProvider:           types.StringValue("AWS"),
		CollectionConfiguration: collectionConfigurationValue(),
		CustomResourcesTags:     populatedCustomResourcesTags(t),
		InstanceName:            types.StringNull(),
		OutpostID:               types.StringNull(),
		CloudPartition:          types.StringNull(),
		ScopeModifications:      types.ObjectNull(fullScopeModificationsAttrTypes()),
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

// TestCloudIntegrationInstanceResourceModelToEditRequestOmitsNullOptionalFields
// verifies that optional/omitempty write-only fields (instance_name, scan_env_id,
// cloud_partition, scope_modifications) are omitted from the marshaled request
// when the corresponding model attributes are null.
func TestCloudIntegrationInstanceResourceModelToEditRequestOmitsNullOptionalFields(t *testing.T) {
	ctx := context.Background()
	var diags diag.Diagnostics

	model := &CloudIntegrationInstanceResourceModel{
		ID:                      types.StringValue("instance-456"),
		AdditionalCapabilities:  buildAdditionalCapabilities(t, false),
		CloudProvider:           types.StringValue("AWS"),
		CollectionConfiguration: collectionConfigurationValue(),
		CustomResourcesTags:     nullTagSet(),
		InstanceName:            types.StringNull(),
		OutpostID:               types.StringNull(),
		CloudPartition:          types.StringNull(),
		ScopeModifications:      types.ObjectNull(fullScopeModificationsAttrTypes()),
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

// TestCloudIntegrationInstanceResourceModelToEditRequestWiresWriteOnlyFields
// verifies that the resource-specific write-only fields (outpost_id → scan_env_id,
// cloud_partition, scope_modifications) are wired into the marshaled request when
// the corresponding model attributes are configured.
func TestCloudIntegrationInstanceResourceModelToEditRequestWiresWriteOnlyFields(t *testing.T) {
	ctx := context.Background()
	var diags diag.Diagnostics

	model := &CloudIntegrationInstanceResourceModel{
		ID:                      types.StringValue("instance-789"),
		AdditionalCapabilities:  buildAdditionalCapabilities(t, true),
		CloudProvider:           types.StringValue("AWS"),
		CollectionConfiguration: collectionConfigurationValue(),
		CustomResourcesTags:     nullTagSet(),
		InstanceName:            types.StringValue("my-instance"),
		OutpostID:               types.StringValue("outpost-1"),
		CloudPartition:          types.StringValue("aws-us-gov"),
		ScopeModifications:      fullScopeModificationsValue(),
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

	if got := decoded["instance_name"]; got != "my-instance" {
		t.Errorf("instance_name = %v, want my-instance", got)
	}
	if got := decoded["scan_env_id"]; got != "outpost-1" {
		t.Errorf("scan_env_id = %v, want outpost-1", got)
	}
	if got := decoded["cloud_partition"]; got != "aws-us-gov" {
		t.Errorf("cloud_partition = %v, want aws-us-gov", got)
	}
	if _, ok := decoded["scope_modifications"]; !ok {
		t.Error("scope_modifications missing from marshaled request when configured")
	}
}

// TestCloudIntegrationInstanceResourceModelToEditRequestHandlesNullAdditionalCapabilities
// verifies that a null additional_capabilities object does not panic and
// produces a non-nil request.
func TestCloudIntegrationInstanceResourceModelToEditRequestHandlesNullAdditionalCapabilities(t *testing.T) {
	ctx := context.Background()
	var diags diag.Diagnostics

	model := &CloudIntegrationInstanceResourceModel{
		ID:                      types.StringValue("instance-000"),
		AdditionalCapabilities:  types.ObjectNull(testAdditionalCapabilitiesAttrTypes),
		CloudProvider:           types.StringValue("AWS"),
		CollectionConfiguration: collectionConfigurationValue(),
		CustomResourcesTags:     nullTagSet(),
		InstanceName:            types.StringNull(),
		OutpostID:               types.StringNull(),
		CloudPartition:          types.StringNull(),
		ScopeModifications:      types.ObjectNull(fullScopeModificationsAttrTypes()),
	}

	request := model.ToEditRequest(ctx, &diags)
	if request == nil {
		t.Fatal("expected non-nil request even with null additional_capabilities")
	}

	if _, err := json.Marshal(request); err != nil {
		t.Fatalf("failed to marshal request: %v", err)
	}
}

// buildAdditionalCapabilitiesWithNullBools constructs an additional_capabilities
// object where every boolean attribute is null. It is used to prove that
// ToEditRequest coerces unset capability booleans to concrete false values
// (the edit_instance contract rejects null booleans).
func buildAdditionalCapabilitiesWithNullBools() types.Object {
	return types.ObjectValueMust(
		testAdditionalCapabilitiesAttrTypes,
		map[string]attr.Value{
			"data_security_posture_management": types.BoolNull(),
			"registry_scanning":                types.BoolNull(),
			"registry_scanning_options":        types.ObjectNull(registryScanningOptionsAttrTypes),
			"agentless_disk_scanning":          types.BoolNull(),
			"xsiam_analytics":                  types.BoolNull(),
			"serverless_scanning":              types.BoolNull(),
		},
	)
}

// TestCloudIntegrationInstanceResourceModelToEditRequestCoercesNullCapabilityBools
// verifies that unset (null) additional_capabilities booleans are serialized as
// concrete false values, satisfying the edit_instance contract which rejects
// null booleans.
func TestCloudIntegrationInstanceResourceModelToEditRequestCoercesNullCapabilityBools(t *testing.T) {
	ctx := context.Background()
	var diags diag.Diagnostics

	model := &CloudIntegrationInstanceResourceModel{
		ID:                      types.StringValue("instance-null-bools"),
		AdditionalCapabilities:  buildAdditionalCapabilitiesWithNullBools(),
		CloudProvider:           types.StringValue("AWS"),
		CollectionConfiguration: collectionConfigurationValue(),
		CustomResourcesTags:     nullTagSet(),
		InstanceName:            types.StringNull(),
		OutpostID:               types.StringNull(),
		CloudPartition:          types.StringNull(),
		ScopeModifications:      types.ObjectNull(fullScopeModificationsAttrTypes()),
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

	ac, ok := decoded["additional_capabilities"].(map[string]any)
	if !ok {
		t.Fatalf("additional_capabilities missing or wrong type: %v", decoded["additional_capabilities"])
	}

	for _, field := range []string{
		"data_security_posture_management",
		"registry_scanning",
		"agentless_disk_scanning",
		"xsiam_analytics",
		"serverless_scanning",
	} {
		got, present := ac[field]
		if !present {
			t.Errorf("additional_capabilities.%s missing from marshaled request", field)
			continue
		}
		if got == nil {
			t.Errorf("additional_capabilities.%s = null, want a concrete boolean (false)", field)
			continue
		}
		if got != false {
			t.Errorf("additional_capabilities.%s = %v, want false", field, got)
		}
	}
}

// TestCloudIntegrationInstanceResourceModelToEditRequestSendsEmptyTagsList
// verifies that a null/absent custom_resources_tags model attribute serializes
// as an empty JSON list ([]) rather than null, satisfying the edit_instance
// contract which requires the field to be a list.
func TestCloudIntegrationInstanceResourceModelToEditRequestSendsEmptyTagsList(t *testing.T) {
	ctx := context.Background()
	var diags diag.Diagnostics

	model := &CloudIntegrationInstanceResourceModel{
		ID:                      types.StringValue("instance-empty-tags"),
		AdditionalCapabilities:  buildAdditionalCapabilities(t, true),
		CloudProvider:           types.StringValue("AWS"),
		CollectionConfiguration: collectionConfigurationValue(),
		CustomResourcesTags:     nullTagSet(),
		InstanceName:            types.StringNull(),
		OutpostID:               types.StringNull(),
		CloudPartition:          types.StringNull(),
		ScopeModifications:      types.ObjectNull(fullScopeModificationsAttrTypes()),
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

	tags, ok := decoded["custom_resources_tags"]
	if !ok {
		t.Fatal("custom_resources_tags missing from marshaled request; want []")
	}
	if tags == nil {
		t.Fatal("custom_resources_tags = null, want an empty list []")
	}
	list, ok := tags.([]any)
	if !ok {
		t.Fatalf("custom_resources_tags wrong type: %T, want []any", tags)
	}
	if len(list) != 0 {
		t.Errorf("custom_resources_tags length = %d, want 0", len(list))
	}
}

// scopeModificationsWithoutRegions returns a scope_modifications object that
// configures a generic block (accounts) but leaves the regions block null. It
// is used to prove that ToEditRequest injects a regions block when
// scope_modifications is sent without one.
func scopeModificationsWithoutRegions() types.Object {
	attrTypes := fullScopeModificationsAttrTypes()
	genericType := attrTypes["accounts"].(types.ObjectType)
	accounts := types.ObjectValueMust(genericType.AttrTypes, map[string]attr.Value{
		"enabled":          types.BoolValue(true),
		"type":             types.StringNull(),
		"account_ids":      types.SetNull(types.StringType),
		"project_ids":      types.SetNull(types.StringType),
		"subscription_ids": types.SetNull(types.StringType),
	})
	return types.ObjectValueMust(attrTypes, map[string]attr.Value{
		"accounts":      accounts,
		"projects":      types.ObjectNull(genericType.AttrTypes),
		"subscriptions": types.ObjectNull(genericType.AttrTypes),
		"regions":       types.ObjectNull(attrTypes["regions"].(types.ObjectType).AttrTypes),
	})
}

// TestCloudIntegrationInstanceResourceModelToEditRequestInjectsScopeRegions
// verifies that when scope_modifications is sent without a regions block, a
// (disabled) regions block is injected, satisfying the edit_instance contract
// which requires scope_modifications.regions whenever scope_modifications is
// present.
func TestCloudIntegrationInstanceResourceModelToEditRequestInjectsScopeRegions(t *testing.T) {
	ctx := context.Background()
	var diags diag.Diagnostics

	model := &CloudIntegrationInstanceResourceModel{
		ID:                      types.StringValue("instance-scope-regions"),
		AdditionalCapabilities:  buildAdditionalCapabilities(t, true),
		CloudProvider:           types.StringValue("AWS"),
		CollectionConfiguration: collectionConfigurationValue(),
		CustomResourcesTags:     nullTagSet(),
		InstanceName:            types.StringNull(),
		OutpostID:               types.StringNull(),
		CloudPartition:          types.StringNull(),
		ScopeModifications:      scopeModificationsWithoutRegions(),
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

	scope, ok := decoded["scope_modifications"].(map[string]any)
	if !ok {
		t.Fatalf("scope_modifications missing or wrong type: %v", decoded["scope_modifications"])
	}
	regions, ok := scope["regions"].(map[string]any)
	if !ok {
		t.Fatalf("scope_modifications.regions missing or wrong type: %v", scope["regions"])
	}
	if got := regions["enabled"]; got != false {
		t.Errorf("scope_modifications.regions.enabled = %v, want false", got)
	}
}

// TestCloudIntegrationInstanceResourceModelToEditRequestDropsRegistryOptionsWhenScanningOff
// verifies the registry coupling rule: when registry_scanning is disabled, the
// registry_scanning_options block is dropped so the request contains "neither"
// rather than an orphaned options block (the edit_instance contract requires
// both or neither).
func TestCloudIntegrationInstanceResourceModelToEditRequestDropsRegistryOptionsWhenScanningOff(t *testing.T) {
	ctx := context.Background()
	var diags diag.Diagnostics

	// buildAdditionalCapabilities always populates registry_scanning_options with
	// {type: "ALL"}; passing registryScanning=false makes them inconsistent, which
	// ToEditRequest must reconcile by dropping the options.
	model := &CloudIntegrationInstanceResourceModel{
		ID:                      types.StringValue("instance-registry-off"),
		AdditionalCapabilities:  buildAdditionalCapabilities(t, false),
		CloudProvider:           types.StringValue("AWS"),
		CollectionConfiguration: collectionConfigurationValue(),
		CustomResourcesTags:     nullTagSet(),
		InstanceName:            types.StringNull(),
		OutpostID:               types.StringNull(),
		CloudPartition:          types.StringNull(),
		ScopeModifications:      types.ObjectNull(fullScopeModificationsAttrTypes()),
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

	ac, ok := decoded["additional_capabilities"].(map[string]any)
	if !ok {
		t.Fatalf("additional_capabilities missing or wrong type: %v", decoded["additional_capabilities"])
	}
	if got := ac["registry_scanning"]; got != false {
		t.Errorf("additional_capabilities.registry_scanning = %v, want false", got)
	}
	if _, present := ac["registry_scanning_options"]; present {
		t.Errorf("additional_capabilities.registry_scanning_options should be dropped when registry_scanning is off; got %v", ac["registry_scanning_options"])
	}
}

// TestCloudIntegrationInstanceResourceModelToEditRequestKeepsRegistryOptionsWhenScanningOn
// verifies the registry coupling rule from the other direction: when
// registry_scanning is enabled, the registry_scanning_options block is retained.
func TestCloudIntegrationInstanceResourceModelToEditRequestKeepsRegistryOptionsWhenScanningOn(t *testing.T) {
	ctx := context.Background()
	var diags diag.Diagnostics

	model := &CloudIntegrationInstanceResourceModel{
		ID:                      types.StringValue("instance-registry-on"),
		AdditionalCapabilities:  buildAdditionalCapabilities(t, true),
		CloudProvider:           types.StringValue("AWS"),
		CollectionConfiguration: collectionConfigurationValue(),
		CustomResourcesTags:     nullTagSet(),
		InstanceName:            types.StringNull(),
		OutpostID:               types.StringNull(),
		CloudPartition:          types.StringNull(),
		ScopeModifications:      types.ObjectNull(fullScopeModificationsAttrTypes()),
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

	ac, ok := decoded["additional_capabilities"].(map[string]any)
	if !ok {
		t.Fatalf("additional_capabilities missing or wrong type: %v", decoded["additional_capabilities"])
	}
	if got := ac["registry_scanning"]; got != true {
		t.Errorf("additional_capabilities.registry_scanning = %v, want true", got)
	}
	if _, present := ac["registry_scanning_options"]; !present {
		t.Error("additional_capabilities.registry_scanning_options should be retained when registry_scanning is on")
	}
}

// collectionConfigurationAttrTypesForTest mirrors the attribute types of the
// collection_configuration object as exposed by the resource schema, so a typed
// null object can be constructed for MergeFromRemote tests.
func collectionConfigurationAttrTypesForTest() map[string]attr.Type {
	return map[string]attr.Type{
		"audit_logs": types.ObjectType{AttrTypes: map[string]attr.Type{
			"enabled":           types.BoolType,
			"collection_method": types.StringType,
			"data_events":       types.BoolType,
		}},
	}
}

// remoteInstance returns an IntegrationInstance representing live server state
// used to exercise MergeFromRemote.
func remoteInstance() cloudOnboardingTypes.IntegrationInstance {
	trueValue := true
	falseValue := false
	return cloudOnboardingTypes.IntegrationInstance{
		ID:            "instance-merge",
		CloudProvider: "AWS",
		InstanceName:  "live-instance-name",
		AdditionalCapabilities: cloudOnboardingTypes.AdditionalCapabilities{
			XSIAMAnalytics:                &trueValue,
			DataSecurityPostureManagement: &falseValue,
			RegistryScanning:              &falseValue,
			ServerlessScanning:            &trueValue,
			AgentlessDiskScanning:         &trueValue,
		},
		CollectionConfiguration: cloudOnboardingTypes.CollectionConfiguration{
			AuditLogs: cloudOnboardingTypes.AuditLogsConfiguration{
				Enabled:          true,
				CollectionMethod: "AUTOMATED",
				DataEvents:       false,
			},
		},
		CustomResourcesTags: []cloudOnboardingTypes.Tag{{Key: "owner", Value: "platform"}},
	}
}

// TestCloudIntegrationInstanceResourceModelMergeFromRemoteFillsUnspecifiedFields
// verifies that MergeFromRemote overlays live instance values onto the model for
// editable fields the plan leaves null, so a full-replace edit does not blank
// server-side state.
func TestCloudIntegrationInstanceResourceModelMergeFromRemoteFillsUnspecifiedFields(t *testing.T) {
	ctx := context.Background()
	var diags diag.Diagnostics

	// A plan with all editable fields unspecified (typed-null). The object attr
	// types must be set so MergeFromRemote can build the merged objects.
	model := &CloudIntegrationInstanceResourceModel{
		ID:                      types.StringValue("instance-merge"),
		CloudProvider:           types.StringNull(),
		InstanceName:            types.StringNull(),
		AdditionalCapabilities:  types.ObjectNull(testAdditionalCapabilitiesAttrTypes),
		CollectionConfiguration: types.ObjectNull(collectionConfigurationAttrTypesForTest()),
		CustomResourcesTags:     nullTagSet(),
	}

	model.MergeFromRemote(ctx, &diags, remoteInstance())
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", diags.Errors())
	}

	if got := model.CloudProvider.ValueString(); got != "AWS" {
		t.Errorf("cloud_provider = %q, want AWS (merged from remote)", got)
	}
	if got := model.InstanceName.ValueString(); got != "live-instance-name" {
		t.Errorf("instance_name = %q, want live-instance-name (merged from remote)", got)
	}
	if model.AdditionalCapabilities.IsNull() {
		t.Error("additional_capabilities should be filled from remote, got null")
	}
	if model.CollectionConfiguration.IsNull() {
		t.Error("collection_configuration should be filled from remote, got null")
	}
	if model.CustomResourcesTags.IsNull() {
		t.Error("custom_resources_tags should be filled from remote, got null")
	}
}

// TestCloudIntegrationInstanceResourceModelMergeFromRemotePreservesConfiguredFields
// verifies that MergeFromRemote leaves practitioner-configured (non-null) fields
// untouched, so only intentionally-set values diverge from live state.
func TestCloudIntegrationInstanceResourceModelMergeFromRemotePreservesConfiguredFields(t *testing.T) {
	ctx := context.Background()
	var diags diag.Diagnostics

	model := &CloudIntegrationInstanceResourceModel{
		ID:                      types.StringValue("instance-merge"),
		CloudProvider:           types.StringValue("AWS"),
		InstanceName:            types.StringValue("configured-name"),
		AdditionalCapabilities:  buildAdditionalCapabilities(t, true),
		CollectionConfiguration: collectionConfigurationValue(),
		CustomResourcesTags:     populatedCustomResourcesTags(t),
	}

	model.MergeFromRemote(ctx, &diags, remoteInstance())
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", diags.Errors())
	}

	if got := model.InstanceName.ValueString(); got != "configured-name" {
		t.Errorf("instance_name = %q, want configured-name (must not be overwritten by remote)", got)
	}
}

// TestCloudIntegrationInstanceResourceModelMergeFromRemoteInheritsUnspecifiedCapabilities
// verifies the per-attribute merge: when the practitioner configures one
// capability and leaves its siblings unknown, the siblings must inherit their
// live server values. edit_instance is a full-replace, so an unknown sibling
// that falls through to false silently disables a live capability.
func TestCloudIntegrationInstanceResourceModelMergeFromRemoteInheritsUnspecifiedCapabilities(t *testing.T) {
	ctx := context.Background()
	var diags diag.Diagnostics

	// Mirrors a real plan: serverless_scanning explicitly set, every sibling
	// unknown because the schema marks them Optional+Computed.
	plannedCapabilities := types.ObjectValueMust(
		testAdditionalCapabilitiesAttrTypes,
		map[string]attr.Value{
			"serverless_scanning":              types.BoolValue(true),
			"data_security_posture_management": types.BoolUnknown(),
			"registry_scanning":                types.BoolUnknown(),
			"registry_scanning_options":        types.ObjectUnknown(registryScanningOptionsAttrTypes),
			"agentless_disk_scanning":          types.BoolUnknown(),
			"xsiam_analytics":                  types.BoolUnknown(),
		},
	)

	model := &CloudIntegrationInstanceResourceModel{
		ID:                      types.StringValue("instance-merge"),
		CloudProvider:           types.StringValue("AWS"),
		InstanceName:            types.StringNull(),
		AdditionalCapabilities:  plannedCapabilities,
		CollectionConfiguration: types.ObjectNull(collectionConfigurationAttrTypesForTest()),
		CustomResourcesTags:     nullTagSet(),
	}

	model.MergeFromRemote(ctx, &diags, remoteInstance())
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", diags.Errors())
	}

	merged := model.AdditionalCapabilities.Attributes()

	// The configured attribute must survive the merge untouched.
	if got := merged["serverless_scanning"].(types.Bool); !got.ValueBool() {
		t.Errorf("serverless_scanning = %v, want true (practitioner-configured)", got)
	}

	// remoteInstance has xsiam_analytics and agentless_disk_scanning enabled;
	// leaving them unconfigured must not turn them off.
	if got := merged["xsiam_analytics"].(types.Bool); got.IsUnknown() || !got.ValueBool() {
		t.Errorf("xsiam_analytics = %v, want true (inherited from live state)", got)
	}
	if got := merged["agentless_disk_scanning"].(types.Bool); got.IsUnknown() || !got.ValueBool() {
		t.Errorf("agentless_disk_scanning = %v, want true (inherited from live state)", got)
	}

	// Capabilities disabled server-side must stay disabled, not become unknown.
	if got := merged["registry_scanning"].(types.Bool); got.IsUnknown() || got.ValueBool() {
		t.Errorf("registry_scanning = %v, want false (inherited from live state)", got)
	}

	for name, value := range merged {
		if value.IsUnknown() {
			t.Errorf("additional_capabilities.%s is still unknown after merge", name)
		}
	}
}

// TestCloudIntegrationInstanceResourceModelEditRequestPreservesUndeclaredCapabilities
// is the wire-level guard for the full-replace data-loss defect. It runs the
// real Update sequence (MergeFromRemote then ToEditRequest) and asserts the
// serialized body still enables a capability the practitioner never declared.
// Without the per-attribute merge that capability serializes as false and the
// API disables it.
func TestCloudIntegrationInstanceResourceModelEditRequestPreservesUndeclaredCapabilities(t *testing.T) {
	ctx := context.Background()
	var diags diag.Diagnostics

	plannedCapabilities := types.ObjectValueMust(
		testAdditionalCapabilitiesAttrTypes,
		map[string]attr.Value{
			"serverless_scanning":              types.BoolValue(true),
			"data_security_posture_management": types.BoolUnknown(),
			"registry_scanning":                types.BoolUnknown(),
			"registry_scanning_options":        types.ObjectUnknown(registryScanningOptionsAttrTypes),
			"agentless_disk_scanning":          types.BoolUnknown(),
			"xsiam_analytics":                  types.BoolUnknown(),
		},
	)

	model := &CloudIntegrationInstanceResourceModel{
		ID:                      types.StringValue("instance-merge"),
		CloudProvider:           types.StringValue("AWS"),
		InstanceName:            types.StringNull(),
		AdditionalCapabilities:  plannedCapabilities,
		CollectionConfiguration: types.ObjectNull(collectionConfigurationAttrTypesForTest()),
		CustomResourcesTags:     nullTagSet(),
		OutpostID:               types.StringValue("outpost-1"),
		CloudPartition:          types.StringNull(),
		ScopeModifications:      types.ObjectNull(fullScopeModificationsAttrTypes()),
	}

	model.MergeFromRemote(ctx, &diags, remoteInstance())
	if diags.HasError() {
		t.Fatalf("unexpected merge diagnostics: %v", diags.Errors())
	}

	request := model.ToEditRequest(ctx, &diags)
	if diags.HasError() {
		t.Fatalf("unexpected request diagnostics: %v", diags.Errors())
	}

	raw, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("failed to marshal request: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("failed to unmarshal request JSON: %v", err)
	}

	capabilities, ok := decoded["additional_capabilities"].(map[string]any)
	if !ok {
		t.Fatalf("additional_capabilities missing or wrong type: %v", decoded["additional_capabilities"])
	}

	if got := capabilities["serverless_scanning"]; got != true {
		t.Errorf("serverless_scanning = %v, want true (practitioner-configured)", got)
	}
	if got := capabilities["xsiam_analytics"]; got != true {
		t.Errorf("xsiam_analytics = %v, want true: an undeclared capability enabled "+
			"server-side must not be sent as false by a full-replace edit", got)
	}
	if got := capabilities["agentless_disk_scanning"]; got != true {
		t.Errorf("agentless_disk_scanning = %v, want true (enabled server-side)", got)
	}
}

// TestCloudIntegrationInstanceResourceModelMergeFromRemoteInheritsNestedCollectionAttributes
// verifies the merge recurses into nested objects: configuring one attribute of
// collection_configuration.audit_logs must not blank its siblings.
func TestCloudIntegrationInstanceResourceModelMergeFromRemoteInheritsNestedCollectionAttributes(t *testing.T) {
	ctx := context.Background()
	var diags diag.Diagnostics

	attrTypes := collectionConfigurationAttrTypesForTest()
	auditLogsType := attrTypes["audit_logs"].(types.ObjectType)
	plannedCollection := types.ObjectValueMust(attrTypes, map[string]attr.Value{
		"audit_logs": types.ObjectValueMust(auditLogsType.AttrTypes, map[string]attr.Value{
			"enabled":           types.BoolValue(true),
			"collection_method": types.StringUnknown(),
			"data_events":       types.BoolUnknown(),
		}),
	})

	model := &CloudIntegrationInstanceResourceModel{
		ID:                      types.StringValue("instance-merge"),
		CloudProvider:           types.StringValue("AWS"),
		InstanceName:            types.StringNull(),
		AdditionalCapabilities:  types.ObjectNull(testAdditionalCapabilitiesAttrTypes),
		CollectionConfiguration: plannedCollection,
		CustomResourcesTags:     nullTagSet(),
	}

	model.MergeFromRemote(ctx, &diags, remoteInstance())
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", diags.Errors())
	}

	auditLogs := model.CollectionConfiguration.Attributes()["audit_logs"].(types.Object).Attributes()

	if got := auditLogs["enabled"].(types.Bool); !got.ValueBool() {
		t.Errorf("audit_logs.enabled = %v, want true (practitioner-configured)", got)
	}
	if got := auditLogs["collection_method"].(types.String); got.ValueString() != "AUTOMATED" {
		t.Errorf("audit_logs.collection_method = %v, want AUTOMATED (inherited from live state)", got)
	}
	if got := auditLogs["data_events"].(types.Bool); got.IsUnknown() {
		t.Errorf("audit_logs.data_events = %v, want a known value inherited from live state", got)
	}
}

// plannedCapabilitiesWithUnknownRegistryOptions mirrors a plan where the
// practitioner enables registry scanning and sources its options from another
// resource's computed output, so registry_scanning_options is a known object
// whose children are unknown at plan time.
func plannedCapabilitiesWithUnknownRegistryOptions() types.Object {
	options := types.ObjectValueMust(
		registryScanningOptionsAttrTypes,
		map[string]attr.Value{
			"type":      types.StringUnknown(),
			"last_days": types.Int32Unknown(),
		},
	)
	return types.ObjectValueMust(
		testAdditionalCapabilitiesAttrTypes,
		map[string]attr.Value{
			"serverless_scanning":              types.BoolValue(true),
			"registry_scanning":                types.BoolValue(true),
			"registry_scanning_options":        options,
			"data_security_posture_management": types.BoolUnknown(),
			"agentless_disk_scanning":          types.BoolUnknown(),
			"xsiam_analytics":                  types.BoolUnknown(),
		},
	)
}

// TestCloudIntegrationInstanceResourceModelEditRequestRejectsUnresolvedNestedUnknowns
// is the wire-level guard for unknown values escaping the merge. The live
// instance carries no registry_scanning_options, so the nested unknowns have no
// live value to inherit and survive the merge. They must never be serialized:
// the SDK type has no omitempty on registry_scanning_options.type, so a coerced
// unknown ships as "type":"" — not a member of the accepted enum — and a
// full-replace edit writes that over the live configuration with no diagnostic.
// The contract asserted here is "either a diagnostic, or a body with no
// zero-coerced value", never a silent malformed write.
func TestCloudIntegrationInstanceResourceModelEditRequestRejectsUnresolvedNestedUnknowns(t *testing.T) {
	ctx := context.Background()
	var diags diag.Diagnostics

	model := &CloudIntegrationInstanceResourceModel{
		ID:                      types.StringValue("instance-merge"),
		CloudProvider:           types.StringValue("AWS"),
		InstanceName:            types.StringNull(),
		AdditionalCapabilities:  plannedCapabilitiesWithUnknownRegistryOptions(),
		CollectionConfiguration: types.ObjectNull(collectionConfigurationAttrTypesForTest()),
		CustomResourcesTags:     nullTagSet(),
		OutpostID:               types.StringValue("outpost-1"),
		CloudPartition:          types.StringNull(),
		ScopeModifications:      types.ObjectNull(fullScopeModificationsAttrTypes()),
	}

	// remoteInstance() has no registry_scanning_options, so the merge has
	// nothing to resolve the nested unknowns against.
	remote := remoteInstance()
	if remote.AdditionalCapabilities.RegistryScanningOptions != nil {
		t.Fatal("test setup: remote instance must not carry registry_scanning_options")
	}

	model.MergeFromRemote(ctx, &diags, remote)
	if diags.HasError() {
		t.Fatalf("unexpected merge diagnostics: %v", diags.Errors())
	}

	request := model.ToEditRequest(ctx, &diags)

	if diags.HasError() {
		// The expected outcome: the unresolved value is refused, and the error
		// names the offending attribute so it is actionable.
		detail := diags.Errors()[0].Detail()
		if !strings.Contains(detail, "additional_capabilities.registry_scanning_options.type") {
			t.Errorf("error detail should name the unresolved attribute path, got: %q", detail)
		}
		if request != nil {
			t.Error("expected a nil request when the edit payload cannot be built")
		}
		return
	}

	// If the implementation ever resolves the unknown instead of refusing it,
	// that is acceptable — but only if the resulting body is well-formed.
	raw, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("failed to marshal request: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("failed to unmarshal request JSON: %v", err)
	}

	capabilities, ok := decoded["additional_capabilities"].(map[string]any)
	if !ok {
		t.Fatalf("additional_capabilities missing or wrong type: %v", decoded["additional_capabilities"])
	}
	options, present := capabilities["registry_scanning_options"]
	if !present {
		return
	}
	optionsMap, ok := options.(map[string]any)
	if !ok {
		t.Fatalf("registry_scanning_options wrong type: %T", options)
	}
	if got := optionsMap["type"]; got == "" {
		t.Errorf("registry_scanning_options.type = %q: an unresolved value was "+
			"coerced to an empty string and sent on a full-replace edit; "+
			"body was %s", got, raw)
	}
}

// TestCloudIntegrationInstanceResourceModelMergeFromRemoteKeepsConfiguredNestedObjectWhenRemoteIsNull
// verifies the merge still works for a genuinely-new nested block: when the
// practitioner fully configures registry_scanning_options and the live instance
// has none, the configured values must reach the wire untouched. This is the
// counterpart to the unknown-rejection guard above — refusing unresolved values
// must not come at the cost of dropping configured ones.
func TestCloudIntegrationInstanceResourceModelMergeFromRemoteKeepsConfiguredNestedObjectWhenRemoteIsNull(t *testing.T) {
	ctx := context.Background()
	var diags diag.Diagnostics

	options := types.ObjectValueMust(
		registryScanningOptionsAttrTypes,
		map[string]attr.Value{
			"type":      types.StringValue("TAGS_MODIFIED_DAYS"),
			"last_days": types.Int32Value(30),
		},
	)
	plannedCapabilities := types.ObjectValueMust(
		testAdditionalCapabilitiesAttrTypes,
		map[string]attr.Value{
			"serverless_scanning":              types.BoolValue(true),
			"registry_scanning":                types.BoolValue(true),
			"registry_scanning_options":        options,
			"data_security_posture_management": types.BoolUnknown(),
			"agentless_disk_scanning":          types.BoolUnknown(),
			"xsiam_analytics":                  types.BoolUnknown(),
		},
	)

	model := &CloudIntegrationInstanceResourceModel{
		ID:                      types.StringValue("instance-merge"),
		CloudProvider:           types.StringValue("AWS"),
		InstanceName:            types.StringNull(),
		AdditionalCapabilities:  plannedCapabilities,
		CollectionConfiguration: types.ObjectNull(collectionConfigurationAttrTypesForTest()),
		CustomResourcesTags:     nullTagSet(),
		OutpostID:               types.StringValue("outpost-1"),
		CloudPartition:          types.StringNull(),
		ScopeModifications:      types.ObjectNull(fullScopeModificationsAttrTypes()),
	}

	model.MergeFromRemote(ctx, &diags, remoteInstance())
	if diags.HasError() {
		t.Fatalf("unexpected merge diagnostics: %v", diags.Errors())
	}

	request := model.ToEditRequest(ctx, &diags)
	if diags.HasError() {
		t.Fatalf("unexpected request diagnostics: %v", diags.Errors())
	}

	raw, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("failed to marshal request: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("failed to unmarshal request JSON: %v", err)
	}

	capabilities := decoded["additional_capabilities"].(map[string]any)
	options2, ok := capabilities["registry_scanning_options"].(map[string]any)
	if !ok {
		t.Fatalf("registry_scanning_options missing from marshaled request: %s", raw)
	}
	if got := options2["type"]; got != "TAGS_MODIFIED_DAYS" {
		t.Errorf("registry_scanning_options.type = %v, want TAGS_MODIFIED_DAYS (practitioner-configured)", got)
	}
	if got := options2["last_days"]; got != float64(30) {
		t.Errorf("registry_scanning_options.last_days = %v, want 30 (practitioner-configured)", got)
	}
}
