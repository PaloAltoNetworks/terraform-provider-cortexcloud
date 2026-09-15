// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package models

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
)

// additionalCapabilitiesWithRegistryScanning builds an additional_capabilities
// value that turns registry scanning on and asks for the "ALL" option set,
// leaving every other member null.
func additionalCapabilitiesWithRegistryScanning(t *testing.T) types.Object {
	t.Helper()

	attributeTypes := ManualAdditionalCapabilitiesAttributeTypes()

	optionsType, ok := attributeTypes["registry_scanning_options"]
	if !ok {
		t.Fatalf(
			"additional_capabilities has no registry_scanning_options member, so a "+
				"configuration cannot express it; the platform refuses "+
				"registry_scanning without it. members present: %v",
			attributeTypeNames(attributeTypes),
		)
	}

	optionsObjectType, ok := optionsType.(types.ObjectType)
	if !ok {
		t.Fatalf("registry_scanning_options is %T, want an object", optionsType)
	}

	optionsValues := make(map[string]attr.Value, len(optionsObjectType.AttrTypes))
	for name, attributeType := range optionsObjectType.AttrTypes {
		switch name {
		case "type":
			optionsValues[name] = types.StringValue("ALL")
		default:
			optionsValues[name] = nullOf(t, attributeType)
		}
	}

	options, diags := types.ObjectValue(optionsObjectType.AttrTypes, optionsValues)
	if diags.HasError() {
		t.Fatalf("building registry_scanning_options failed: %v", diags.Errors())
	}

	values := make(map[string]attr.Value, len(attributeTypes))
	for name, attributeType := range attributeTypes {
		switch name {
		case "registry_scanning":
			values[name] = types.BoolValue(true)
		case "registry_scanning_options":
			values[name] = options
		default:
			values[name] = nullOf(t, attributeType)
		}
	}

	object, diags := types.ObjectValue(attributeTypes, values)
	if diags.HasError() {
		t.Fatalf("building additional_capabilities failed: %v", diags.Errors())
	}

	return object
}

func attributeTypeNames(attributeTypes map[string]attr.Type) []string {
	names := make([]string, 0, len(attributeTypes))
	for name := range attributeTypes {
		names = append(names, name)
	}
	return names
}

func nullOf(t *testing.T, attributeType attr.Type) attr.Value {
	t.Helper()

	switch typed := attributeType.(type) {
	case basetypes.BoolType:
		return types.BoolNull()
	case basetypes.StringType:
		return types.StringNull()
	case basetypes.Int64Type:
		return types.Int64Null()
	case types.ObjectType:
		return types.ObjectNull(typed.AttrTypes)
	default:
		t.Fatalf("no null value known for %T", attributeType)
		return nil
	}
}

// TestToCreateRequestSendsRegistryScanningOptions proves a connector that turns
// registry scanning on also sends the option set the platform demands with it.
//
// The platform validates the pair, not the members:
//
//	422 {"type": "value_error", "loc": [],
//	     "msg": "Value error, Registry scanning and registry scanning options
//	             must both be provided together or neither should be provided"}
//
// That is a live capture against tf-test. The same body with
// registry_scanning_options present is accepted with 200, so this is not a
// credentials or environment problem: registry_scanning is simply unusable
// unless the option set travels with it. A configuration that says
// "registry_scanning = true" and cannot say anything else therefore produces a
// request that always fails, which is what a real "terraform apply" of an
// Azure connector did.
func TestToCreateRequestSendsRegistryScanningOptions(t *testing.T) {
	t.Parallel()

	model := CloudManualIntegrationInstanceModel{
		CloudProvider: types.StringValue("AZURE"),
		Scope:         types.StringValue("ACCOUNT"),
		ScanMode:      types.StringValue("MANAGED"),
		InstanceName:  types.StringValue("example"),
		ManualDetails: manualDetailsObject(t, map[string]string{
			"tenant_id":       "194cfdc7-41f0-4eec-8bfb-1b805cf74f53",
			"subscription_id": "a00175b3-230f-49db-b68f-0b35f61bf305",
		}),
		AdditionalCapabilities:  additionalCapabilitiesWithRegistryScanning(t),
		CollectionConfiguration: types.ObjectNull(ManualCollectionConfigurationAttributeTypes()),
		ScopeModifications:      types.ObjectNull(ManualScopeModificationsAttributeTypes()),
		CustomResourcesTags:     types.SetNull(ManualCustomResourcesTagType()),
	}

	diagnostics := diag.Diagnostics{}
	request := model.ToCreateRequest(context.Background(), &diagnostics)
	if diagnostics.HasError() {
		t.Fatalf("building the create request failed: %v", diagnostics.Errors())
	}

	payload := marshalled(t, request)

	capabilities, ok := payload["additional_capabilities"].(map[string]any)
	if !ok {
		t.Fatalf("the payload carries no additional_capabilities object: %v", payload["additional_capabilities"])
	}

	if capabilities["registry_scanning"] != true {
		t.Fatalf("registry_scanning = %v, want true", capabilities["registry_scanning"])
	}

	options, ok := capabilities["registry_scanning_options"].(map[string]any)
	if !ok {
		t.Fatalf(
			"additional_capabilities sends registry_scanning without "+
				"registry_scanning_options; the platform answers that pairing with "+
				"422 \"Registry scanning and registry scanning options must both be "+
				"provided together\". got: %v",
			capabilities,
		)
	}

	if options["type"] != "ALL" {
		t.Errorf("registry_scanning_options.type = %v, want %q", options["type"], "ALL")
	}
}
