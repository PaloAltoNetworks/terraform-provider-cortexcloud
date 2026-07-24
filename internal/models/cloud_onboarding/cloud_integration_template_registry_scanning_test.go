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

// registryScanningOptionsAttrTypes mirrors the schema definition of the
// additional_capabilities.registry_scanning_options nested object.
var registryScanningOptionsAttrTypes = map[string]attr.Type{
	"type":      types.StringType,
	"last_days": types.Int32Type,
}

// additionalCapabilitiesAttrTypes mirrors the schema definition of the
// additional_capabilities object across all cloud providers.
var testAdditionalCapabilitiesAttrTypes = map[string]attr.Type{
	"data_security_posture_management": types.BoolType,
	"registry_scanning":                types.BoolType,
	"registry_scanning_options": types.ObjectType{
		AttrTypes: registryScanningOptionsAttrTypes,
	},
	"agentless_disk_scanning": types.BoolType,
	"xsiam_analytics":         types.BoolType,
	"serverless_scanning":     types.BoolType,
}

// buildAdditionalCapabilities constructs an additional_capabilities object with
// registry_scanning set to the given value and registry_scanning_options always
// populated with {type: "ALL"} — replicating the schema's computed default.
func buildAdditionalCapabilities(t *testing.T, registryScanning bool) types.Object {
	t.Helper()

	options := types.ObjectValueMust(
		registryScanningOptionsAttrTypes,
		map[string]attr.Value{
			"type":      types.StringValue("ALL"),
			"last_days": types.Int32Null(),
		},
	)

	return types.ObjectValueMust(
		testAdditionalCapabilitiesAttrTypes,
		map[string]attr.Value{
			"data_security_posture_management": types.BoolValue(false),
			"registry_scanning":                types.BoolValue(registryScanning),
			"registry_scanning_options":        options,
			"agentless_disk_scanning":          types.BoolValue(true),
			"xsiam_analytics":                  types.BoolValue(true),
			"serverless_scanning":              types.BoolValue(true),
		},
	)
}

// tagAttrTypes mirrors a custom_resources_tags element.
var tagAttrTypes = map[string]attr.Type{
	"key":   types.StringType,
	"value": types.StringType,
}

// nullTagSet returns a correctly-typed null set for custom_resources_tags.
func nullTagSet() types.Set {
	return types.SetNull(types.ObjectType{AttrTypes: tagAttrTypes})
}

// collectionConfigurationValue returns a populated collection_configuration
// object. The model deserializes this into a value type that cannot handle
// nulls, so tests must provide a concrete object.
func collectionConfigurationValue() types.Object {
	auditLogsType := map[string]attr.Type{
		"enabled":           types.BoolType,
		"collection_method": types.StringType,
		"data_events":       types.BoolType,
	}
	auditLogs := types.ObjectValueMust(auditLogsType, map[string]attr.Value{
		"enabled":           types.BoolValue(true),
		"collection_method": types.StringValue("AUTOMATED"),
		"data_events":       types.BoolValue(false),
	})
	return types.ObjectValueMust(
		map[string]attr.Type{"audit_logs": types.ObjectType{AttrTypes: auditLogsType}},
		map[string]attr.Value{"audit_logs": auditLogs},
	)
}

// scopeModificationsValue returns a populated scope_modifications object with a
// disabled regions block (the schema default). The model deserializes this into
// a value type that cannot handle nulls.
// disabledRegions returns a regions object with a disabled modification.
func disabledRegions() (map[string]attr.Type, attr.Value) {
	regionsType := map[string]attr.Type{
		"enabled": types.BoolType,
		"type":    types.StringType,
		"regions": types.SetType{ElemType: types.StringType},
	}
	return regionsType, types.ObjectValueMust(regionsType, map[string]attr.Value{
		"enabled": types.BoolValue(false),
		"type":    types.StringNull(),
		"regions": types.SetNull(types.StringType),
	})
}

// scopeModificationsValue returns an AWS scope_modifications object ({accounts, regions}).
func scopeModificationsValue() types.Object {
	regionsType, regions := disabledRegions()
	accountsType := map[string]attr.Type{
		"enabled":     types.BoolType,
		"type":        types.StringType,
		"account_ids": types.SetType{ElemType: types.StringType},
	}
	return types.ObjectValueMust(
		map[string]attr.Type{
			"accounts": types.ObjectType{AttrTypes: accountsType},
			"regions":  types.ObjectType{AttrTypes: regionsType},
		},
		map[string]attr.Value{
			"accounts": types.ObjectNull(accountsType),
			"regions":  regions,
		},
	)
}

// scopeModificationsValueGcp returns a GCP scope_modifications object ({projects, regions}).
func scopeModificationsValueGcp() types.Object {
	regionsType, regions := disabledRegions()
	projectsType := map[string]attr.Type{
		"enabled":     types.BoolType,
		"type":        types.StringType,
		"project_ids": types.SetType{ElemType: types.StringType},
	}
	return types.ObjectValueMust(
		map[string]attr.Type{
			"projects": types.ObjectType{AttrTypes: projectsType},
			"regions":  types.ObjectType{AttrTypes: regionsType},
		},
		map[string]attr.Value{
			"projects": types.ObjectNull(projectsType),
			"regions":  regions,
		},
	)
}

// scopeModificationsValueAzure returns an Azure scope_modifications object ({subscriptions, regions}).
func scopeModificationsValueAzure() types.Object {
	regionsType, regions := disabledRegions()
	subscriptionsType := map[string]attr.Type{
		"enabled":          types.BoolType,
		"type":             types.StringType,
		"subscription_ids": types.SetType{ElemType: types.StringType},
	}
	return types.ObjectValueMust(
		map[string]attr.Type{
			"subscriptions": types.ObjectType{AttrTypes: subscriptionsType},
			"regions":       types.ObjectType{AttrTypes: regionsType},
		},
		map[string]attr.Value{
			"subscriptions": types.ObjectNull(subscriptionsType),
			"regions":       regions,
		},
	)
}

// marshalledAdditionalCapabilities extracts the additional_capabilities object
// from a marshalled create request so tests can assert on the wire shape.
func marshalledAdditionalCapabilities(t *testing.T, raw []byte) map[string]any {
	t.Helper()

	var payload struct {
		AdditionalCapabilities map[string]any `json:"additional_capabilities"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("failed to unmarshal request: %v", err)
	}
	return payload.AdditionalCapabilities
}

// assertRegistryOptions verifies the both-or-neither API contract on the
// marshalled additional_capabilities.
func assertRegistryOptions(t *testing.T, ac map[string]any, registryScanning bool) {
	t.Helper()

	got, ok := ac["registry_scanning"].(bool)
	if !ok {
		t.Fatalf("registry_scanning missing or not a bool in payload: %#v", ac["registry_scanning"])
	}
	if got != registryScanning {
		t.Errorf("registry_scanning = %v, want %v", got, registryScanning)
	}

	_, optionsPresent := ac["registry_scanning_options"]
	if registryScanning && !optionsPresent {
		t.Errorf("registry_scanning_options should be present when registry_scanning=true")
	}
	if !registryScanning && optionsPresent {
		t.Errorf("registry_scanning_options must be omitted when registry_scanning=false, got %#v", ac["registry_scanning_options"])
	}
}

func TestAwsToCreateRequest_RegistryScanningOptions(t *testing.T) {
	ctx := context.Background()

	for _, tc := range []struct {
		name             string
		registryScanning bool
	}{
		{"disabled omits options", false},
		{"enabled keeps options", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := &CloudIntegrationTemplateAwsModel{
				AdditionalCapabilities:  buildAdditionalCapabilities(t, tc.registryScanning),
				CollectionConfiguration: collectionConfigurationValue(),
				CustomResourcesTags:     nullTagSet(),
				ScopeModifications:      scopeModificationsValue(),
				InstanceName:            types.StringValue("test"),
				ScanMode:                types.StringValue("MANAGED"),
				Scope:                   types.StringValue("ACCOUNT"),
				OutpostID:               types.StringNull(),
			}

			var diags diag.Diagnostics
			req := m.ToCreateRequest(ctx, &diags)
			if diags.HasError() {
				t.Fatalf("unexpected diagnostics: %v", diags)
			}
			raw, err := json.Marshal(req)
			if err != nil {
				t.Fatalf("marshal failed: %v", err)
			}
			assertRegistryOptions(t, marshalledAdditionalCapabilities(t, raw), tc.registryScanning)
		})
	}
}

func TestGcpToCreateRequest_RegistryScanningOptions(t *testing.T) {
	ctx := context.Background()

	for _, tc := range []struct {
		name             string
		registryScanning bool
	}{
		{"disabled omits options", false},
		{"enabled keeps options", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := &CloudIntegrationTemplateGcpModel{
				AdditionalCapabilities:  buildAdditionalCapabilities(t, tc.registryScanning),
				CollectionConfiguration: collectionConfigurationValue(),
				CustomResourcesTags:     nullTagSet(),
				ScopeModifications:      scopeModificationsValueGcp(),
				InstanceName:            types.StringValue("test"),
				ScanMode:                types.StringValue("MANAGED"),
				Scope:                   types.StringValue("ACCOUNT"),
				OutpostID:               types.StringNull(),
			}

			var diags diag.Diagnostics
			req := m.ToCreateRequest(ctx, &diags)
			if diags.HasError() {
				t.Fatalf("unexpected diagnostics: %v", diags)
			}
			raw, err := json.Marshal(req)
			if err != nil {
				t.Fatalf("marshal failed: %v", err)
			}
			assertRegistryOptions(t, marshalledAdditionalCapabilities(t, raw), tc.registryScanning)
		})
	}
}

func TestAzureToCreateRequest_RegistryScanningOptions(t *testing.T) {
	ctx := context.Background()

	for _, tc := range []struct {
		name             string
		registryScanning bool
	}{
		{"disabled omits options", false},
		{"enabled keeps options", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := &CloudIntegrationTemplateAzureModel{
				AccountDetails:          types.ObjectNull(map[string]attr.Type{"organization_id": types.StringType}),
				AdditionalCapabilities:  buildAdditionalCapabilities(t, tc.registryScanning),
				CollectionConfiguration: collectionConfigurationValue(),
				CustomResourcesTags:     nullTagSet(),
				ScopeModifications:      scopeModificationsValueAzure(),
				InstanceName:            types.StringValue("test"),
				ScanMode:                types.StringValue("MANAGED"),
				Scope:                   types.StringValue("ACCOUNT"),
				OutpostID:               types.StringNull(),
			}

			var diags diag.Diagnostics
			req := m.ToCreateRequest(ctx, &diags)
			if diags.HasError() {
				t.Fatalf("unexpected diagnostics: %v", diags)
			}
			raw, err := json.Marshal(req)
			if err != nil {
				t.Fatalf("marshal failed: %v", err)
			}
			assertRegistryOptions(t, marshalledAdditionalCapabilities(t, raw), tc.registryScanning)
		})
	}
}
