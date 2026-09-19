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

// Every optional member of these blocks is also Computed, so Terraform marks
// the ones the practitioner did not write as UNKNOWN while it plans. That is
// the ordinary shape of a plan, not an edge case: a configuration that sets one
// capability and leaves the other six to the platform produces exactly it.
//
// The conversion has to survive that. Reading an unknown into a *bool or a
// *string is impossible -- there is no value to point at -- and the framework
// answers with a Value Conversion Error that aborts the apply before any
// request is sent. The tests below hold each conversion to that case.

// partiallyUnknownObject builds an object whose declared members carry values
// and whose remaining members are unknown, mirroring a real plan.
func partiallyUnknownObject(t *testing.T, attributeTypes map[string]attr.Type, known map[string]attr.Value) basetypes.ObjectValue {
	t.Helper()

	members := map[string]attr.Value{}
	for name, attributeType := range attributeTypes {
		if value, ok := known[name]; ok {
			members[name] = value
			continue
		}
		members[name] = unknownOf(t, attributeType)
	}

	object, diagnostics := types.ObjectValue(attributeTypes, members)
	if diagnostics.HasError() {
		t.Fatalf("failed to build the test object: %v", diagnostics)
	}
	return object
}

func unknownOf(t *testing.T, attributeType attr.Type) attr.Value {
	t.Helper()

	// Nested objects are matched first: an ObjectType carries its member types,
	// so it never compares equal to a bare type and has to be handled by shape.
	if objectType, ok := attributeType.(types.ObjectType); ok {
		return types.ObjectUnknown(objectType.AttrTypes)
	}

	switch attributeType {
	case types.BoolType:
		return types.BoolUnknown()
	case types.StringType:
		return types.StringUnknown()
	case types.Int64Type:
		return types.Int64Unknown()
	default:
		t.Fatalf("unhandled attribute type %s", attributeType)
		return nil
	}
}

// TestAdditionalCapabilitiesAcceptsUnknownMembers covers the case that broke the
// first live apply: one capability declared, the rest left to the platform.
func TestAdditionalCapabilitiesAcceptsUnknownMembers(t *testing.T) {
	t.Parallel()

	// Taken from the schema rather than restated here. A second copy of the
	// member list silently stops covering the real object as soon as a member
	// is added, which is exactly what happened when registry_scanning_options
	// was introduced.
	attributeTypes := ManualAdditionalCapabilitiesAttributeTypes()

	model := &CloudManualIntegrationInstanceModel{
		AdditionalCapabilities: partiallyUnknownObject(t, attributeTypes, map[string]attr.Value{
			"xsiam_analytics": types.BoolValue(true),
		}),
	}

	diagnostics := &diag.Diagnostics{}
	capabilities := model.additionalCapabilities(context.Background(), diagnostics)

	if diagnostics.HasError() {
		t.Fatalf("a plan that declares one capability and leaves the rest to the platform must convert, got: %v", diagnostics)
	}
	if capabilities.XSIAMAnalytics == nil || !*capabilities.XSIAMAnalytics {
		t.Errorf("the declared capability was not carried through: %+v", capabilities.XSIAMAnalytics)
	}
	// An unknown member must not be sent. The edit is a partial update and the
	// request type omits a nil member, so leaving it nil is what preserves the
	// platform's own value; inventing false would silently disable it.
	if capabilities.RegistryScanning != nil {
		t.Errorf("an undeclared capability was resolved to %t and would be transmitted, overwriting the platform's value", *capabilities.RegistryScanning)
	}
}

// TestCollectionConfigurationAcceptsUnknownMembers covers the same shape one
// level down, where audit_logs members are individually Optional+Computed.
func TestCollectionConfigurationAcceptsUnknownMembers(t *testing.T) {
	t.Parallel()

	// Taken from the production map rather than restated, so a member added or
	// removed there cannot leave this test asserting a shape that no longer
	// exists.
	auditLogTypes := ManualAuditLogsAttributeTypes()

	auditLogs := partiallyUnknownObject(t, auditLogTypes, map[string]attr.Value{
		"enabled": types.BoolValue(true),
	})

	collectionConfiguration, diagnostics := types.ObjectValue(
		map[string]attr.Type{"audit_logs": auditLogs.Type(context.Background())},
		map[string]attr.Value{"audit_logs": auditLogs},
	)
	if diagnostics.HasError() {
		t.Fatalf("failed to build the test object: %v", diagnostics)
	}

	model := &CloudManualIntegrationInstanceModel{CollectionConfiguration: collectionConfiguration}

	convertDiagnostics := &diag.Diagnostics{}
	configuration := model.collectionConfiguration(context.Background(), convertDiagnostics)

	if convertDiagnostics.HasError() {
		t.Fatalf("a plan that enables audit logs and leaves the rest to the platform must convert, got: %v", convertDiagnostics)
	}
	if !configuration.AuditLogs.Enabled {
		t.Error("the declared audit-log toggle was not carried through")
	}
}

// TestScopeModificationsInventsNoRegionScope proves the provider sends the
// region scope the practitioner wrote and never one of its own.
//
// The provider used to substitute regions{enabled:false} on silence, sending a
// region policy nobody wrote. Both attributes are now Required, so a null
// object must convert to an empty payload. That shape is unreachable from a
// validated configuration, so this covers the paths that bypass validation.
func TestScopeModificationsInventsNoRegionScope(t *testing.T) {
	t.Parallel()

	for name, scopeModifications := range map[string]basetypes.ObjectValue{
		"omitted entirely":     types.ObjectNull(map[string]attr.Type{}),
		"unknown at plan time": types.ObjectUnknown(map[string]attr.Type{}),
	} {
		t.Run(name, func(t *testing.T) {
			model := &CloudManualIntegrationInstanceModel{ScopeModifications: scopeModifications}

			diagnostics := &diag.Diagnostics{}
			converted := model.scopeModifications(context.Background(), diagnostics)

			if diagnostics.HasError() {
				t.Fatalf("conversion reported an error: %v", diagnostics)
			}
			if converted.Regions != nil {
				t.Errorf("the provider invented a region scope nobody configured: %+v", *converted.Regions)
			}
		})
	}
}

// TestScopeModificationsCarriesTheConfiguredRegions is the positive arm of the
// test above: proving nothing is invented is only meaningful alongside proof
// that a scope the practitioner did write still reaches the platform.
func TestScopeModificationsCarriesTheConfiguredRegions(t *testing.T) {
	t.Parallel()

	// Built from the production attribute types rather than a hand-written
	// copy, so the test cannot drift from the schema it is guarding.
	scopeTypes := ManualScopeModificationsAttributeTypes()

	regionsType, ok := scopeTypes["regions"].(types.ObjectType)
	if !ok {
		t.Fatalf("scope_modifications.regions is not an object type: %T", scopeTypes["regions"])
	}

	regionList, diagnostics := types.ListValue(types.StringType, []attr.Value{types.StringValue("us-east-1")})
	if diagnostics.HasError() {
		t.Fatalf("failed to build the test list: %v", diagnostics)
	}

	regions, diagnostics := types.ObjectValue(regionsType.AttrTypes, map[string]attr.Value{
		"enabled": types.BoolValue(true),
		"type":    types.StringValue("INCLUDE"),
		"regions": regionList,
	})
	if diagnostics.HasError() {
		t.Fatalf("failed to build the test object: %v", diagnostics)
	}

	members := map[string]attr.Value{"regions": regions}
	for name, attributeType := range scopeTypes {
		if name == "regions" {
			continue
		}
		if objectType, isObject := attributeType.(types.ObjectType); isObject {
			members[name] = types.ObjectNull(objectType.AttrTypes)
			continue
		}
		members[name] = types.BoolNull()
	}

	scopeModifications, diagnostics := types.ObjectValue(scopeTypes, members)
	if diagnostics.HasError() {
		t.Fatalf("failed to build the test object: %v", diagnostics)
	}

	model := &CloudManualIntegrationInstanceModel{ScopeModifications: scopeModifications}

	convertDiagnostics := &diag.Diagnostics{}
	converted := model.scopeModifications(context.Background(), convertDiagnostics)

	if convertDiagnostics.HasError() {
		t.Fatalf("conversion reported an error: %v", convertDiagnostics)
	}
	if converted.Regions == nil {
		t.Fatal("the configured region scope never reached the request")
	}
	if !converted.Regions.Enabled {
		t.Error("the configured region restriction was turned off on the way to the platform")
	}
	if converted.Regions.Type == nil || *converted.Regions.Type != "INCLUDE" {
		t.Errorf("the configured restriction type was not carried through: %+v", converted.Regions.Type)
	}
	if converted.Regions.Regions == nil {
		t.Fatal("the configured region list was dropped on the way to the platform")
	}
	if list := *converted.Regions.Regions; len(list) != 1 || list[0] != "us-east-1" {
		t.Errorf("the configured region list was not carried through: %+v", list)
	}
}

// TestManualDetailsAcceptsUnknownMembers guards the write block. Its members are
// Optional only, so they plan as null rather than unknown today -- but the same
// conversion is used for the object read back from the platform, and a single
// unknown member there would abort the apply for the same reason.
//
// The object must carry every member the target struct declares. The framework
// matches them by name and rejects a subset outright, so a narrowed object here
// would fail for a reason that has nothing to do with unknown handling and
// would keep this test green after a regression.
func TestManualDetailsAcceptsUnknownMembers(t *testing.T) {
	t.Parallel()

	attributeTypes := map[string]attr.Type{}
	for _, name := range []string{
		"account_id", "account_name", "organization_id", "role_arn",
		"external_id", "outpost_scanner_role_arn", "cloudtrail_role", "sqs_url",
		"tenant_id", "subscription_id", "resource_group_name",
		"resource_group_location", "ads_image_gallery_resource_id",
		"eventhub_name", "eventhub_resource_group_name", "eventhub_namespace",
		"azure_audit_eventhub_consumer_group_name", "storage_account_name",
		"eventhub_audit_client_id",
	} {
		attributeTypes[name] = types.StringType
	}

	object := partiallyUnknownObject(t, attributeTypes, map[string]attr.Value{
		"account_id": types.StringValue("123456789012"),
	})

	model := &CloudManualIntegrationInstanceModel{ManualDetails: object}

	diagnostics := &diag.Diagnostics{}
	details := model.manualDetails(context.Background(), diagnostics)

	if diagnostics.HasError() {
		t.Fatalf("an object carrying an unknown member must convert, got: %v", diagnostics)
	}
	if details.AccountID == nil || *details.AccountID != "123456789012" {
		t.Errorf("the known member was not carried through: %+v", details.AccountID)
	}
	if details.RoleARN != nil {
		t.Errorf("an unknown member was resolved to %q and would be transmitted", *details.RoleARN)
	}
}
