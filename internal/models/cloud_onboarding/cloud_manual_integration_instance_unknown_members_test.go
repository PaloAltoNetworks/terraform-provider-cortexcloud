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

	auditLogTypes := map[string]attr.Type{
		"enabled":               types.BoolType,
		"data_events":           types.BoolType,
		"collection_method":     types.StringType,
		"is_control_tower_byob": types.BoolType,
		"cloudtrail_role":       types.StringType,
		"sqs_url":               types.StringType,
	}

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

// TestScopeModificationsAlwaysCarriesRegions holds the create payload to what
// the platform actually requires.
//
// scope_modifications.regions is mandatory. Omitting it is answered with
//
//	422 {"type": "missing", "loc": ["scope_modifications", "regions"],
//	     "msg": "Field required"}
//
// and every shipped example omits it, so without this the resource cannot
// onboard anything at all. The member is Optional+Computed, so a configuration
// that says nothing about scope leaves the whole object unknown and the request
// carried no regions member -- which is exactly the shape that failed.
//
// enabled=false is the correct default rather than a placeholder: it is what the
// platform reports back for a connector onboarded without a region restriction,
// so sending it asks for the behaviour a practitioner who said nothing expects.
func TestScopeModificationsAlwaysCarriesRegions(t *testing.T) {
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
			if converted.Regions == nil {
				t.Fatal("regions is absent, so the request omits a member the platform requires and the create is rejected with HTTP 422")
			}
			if converted.Regions.Enabled {
				t.Error("a practitioner who said nothing about scope must not have a region restriction turned on for them")
			}
		})
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
