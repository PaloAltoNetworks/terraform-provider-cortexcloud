// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package models

import (
	"context"
	"testing"

	cloudOnboardingTypes "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/types/cloudonboarding"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// TestCollectionConfigurationAcceptsUnknownAuditLogMembers covers the shape a
// real plan has for a connector that configures audit-log collection without
// mentioning the AWS-only members.
//
// enabled, data_events and collection_method are declared; is_control_tower_byob,
// cloudtrail_role and sqs_url are Optional+Computed and so arrive unknown. A
// live "terraform apply" of an Azure connector in exactly that shape aborted
// with
//
//	Received unknown value, however the target type cannot handle unknown
//	values. Path: audit_logs.is_control_tower_byob
//	Target Type: *bool
//
// and it aborted AFTER the connector had been created, leaving a connector and
// its template orphaned on the tenant with nothing in Terraform state tracking
// them. That makes this worse than a plain validation failure.
func TestCollectionConfigurationAcceptsUnknownAuditLogMembers(t *testing.T) {
	t.Parallel()

	auditLogTypes := ManualAuditLogsAttributeTypes()

	auditLogValues := make(map[string]attr.Value, len(auditLogTypes))
	for name, attributeType := range auditLogTypes {
		switch name {
		case "enabled":
			auditLogValues[name] = types.BoolValue(true)
		case "data_events":
			auditLogValues[name] = types.BoolValue(false)
		case "collection_method":
			auditLogValues[name] = types.StringValue("CUSTOM")
		default:
			// Optional+Computed and not configured: unknown at plan time.
			auditLogValues[name] = unknownOf(t, attributeType)
		}
	}

	auditLogs, diags := types.ObjectValue(auditLogTypes, auditLogValues)
	if diags.HasError() {
		t.Fatalf("building audit_logs failed: %v", diags.Errors())
	}

	collectionTypes := ManualCollectionConfigurationAttributeTypes()
	collection, diags := types.ObjectValue(collectionTypes, map[string]attr.Value{
		"audit_logs": auditLogs,
	})
	if diags.HasError() {
		t.Fatalf("building collection_configuration failed: %v", diags.Errors())
	}

	model := &CloudManualIntegrationInstanceModel{CollectionConfiguration: collection}

	diagnostics := &diag.Diagnostics{}
	configuration := model.collectionConfiguration(context.Background(), diagnostics)

	if diagnostics.HasError() {
		t.Fatalf(
			"a plan that configures audit logs and leaves the AWS-only members to "+
				"the platform must convert, got: %v",
			diagnostics.Errors(),
		)
	}

	if !configuration.AuditLogs.Enabled {
		t.Error("audit_logs.enabled was not carried through")
	}
	if configuration.AuditLogs.CollectionMethod != "CUSTOM" {
		t.Errorf("audit_logs.collection_method = %q, want %q", configuration.AuditLogs.CollectionMethod, "CUSTOM")
	}
	// An unknown member must not be invented. The request type omits a nil
	// member, which is what leaves the platform's own value alone.
	if configuration.AuditLogs.IsControlTowerBYOB != nil {
		t.Errorf(
			"an undeclared AWS-only member resolved to %t and would be transmitted",
			*configuration.AuditLogs.IsControlTowerBYOB,
		)
	}

	// The refresh runs against the same plan object immediately after the
	// create call returns, and it is the refresh -- not the write above -- that
	// aborted the live apply. It reads the previously configured audit-log
	// members to carry forward the two the platform never reports, so it must
	// tolerate the unknowns a plan legitimately contains.
	refreshDiagnostics := &diag.Diagnostics{}
	refreshed := refreshedCollectionConfiguration(
		context.Background(),
		refreshDiagnostics,
		collection,
		&cloudOnboardingTypes.CollectionConfigurationRead{
			AuditLogs: cloudOnboardingTypes.AuditLogsRead{
				Enabled:          true,
				DataEvents:       false,
				CollectionMethod: "CUSTOM",
			},
		},
	)

	if refreshDiagnostics.HasError() {
		t.Fatalf(
			"refreshing against a plan whose Optional+Computed audit-log members "+
				"are unknown must not fail; this is the abort that orphaned a live "+
				"connector: %v",
			refreshDiagnostics.Errors(),
		)
	}
	if refreshed.IsNull() {
		t.Fatal("the refreshed collection_configuration is null")
	}
}
