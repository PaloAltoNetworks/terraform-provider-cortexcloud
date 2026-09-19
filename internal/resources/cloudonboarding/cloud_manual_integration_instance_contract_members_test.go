// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package cloudonboarding

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
)

// auditLogsAttributes returns the members of
// collection_configuration.audit_logs.
func auditLogsAttributes(t *testing.T) map[string]schema.Attribute {
	t.Helper()

	resp := manualInstanceSchema(t)

	collection, ok := resp.Schema.Attributes["collection_configuration"].(schema.SingleNestedAttribute)
	if !ok {
		t.Fatalf(
			"collection_configuration is %T, want a single nested attribute",
			resp.Schema.Attributes["collection_configuration"],
		)
	}

	auditLogs, ok := collection.Attributes["audit_logs"].(schema.SingleNestedAttribute)
	if !ok {
		t.Fatalf("audit_logs is %T, want a single nested attribute", collection.Attributes["audit_logs"])
	}

	return auditLogs.Attributes
}

// TestAuditLogsRejectsMembersThePlatformRefuses keeps audit-log source fields
// out of collection_configuration.audit_logs.
//
// The platform refuses cloudtrail_role and sqs_url in that block outright:
//
//	Error Code: 422
//	Error Message: Validation failed
//	  - Type: "extra_forbidden"
//	    Location: ["collection_configuration", "audit_logs", "cloudtrail_role"]
//	  - Type: "extra_forbidden"
//	    Location: ["collection_configuration", "audit_logs", "sqs_url"]
//
// Both belong in manual_details, where the same two values onboard a connector
// successfully -- that was the control arm, and it is the placement the
// examples already use. Offering them here produced a resource whose every
// apply failed, and the generated documentation told users to write exactly
// that.
//
// The platform never reports either field back inside audit_logs either. What
// it does return there is is_control_tower_byob, which is accepted on write
// and echoed on read, so that member is legitimate and deliberately not
// listed below.
func TestAuditLogsRejectsMembersThePlatformRefuses(t *testing.T) {
	t.Parallel()

	// Members the API answers with "extra_forbidden" when they appear inside
	// collection_configuration.audit_logs.
	refused := []string{"cloudtrail_role", "sqs_url"}

	attributes := auditLogsAttributes(t)

	for _, name := range refused {
		if _, found := attributes[name]; found {
			t.Errorf(
				"audit_logs offers %q, but the platform refuses it there with "+
					"extra_forbidden -- every apply of a configuration that sets it "+
					"fails. It belongs in manual_details.",
				name,
			)
		}
	}
}

// TestScopeModificationsOffersNoUndocumentedMembers keeps members the v4 API
// contract does not define out of scope_modifications.
//
// onboard_only_mode was offered here and appears nowhere in the contract. Live
// measurement showed the platform accepts only one value for it:
//
//	omitted        -> 200
//	false          -> 200
//	true           -> 422 "Invalid connector details"
//
// The platform does echo it on read -- 24 of 24 captured successful reads
// report onboard_only_mode: false, none of which asked for it -- so it is a
// server-owned readback, not a setting. An attribute whose sole accepted value
// is indistinguishable from leaving it out gives a practitioner nothing to
// decide, while implying a capability the contract does not offer. It was
// removed rather than documented.
func TestScopeModificationsOffersNoUndocumentedMembers(t *testing.T) {
	t.Parallel()

	resp := manualInstanceSchema(t)

	scope, ok := resp.Schema.Attributes["scope_modifications"].(schema.SingleNestedAttribute)
	if !ok {
		t.Fatalf(
			"scope_modifications is %T, want a single nested attribute",
			resp.Schema.Attributes["scope_modifications"],
		)
	}

	for _, name := range []string{"onboard_only_mode"} {
		if _, found := scope.Attributes[name]; found {
			t.Errorf(
				"scope_modifications offers %q, which the v4 contract does not define and "+
					"which the platform accepts in only one value -- identical in effect to "+
					"omitting it",
				name,
			)
		}
	}
}

// TestAuditLogsKeepsTheMembersThePlatformAccepts is the other half of the
// guard above: it fails if a later change removes too much.
//
// Deleting the whole block would satisfy the "refused" test trivially, so this
// pins the members that are genuinely part of the API contract. enabled,
// data_events and collection_method are Required by the contract, and
// is_control_tower_byob is accepted on write and returned on read.
func TestAuditLogsKeepsTheMembersThePlatformAccepts(t *testing.T) {
	t.Parallel()

	accepted := []string{"enabled", "data_events", "collection_method", "is_control_tower_byob"}

	attributes := auditLogsAttributes(t)

	for _, name := range accepted {
		if _, found := attributes[name]; !found {
			t.Errorf("audit_logs no longer offers %q, which the platform accepts and reports back", name)
		}
	}
}
