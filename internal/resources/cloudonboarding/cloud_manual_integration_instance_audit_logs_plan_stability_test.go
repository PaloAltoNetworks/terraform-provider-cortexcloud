// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package cloudonboarding

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
)

// TestAuditLogMembersHoldTheirStateAcrossPlans proves the Optional+Computed
// members of collection_configuration.audit_logs keep their state value when
// the configuration does not set them.
//
// Without that, a value the platform supplied at create time is re-planned as
// "(known after apply)" on the very next plan, and the second plan of an
// unchanged configuration is not empty. A live run showed exactly this:
//
//	~ collection_configuration = {
//	    ~ audit_logs = {
//	        ~ is_control_tower_byob = false -> (known after apply)
//	      }
//	  }
//	Plan: 0 to add, 1 to change, 0 to destroy.
//
// terraform plan -detailed-exitcode returned 2 rather than 0. That is a
// perpetual diff: every plan proposes an update, and no apply ever settles it.
//
// The sibling object additional_capabilities already carries
// UseStateForUnknown on each of its members for this reason. audit_logs was
// left without it.
func TestAuditLogMembersHoldTheirStateAcrossPlans(t *testing.T) {
	t.Parallel()

	resp := manualInstanceSchema(t)

	attribute, ok := resp.Schema.Attributes["collection_configuration"]
	if !ok {
		t.Fatal("collection_configuration is not in the schema")
	}

	collection, ok := attribute.(schema.SingleNestedAttribute)
	if !ok {
		t.Fatalf("collection_configuration is %T, want a single nested attribute", attribute)
	}

	auditLogs, ok := collection.Attributes["audit_logs"].(schema.SingleNestedAttribute)
	if !ok {
		t.Fatalf("audit_logs is %T, want a single nested attribute", collection.Attributes["audit_logs"])
	}

	for name, member := range auditLogs.Attributes {
		if !member.IsComputed() {
			// Not Computed: the platform never supplies it, so there is no
			// state value that could be discarded.
			continue
		}

		if planModifierCount(member) == 0 {
			t.Errorf(
				"audit_logs.%s is Computed but carries no plan modifier, so a value "+
					"the platform supplied is re-planned as \"known after apply\" and "+
					"the second plan of an unchanged configuration is not empty",
				name,
			)
		}
	}
}

// planModifierCount reports how many plan modifiers an attribute declares,
// whatever its type.
func planModifierCount(attribute schema.Attribute) int {
	switch typed := attribute.(type) {
	case schema.BoolAttribute:
		return len(typed.PlanModifiers)
	case schema.StringAttribute:
		return len(typed.PlanModifiers)
	case schema.Int64Attribute:
		return len(typed.PlanModifiers)
	case schema.SingleNestedAttribute:
		return len(typed.PlanModifiers)
	default:
		return 0
	}
}
