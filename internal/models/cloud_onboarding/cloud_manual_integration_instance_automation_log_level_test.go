// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package models

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// TestToCreateRequestSendsAutomationLogLevel proves a connector that turns
// automation on also sends the log level the platform demands with it.
//
// This is the same pairing rule that governs registry scanning, on a different
// pair of members:
//
//	422 {"type": "value_error", "loc": [],
//	     "msg": "Value error, Automation and Automation log level must both be
//	             provided together or neither should be provided"}
//
// captured live against tf-test. The level is a real write field rather than a
// value the platform derives: sending an unsupported one is refused with
//
//	422 {"loc": ["additional_capabilities", "automation_log_level"],
//	     "msg": "Input should be 'OFF', 'Debug' or 'Verbose'"}
//
// so the platform both validates and stores it. A configuration that can set
// "automation = true" but cannot set the level therefore builds a request that
// always fails, which is what a real "terraform apply" of an Azure connector
// did once registry_scanning_options was fixed.
func TestToCreateRequestSendsAutomationLogLevel(t *testing.T) {
	t.Parallel()

	attributeTypes := ManualAdditionalCapabilitiesAttributeTypes()

	if _, ok := attributeTypes["automation_log_level"]; !ok {
		t.Fatalf(
			"additional_capabilities has no automation_log_level member, so a "+
				"configuration cannot express it; the platform refuses automation "+
				"without it. members present: %v",
			attributeTypeNames(attributeTypes),
		)
	}

	values := make(map[string]attr.Value, len(attributeTypes))
	for name, attributeType := range attributeTypes {
		switch name {
		case "automation":
			values[name] = types.BoolValue(true)
		case "automation_log_level":
			values[name] = types.StringValue("OFF")
		default:
			values[name] = nullOf(t, attributeType)
		}
	}

	capabilitiesObject, diags := types.ObjectValue(attributeTypes, values)
	if diags.HasError() {
		t.Fatalf("building additional_capabilities failed: %v", diags.Errors())
	}

	model := CloudManualIntegrationInstanceModel{
		CloudProvider: types.StringValue("AZURE"),
		Scope:         types.StringValue("ACCOUNT"),
		ScanMode:      types.StringValue("MANAGED"),
		InstanceName:  types.StringValue("example"),
		ManualDetails: manualDetailsObject(t, map[string]string{
			"tenant_id":       "194cfdc7-41f0-4eec-8bfb-1b805cf74f53",
			"subscription_id": "a00175b3-230f-49db-b68f-0b35f61bf305",
		}),
		AdditionalCapabilities:  capabilitiesObject,
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

	if capabilities["automation"] != true {
		t.Fatalf("automation = %v, want true", capabilities["automation"])
	}

	if capabilities["automation_log_level"] != "OFF" {
		t.Errorf(
			"automation_log_level = %v, want %q; the platform refuses automation "+
				"sent without it",
			capabilities["automation_log_level"], "OFF",
		)
	}
}
