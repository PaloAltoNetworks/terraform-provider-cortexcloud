// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package models

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"

	cloudOnboardingTypes "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/types/cloudonboarding"
)

// upload_files_to_wildfire is a documented member of additional_capabilities:
// the connector contract lists it as an optional boolean and carries it in the
// create_instance sample body. It is also accepted on the live write path -
// sending it with a non-boolean returns
//
//	422 bool_parsing, loc ["additional_capabilities","upload_files_to_wildfire"]
//
// which names the field back, while an invented key returns extra_forbidden.
// So the platform knows this field and type-checks it.
//
// These tests pin the two directions independently. A single round-trip test
// would pass if both directions dropped the value, which is the failure this
// resource is most prone to: an unrecognised member of an object-typed
// attribute is discarded with no error at all.

// TestManualInstanceUploadFilesToWildfireIsSentOnWrite is the write direction:
// a configuration that sets the member must put it on the wire.
func TestManualInstanceUploadFilesToWildfireIsSentOnWrite(t *testing.T) {
	t.Parallel()

	attributeTypes := ManualAdditionalCapabilitiesAttributeTypes()

	if _, ok := attributeTypes["upload_files_to_wildfire"]; !ok {
		t.Fatalf(
			"additional_capabilities has no upload_files_to_wildfire member, so a "+
				"configuration cannot express a field the connector contract documents "+
				"as writable. members present: %v",
			attributeTypeNames(attributeTypes),
		)
	}

	values := make(map[string]attr.Value, len(attributeTypes))
	for name, attributeType := range attributeTypes {
		switch name {
		case "upload_files_to_wildfire":
			values[name] = types.BoolValue(true)
		default:
			values[name] = nullOf(t, attributeType)
		}
	}

	object, diags := types.ObjectValue(attributeTypes, values)
	if diags.HasError() {
		t.Fatalf("building additional_capabilities failed: %v", diags.Errors())
	}

	model := &CloudManualIntegrationInstanceModel{AdditionalCapabilities: object}

	var conversion diag.Diagnostics
	capabilities := model.additionalCapabilities(context.Background(), &conversion)
	if conversion.HasError() {
		t.Fatalf("converting additional_capabilities failed: %v", conversion.Errors())
	}

	if capabilities.UploadFilesToWildfire == nil {
		t.Fatal(
			"upload_files_to_wildfire was configured as true but reached the SDK as nil, " +
				"so the request omits it and the connector is created without the " +
				"capability - silently, because the API ignores what it is not sent",
		)
	}

	if !*capabilities.UploadFilesToWildfire {
		t.Errorf("upload_files_to_wildfire = %v, want true", *capabilities.UploadFilesToWildfire)
	}
}

// TestManualInstanceUploadFilesToWildfireFalseIsSentOnWrite guards the value
// rather than mere presence: a hard-coded true would satisfy the test above.
func TestManualInstanceUploadFilesToWildfireFalseIsSentOnWrite(t *testing.T) {
	t.Parallel()

	attributeTypes := ManualAdditionalCapabilitiesAttributeTypes()

	if _, ok := attributeTypes["upload_files_to_wildfire"]; !ok {
		t.Fatalf(
			"additional_capabilities has no upload_files_to_wildfire member. members present: %v",
			attributeTypeNames(attributeTypes),
		)
	}

	values := make(map[string]attr.Value, len(attributeTypes))
	for name, attributeType := range attributeTypes {
		switch name {
		case "upload_files_to_wildfire":
			values[name] = types.BoolValue(false)
		default:
			values[name] = nullOf(t, attributeType)
		}
	}

	object, diags := types.ObjectValue(attributeTypes, values)
	if diags.HasError() {
		t.Fatalf("building additional_capabilities failed: %v", diags.Errors())
	}

	model := &CloudManualIntegrationInstanceModel{AdditionalCapabilities: object}

	var conversion diag.Diagnostics
	capabilities := model.additionalCapabilities(context.Background(), &conversion)
	if conversion.HasError() {
		t.Fatalf("converting additional_capabilities failed: %v", conversion.Errors())
	}

	if capabilities.UploadFilesToWildfire == nil {
		t.Fatal("upload_files_to_wildfire = false was dropped; false is a meaningful value here")
	}

	if *capabilities.UploadFilesToWildfire {
		t.Errorf("upload_files_to_wildfire = %v, want false", *capabilities.UploadFilesToWildfire)
	}
}

// TestManualInstanceUploadFilesToWildfireIsUnsetWhenAbsent is the control for
// the two above: an unset member must stay unset, so that the write path can
// tell "leave it alone" from "set it to false". Without this, satisfying the
// tests above by always sending a value would look correct.
func TestManualInstanceUploadFilesToWildfireIsUnsetWhenAbsent(t *testing.T) {
	t.Parallel()

	attributeTypes := ManualAdditionalCapabilitiesAttributeTypes()

	values := make(map[string]attr.Value, len(attributeTypes))
	for name, attributeType := range attributeTypes {
		values[name] = nullOf(t, attributeType)
	}

	object, diags := types.ObjectValue(attributeTypes, values)
	if diags.HasError() {
		t.Fatalf("building additional_capabilities failed: %v", diags.Errors())
	}

	model := &CloudManualIntegrationInstanceModel{AdditionalCapabilities: object}

	var conversion diag.Diagnostics
	capabilities := model.additionalCapabilities(context.Background(), &conversion)
	if conversion.HasError() {
		t.Fatalf("converting additional_capabilities failed: %v", conversion.Errors())
	}

	if capabilities.UploadFilesToWildfire != nil {
		t.Errorf(
			"upload_files_to_wildfire was not configured but reached the SDK as %v; "+
				"omitempty then cannot distinguish it from a deliberate false",
			*capabilities.UploadFilesToWildfire,
		)
	}
}

// TestManualInstanceUploadFilesToWildfireIsReadBack is the read direction. The
// SDK has always carried the field on the read type, so this fails only if the
// refresh path drops it on the way into state - which would show up to a
// practitioner as a permanent diff.
func TestManualInstanceUploadFilesToWildfireIsReadBack(t *testing.T) {
	t.Parallel()

	enabled := true
	read := &cloudOnboardingTypes.AdditionalCapabilitiesRead{
		UploadFilesToWildfire: &enabled,
	}

	var conversion diag.Diagnostics
	object := refreshedAdditionalCapabilities(context.Background(), &conversion, read)
	if conversion.HasError() {
		t.Fatalf("refreshing additional_capabilities failed: %v", conversion.Errors())
	}

	member, ok := object.Attributes()["upload_files_to_wildfire"]
	if !ok {
		t.Fatalf(
			"refreshed additional_capabilities has no upload_files_to_wildfire member; "+
				"members present: %v",
			attributeTypeNames(object.AttributeTypes(context.Background())),
		)
	}

	value, ok := member.(types.Bool)
	if !ok {
		t.Fatalf("upload_files_to_wildfire is %T, want a bool", member)
	}

	if value.IsNull() || !value.ValueBool() {
		t.Errorf("upload_files_to_wildfire read back as %v, want true", member)
	}
}
