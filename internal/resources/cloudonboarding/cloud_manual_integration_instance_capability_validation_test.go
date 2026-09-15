// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package cloudonboarding

import (
	"context"
	"strings"
	"testing"

	models "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/cloud_onboarding"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

// The capability validators below are asserted by running them, not by
// inspecting the schema for a validator of the expected type. A validator that
// is declared but never fires - because it was pointed at the wrong path, or
// because an earlier guard returns before it can report - passes a
// type-inspection test and still lets the offending configuration through to
// the platform. Everything here therefore builds a real config, hands it to the
// real validator taken off the real schema, and asserts on the diagnostics.

// manualCapabilityAttribute returns one member of additional_capabilities.
func manualCapabilityAttribute(t *testing.T, name string) schema.Attribute {
	t.Helper()

	schemaResp := manualInstanceSchema(t)

	attribute, ok := schemaResp.Schema.Attributes["additional_capabilities"]
	if ok == false {
		t.Fatal("schema does not declare additional_capabilities")
	}

	nested, ok := attribute.(schema.SingleNestedAttribute)
	if ok == false {
		t.Fatalf("additional_capabilities is not a single nested attribute (type %T)", attribute)
	}

	member, ok := nested.Attributes[name]
	if ok == false {
		t.Fatalf("additional_capabilities does not declare %s", name)
	}

	return member
}

// manualRegistryOptionAttribute returns one member of
// additional_capabilities.registry_scanning_options.
func manualRegistryOptionAttribute(t *testing.T, name string) schema.Attribute {
	t.Helper()

	options, ok := manualCapabilityAttribute(t, "registry_scanning_options").(schema.SingleNestedAttribute)
	if ok == false {
		t.Fatal("registry_scanning_options is not a single nested attribute")
	}

	member, ok := options.Attributes[name]
	if ok == false {
		t.Fatalf("registry_scanning_options does not declare %s", name)
	}

	return member
}

// nullAttrValue builds the null value of an arbitrary attribute type, so the
// helpers below can fill in every member of an object without knowing which
// members exist.
func nullAttrValue(t *testing.T, attrType attr.Type) attr.Value {
	t.Helper()

	ctx := context.Background()

	value, err := attrType.ValueFromTerraform(ctx, tftypes.NewValue(attrType.TerraformType(ctx), nil))
	if err != nil {
		t.Fatalf("building a null value of %s: %v", attrType, err)
	}

	return value
}

// registryOptionsObject builds a registry_scanning_options object. A nil member
// is recorded as null, which is what an omitted argument looks like in config.
func registryOptionsObject(t *testing.T, scanType *string, lastDays *int64) types.Object {
	t.Helper()

	typeValue := types.StringNull()
	if scanType != nil {
		typeValue = types.StringValue(*scanType)
	}

	lastDaysValue := types.Int64Null()
	if lastDays != nil {
		lastDaysValue = types.Int64Value(*lastDays)
	}

	return types.ObjectValueMust(
		models.ManualRegistryScanningOptionsAttributeTypes(),
		map[string]attr.Value{"type": typeValue, "last_days": lastDaysValue},
	)
}

// capabilitiesObject builds an additional_capabilities object in which every
// member not named in overrides is null.
func capabilitiesObject(t *testing.T, overrides map[string]attr.Value) types.Object {
	t.Helper()

	attrTypes := models.ManualAdditionalCapabilitiesAttributeTypes()

	values := make(map[string]attr.Value, len(attrTypes))
	for name, attrType := range attrTypes {
		values[name] = nullAttrValue(t, attrType)
	}

	for name, value := range overrides {
		if _, ok := attrTypes[name]; ok == false {
			t.Fatalf("additional_capabilities has no member %s", name)
		}
		values[name] = value
	}

	return types.ObjectValueMust(attrTypes, values)
}

// manualConfigWithCapabilities builds a whole-resource config whose only
// populated attribute is additional_capabilities. The validators resolve
// sibling paths through this config, so it has to carry the real schema.
func manualConfigWithCapabilities(t *testing.T, capabilities types.Object) tfsdk.Config {
	t.Helper()

	ctx := context.Background()
	resourceSchema := manualInstanceSchema(t).Schema

	objectType, ok := resourceSchema.Type().TerraformType(ctx).(tftypes.Object)
	if ok == false {
		t.Fatal("the resource type is not an object")
	}

	capabilityValue, err := capabilities.ToTerraformValue(ctx)
	if err != nil {
		t.Fatalf("converting additional_capabilities: %v", err)
	}

	values := make(map[string]tftypes.Value, len(objectType.AttributeTypes))
	for name, attrType := range objectType.AttributeTypes {
		values[name] = tftypes.NewValue(attrType, nil)
	}
	values["additional_capabilities"] = capabilityValue

	return tfsdk.Config{Raw: tftypes.NewValue(objectType, values), Schema: resourceSchema}
}

// validateCapabilityString runs the declared validators of a string member of
// additional_capabilities over the supplied config.
func validateCapabilityString(t *testing.T, config tfsdk.Config, name string, value types.String) diag.Diagnostics {
	t.Helper()

	attribute, ok := manualCapabilityAttribute(t, name).(schema.StringAttribute)
	if ok == false {
		t.Fatalf("%s is not a string attribute", name)
	}

	req := validator.StringRequest{
		Config:         config,
		ConfigValue:    value,
		Path:           path.Root("additional_capabilities").AtName(name),
		PathExpression: path.MatchRoot("additional_capabilities").AtName(name),
	}

	diagnostics := diag.Diagnostics{}
	for _, declared := range attribute.Validators {
		resp := &validator.StringResponse{}
		declared.ValidateString(context.Background(), req, resp)
		diagnostics.Append(resp.Diagnostics...)
	}

	return diagnostics
}

// validateCapabilityBool runs the declared validators of a bool member of
// additional_capabilities over the supplied config.
func validateCapabilityBool(t *testing.T, config tfsdk.Config, name string, value types.Bool) diag.Diagnostics {
	t.Helper()

	attribute, ok := manualCapabilityAttribute(t, name).(schema.BoolAttribute)
	if ok == false {
		t.Fatalf("%s is not a bool attribute", name)
	}

	req := validator.BoolRequest{
		Config:         config,
		ConfigValue:    value,
		Path:           path.Root("additional_capabilities").AtName(name),
		PathExpression: path.MatchRoot("additional_capabilities").AtName(name),
	}

	diagnostics := diag.Diagnostics{}
	for _, declared := range attribute.Validators {
		resp := &validator.BoolResponse{}
		declared.ValidateBool(context.Background(), req, resp)
		diagnostics.Append(resp.Diagnostics...)
	}

	return diagnostics
}

// validateCapabilityObject runs the declared validators of an object member of
// additional_capabilities over the supplied config.
func validateCapabilityObject(t *testing.T, config tfsdk.Config, name string, value types.Object) diag.Diagnostics {
	t.Helper()

	attribute, ok := manualCapabilityAttribute(t, name).(schema.SingleNestedAttribute)
	if ok == false {
		t.Fatalf("%s is not a single nested attribute", name)
	}

	req := validator.ObjectRequest{
		Config:         config,
		ConfigValue:    value,
		Path:           path.Root("additional_capabilities").AtName(name),
		PathExpression: path.MatchRoot("additional_capabilities").AtName(name),
	}

	diagnostics := diag.Diagnostics{}
	for _, declared := range attribute.Validators {
		resp := &validator.ObjectResponse{}
		declared.ValidateObject(context.Background(), req, resp)
		diagnostics.Append(resp.Diagnostics...)
	}

	return diagnostics
}

// validateRegistryOptionString runs the declared validators of a string member
// of registry_scanning_options over the supplied config.
func validateRegistryOptionString(t *testing.T, config tfsdk.Config, name string, value types.String) diag.Diagnostics {
	t.Helper()

	attribute, ok := manualRegistryOptionAttribute(t, name).(schema.StringAttribute)
	if ok == false {
		t.Fatalf("registry_scanning_options.%s is not a string attribute", name)
	}

	base := path.Root("additional_capabilities").AtName("registry_scanning_options")

	req := validator.StringRequest{
		Config:         config,
		ConfigValue:    value,
		Path:           base.AtName(name),
		PathExpression: path.MatchRoot("additional_capabilities").AtName("registry_scanning_options").AtName(name),
	}

	diagnostics := diag.Diagnostics{}
	for _, declared := range attribute.Validators {
		resp := &validator.StringResponse{}
		declared.ValidateString(context.Background(), req, resp)
		diagnostics.Append(resp.Diagnostics...)
	}

	return diagnostics
}

// diagnosticsMention reports whether any diagnostic names the given text, so a
// test can prove the error it received is the error it was looking for rather
// than an unrelated one that happens to be present.
func diagnosticsMention(diagnostics diag.Diagnostics, text string) bool {
	for _, d := range diagnostics.Errors() {
		if strings.Contains(d.Summary(), text) || strings.Contains(d.Detail(), text) {
			return true
		}
	}

	return false
}

// TestManualInstanceRegistryScanningTypeIsRequired proves the scanning type
// cannot be omitted while the option set is configured.
//
// The field is sent as a bare Go string with no omitempty, so an omitted type
// does not drop out of the request: it is transmitted as "type": "". Leaving
// the attribute optional therefore offers the practitioner a configuration
// whose only possible outcome is a request carrying an empty scanning type.
func TestManualInstanceRegistryScanningTypeIsRequired(t *testing.T) {
	t.Parallel()

	attribute, ok := manualRegistryOptionAttribute(t, "type").(schema.StringAttribute)
	if ok == false {
		t.Fatal("registry_scanning_options.type is not a string attribute")
	}

	if attribute.Required == false {
		t.Error("registry_scanning_options.type is not Required; the field has no omitempty, so omitting it sends an empty scanning type rather than sending nothing")
	}
}

// stringPointer is a local helper for building optional string members.
func stringPointer(value string) *string {
	return &value
}
