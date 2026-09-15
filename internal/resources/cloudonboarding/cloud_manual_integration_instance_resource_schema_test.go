// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package cloudonboarding

import (
	"context"
	"testing"

	models "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/cloud_onboarding"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	fwresource "github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

// manualInstanceSchema builds the resource schema, failing the test if it does
// not build or is not a valid implementation.
func manualInstanceSchema(t *testing.T) fwresource.SchemaResponse {
	t.Helper()

	resp := fwresource.SchemaResponse{}
	NewCloudManualIntegrationInstanceResource().Schema(context.Background(), fwresource.SchemaRequest{}, &resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("building the schema produced errors: %v", resp.Diagnostics.Errors())
	}

	if diags := resp.Schema.ValidateImplementation(context.Background()); diags.HasError() {
		t.Fatalf("the schema is not a valid implementation: %v", diags.Errors())
	}

	return resp
}

// stringPlanModifiers returns the plan modifiers declared by a top-level string
// attribute.
func stringPlanModifiers(t *testing.T, name string) []planmodifier.String {
	t.Helper()

	schemaResp := manualInstanceSchema(t)

	attribute, ok := schemaResp.Schema.Attributes[name]
	if ok == false {
		t.Fatalf("schema does not declare %s", name)
	}

	stringAttribute, ok := attribute.(schema.StringAttribute)
	if ok == false {
		t.Fatalf("%s is not a string attribute (type %T)", name, attribute)
	}

	return stringAttribute.PlanModifiers
}

// planModifierRequiresReplaceOnChange runs the attribute's plan modifiers over
// an update and reports whether any of them marked the resource for
// replacement.
//
// This exercises the modifier rather than asserting on its type, so a modifier
// that looks right but never fires is still caught.
func planModifierRequiresReplaceOnChange(t *testing.T, name, stateValue, planValue string) bool {
	t.Helper()

	// Non-null raw state and plan are what tell the modifier this is an update
	// rather than a create or a destroy.
	object := tftypes.Object{AttributeTypes: map[string]tftypes.Type{name: tftypes.String}}

	req := planmodifier.StringRequest{
		StateValue: types.StringValue(stateValue),
		PlanValue:  types.StringValue(planValue),
		State: tfsdk.State{
			Raw: tftypes.NewValue(object, map[string]tftypes.Value{
				name: tftypes.NewValue(tftypes.String, stateValue),
			}),
		},
		Plan: tfsdk.Plan{
			Raw: tftypes.NewValue(object, map[string]tftypes.Value{
				name: tftypes.NewValue(tftypes.String, planValue),
			}),
		},
	}

	replaced := false
	for _, modifier := range stringPlanModifiers(t, name) {
		resp := &planmodifier.StringResponse{PlanValue: req.PlanValue}
		modifier.PlanModifyString(context.Background(), req, resp)
		if resp.Diagnostics.HasError() {
			t.Fatalf("%s plan modifier returned errors: %v", name, resp.Diagnostics.Errors())
		}
		if resp.RequiresReplace {
			replaced = true
		}
	}

	return replaced
}

// TestManualInstanceCloudProviderRequiresReplace proves that changing the cloud
// provider plans a replacement.
//
// The platform accepts an edit that resends the connector's own cloud provider
// and rejects one carrying a different value. Without a replacement the
// provider would produce an update plan the platform can only refuse, which
// surfaces as a failure halfway through an apply rather than at plan time.
func TestManualInstanceCloudProviderRequiresReplace(t *testing.T) {
	t.Parallel()

	if planModifierRequiresReplaceOnChange(t, "cloud_provider", "AWS", "AZURE") == false {
		t.Error("changing cloud_provider did not plan a replacement; the platform rejects an edit that changes it, so such a plan can never apply")
	}
}

// TestManualInstanceCloudProviderUnchangedDoesNotReplace is the other side of
// the boundary. A modifier that replaced unconditionally would satisfy the test
// above while destroying connectors on every unrelated change.
func TestManualInstanceCloudProviderUnchangedDoesNotReplace(t *testing.T) {
	t.Parallel()

	if planModifierRequiresReplaceOnChange(t, "cloud_provider", "AWS", "AWS") {
		t.Error("an unchanged cloud_provider planned a replacement; the platform accepts an edit that resends the same value")
	}
}

// TestManualInstanceImmutableAttributesRequireReplace covers the two further
// attributes the platform fixes at creation.
func TestManualInstanceImmutableAttributesRequireReplace(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name       string
		stateValue string
		planValue  string
	}{
		{name: "scope", stateValue: "ACCOUNT", planValue: "ORGANIZATION"},
		{name: "scan_mode", stateValue: "MANAGED", planValue: "OUTPOST"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if planModifierRequiresReplaceOnChange(t, tc.name, tc.stateValue, tc.planValue) == false {
				t.Errorf("changing %s did not plan a replacement; the platform fixes it at creation", tc.name)
			}
		})
	}
}

// TestManualInstanceWriteAndReadDetailsAreDistinct proves the configurable and
// the reported identity objects are not the same shape.
//
// Collapsing them into one object type would either offer the practitioner a
// member the platform refuses on write, or drop members the platform accepts.
// Both fail silently at apply time, so the asymmetry is asserted key by key
// rather than by counting members.
func TestManualInstanceWriteAndReadDetailsAreDistinct(t *testing.T) {
	t.Parallel()

	write := nestedAttributeNames(t, "manual_details")
	read := nestedAttributeNames(t, "reported_manual_details")

	// Reported and refused on write: every captured create that sent it was
	// rejected.
	if read["client_id"] == false {
		t.Error("reported_manual_details omits client_id, which the platform reports")
	}
	if write["client_id"] {
		t.Error("manual_details offers client_id, which the platform refuses on write")
	}

	// Accepted on write and never reported. Marking these readable would invent
	// values the platform never sends.
	for _, name := range []string{"cloudtrail_role", "sqs_url", "subscription_id"} {
		if write[name] == false {
			t.Errorf("manual_details omits %s, which the platform accepts on write", name)
		}
		if read[name] {
			t.Errorf("reported_manual_details offers %s, which the platform never reports", name)
		}
	}

	// Present on both sides.
	for _, name := range []string{"account_id", "account_name", "organization_id", "role_arn", "external_id", "outpost_scanner_role_arn"} {
		if write[name] == false {
			t.Errorf("manual_details omits %s", name)
		}
		if read[name] == false {
			t.Errorf("reported_manual_details omits %s", name)
		}
	}
}

// TestManualInstanceGCPDetailsAreNotModelled pins that the GCP-only members are
// absent, because manual onboarding does not support GCP.
//
// This test previously asserted the opposite. It is inverted rather than
// deleted: the members were modelled once, so an assertion that they are gone
// is what stops them being reinstated by a copy-paste from the automated
// onboarding resource, which does support GCP.
func TestManualInstanceGCPDetailsAreNotModelled(t *testing.T) {
	t.Parallel()

	write := nestedAttributeNames(t, "manual_details")

	for _, name := range []string{
		"service_account_email",
		"outpost_scanner_service_account_email",
		"audit_service_account_email",
		"audit_pubsub_subscription_id",
		"account_group",
	} {
		if write[name] {
			t.Errorf("manual_details offers the GCP-only member %s, which no supported cloud_provider can use", name)
		}
	}

	// The shared members must survive the GCP removal: AWS uses both, so
	// removing them would break a supported provider.
	for _, name := range []string{"account_id", "organization_id"} {
		if write[name] == false {
			t.Errorf("manual_details omits %s, which AWS connectors need; the GCP removal took a shared member with it", name)
		}
	}
}

// TestManualInstanceConfigurableAttributes pins which attributes a practitioner
// can set and which only the platform fills in.
func TestManualInstanceConfigurableAttributes(t *testing.T) {
	t.Parallel()

	schemaResp := manualInstanceSchema(t)

	for _, tc := range []struct {
		name     string
		required bool
		optional bool
		computed bool
		why      string
	}{
		{name: "id", computed: true, why: "the platform assigns the connector ID on creation"},
		{name: "cloud_provider", required: true, why: "the write endpoints reject a payload without it"},
		{name: "scope", required: true, why: "the write endpoints reject a payload without it"},
		{name: "scan_mode", required: true, why: "the write endpoints reject a payload without it"},
		{name: "manual_details", required: true, why: "the write endpoints reject a payload without it"},
		{name: "outpost_id", optional: true, why: "it applies only to the OUTPOST scan mode"},
		{name: "instance_name", optional: true, computed: true, why: "the platform assigns one when it is omitted"},
		{name: "cloud_partition", optional: true, computed: true, why: "the platform defaults it when it is omitted"},
		{name: "reported_manual_details", computed: true, why: "it is what the platform reports and is never sent"},
		{name: "additional_capabilities", optional: true, computed: true, why: "the platform defaults the toggles left unset"},
		{name: "collection_configuration", optional: true, computed: true, why: "the platform defaults the configuration left unset"},
		{name: "scope_modifications", optional: true, computed: true, why: "the platform populates members of it itself"},
		{name: "custom_resources_tags", optional: true, computed: true, why: "an imported connector's tags must not have to be transcribed by hand"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			attribute, ok := schemaResp.Schema.Attributes[tc.name]
			if ok == false {
				t.Fatalf("schema does not declare %s", tc.name)
			}

			if attribute.IsRequired() != tc.required {
				t.Errorf("%s required = %t, want %t: %s", tc.name, attribute.IsRequired(), tc.required, tc.why)
			}
			if attribute.IsOptional() != tc.optional {
				t.Errorf("%s optional = %t, want %t: %s", tc.name, attribute.IsOptional(), tc.optional, tc.why)
			}
			if attribute.IsComputed() != tc.computed {
				t.Errorf("%s computed = %t, want %t: %s", tc.name, attribute.IsComputed(), tc.computed, tc.why)
			}
		})
	}
}

// TestManualInstanceReportedDetailsAreNotConfigurable proves every member of
// the reported identity object is read-only. A configurable member there would
// invite a practitioner to set a value that is never sent anywhere.
func TestManualInstanceReportedDetailsAreNotConfigurable(t *testing.T) {
	t.Parallel()

	schemaResp := manualInstanceSchema(t)

	attribute, ok := schemaResp.Schema.Attributes["reported_manual_details"]
	if ok == false {
		t.Fatal("schema does not declare reported_manual_details")
	}

	nested, ok := attribute.(schema.SingleNestedAttribute)
	if ok == false {
		t.Fatalf("reported_manual_details is not a single-nested attribute (type %T)", attribute)
	}

	for name, nestedAttribute := range nested.Attributes {
		if nestedAttribute.IsRequired() || nestedAttribute.IsOptional() {
			t.Errorf("reported_manual_details.%s is configurable; it is only ever reported by the platform", name)
		}
		if nestedAttribute.IsComputed() == false {
			t.Errorf("reported_manual_details.%s is not computed, so the reported value cannot be recorded", name)
		}
	}
}

// nestedAttributeTypes returns the member types of a top-level single-nested
// attribute, read from the object type the attribute resolves to.
func nestedAttributeTypes(t *testing.T, name string) map[string]attr.Type {
	t.Helper()

	schemaResp := manualInstanceSchema(t)

	attribute, ok := schemaResp.Schema.Attributes[name]
	if ok == false {
		t.Fatalf("schema does not declare %s", name)
	}

	objectType, ok := attribute.GetType().(types.ObjectType)
	if ok == false {
		t.Fatalf("%s is not a single-nested attribute (type %s)", name, attribute.GetType())
	}

	return objectType.AttributeTypes()
}

// nestedAttributeNames returns the member names of a top-level single-nested
// attribute.
func nestedAttributeNames(t *testing.T, name string) map[string]bool {
	t.Helper()

	attributeTypes := nestedAttributeTypes(t, name)

	names := make(map[string]bool, len(attributeTypes))
	for nestedName := range attributeTypes {
		names[nestedName] = true
	}

	return names
}

// TestManualInstanceExternalIDIsSensitive holds the one member of these blocks
// that is a shared secret rather than an identifier.
//
// In the AWS cross-account model the external ID is what prevents the
// confused-deputy attack against an assumable role: possession of it, together
// with the role ARN, is what an unrelated caller would need. The schema's own
// description calls it a guard. Left unmarked it is rendered in full in plan
// output and in whatever CI log captures that plan, in both the configured and
// the reported block.
//
// The identifiers are asserted unmarked in the same test on purpose. Marking
// them would make plans unreadable -- an ARN, a queue URL and an account ID are
// published values, not credentials -- and a later blanket change that marked
// everything would leave the sensitive-marking with no meaning left to carry.
func TestManualInstanceExternalIDIsSensitive(t *testing.T) {
	t.Parallel()

	schemaResp := manualInstanceSchema(t)

	for _, block := range []string{"manual_details", "reported_manual_details"} {
		attributes := nestedAttributes(t, schemaResp.Schema.Attributes, block)

		externalID, ok := attributes["external_id"].(schema.StringAttribute)
		if ok == false {
			t.Fatalf("%s does not declare external_id as a string attribute", block)
		}
		if externalID.Sensitive == false {
			t.Errorf("%s.external_id is not marked sensitive, so the value that "+
				"guards the assumed AWS role is printed in plan output and CI logs", block)
		}

		// Identifiers, not secrets. These are the control: if this loop ever
		// passes for every member, the assertion above has stopped meaning
		// "the secret is marked" and started meaning "everything is marked".
		for _, name := range []string{"role_arn", "outpost_scanner_role_arn", "account_id", "organization_id"} {
			attribute, ok := attributes[name].(schema.StringAttribute)
			if ok == false {
				continue
			}
			if attribute.Sensitive {
				t.Errorf("%s.%s is marked sensitive, but it is an identifier the "+
					"cloud provider publishes; hiding it makes plans unreadable "+
					"for no security gain", block, name)
			}
		}
	}
}

// TestManualInstanceSchemaMatchesModelAttributeTypes proves the schema and the
// conversion helpers describe the same objects.
//
// The conversions build their objects from the attribute-type maps in the model
// package. A member added to one and not the other fails at runtime with an
// obscure type error; this turns that into a named failure at build time.
func TestManualInstanceSchemaMatchesModelAttributeTypes(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		attribute      string
		attributeTypes map[string]attr.Type
	}{
		{attribute: "manual_details", attributeTypes: models.ManualDetailsWriteAttributeTypes()},
		{attribute: "reported_manual_details", attributeTypes: models.ManualDetailsReadAttributeTypes()},
		{attribute: "additional_capabilities", attributeTypes: models.ManualAdditionalCapabilitiesAttributeTypes()},
		{attribute: "collection_configuration", attributeTypes: models.ManualCollectionConfigurationAttributeTypes()},
		{attribute: "scope_modifications", attributeTypes: models.ManualScopeModificationsAttributeTypes()},
	} {
		t.Run(tc.attribute, func(t *testing.T) {
			t.Parallel()

			schemaTypes := nestedAttributeTypes(t, tc.attribute)

			for name, modelType := range tc.attributeTypes {
				schemaType, ok := schemaTypes[name]
				if ok == false {
					t.Errorf("the model declares %s.%s but the schema does not", tc.attribute, name)
					continue
				}
				if schemaType.Equal(modelType) == false {
					t.Errorf("%s.%s is %s in the schema and %s in the model", tc.attribute, name, schemaType, modelType)
				}
			}
			for name := range schemaTypes {
				if _, ok := tc.attributeTypes[name]; ok == false {
					t.Errorf("the schema declares %s.%s but the model does not", tc.attribute, name)
				}
			}
		})
	}
}
