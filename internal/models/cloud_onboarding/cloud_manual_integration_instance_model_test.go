// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package models

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"

	cloudOnboardingTypes "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/types/cloudonboarding"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func stringPtr(value string) *string { return &value }

func boolPtr(value bool) *bool { return &value }

// manualDetailsObject builds a manual_details value from the named members,
// leaving every other member null.
func manualDetailsObject(t *testing.T, members map[string]string) types.Object {
	t.Helper()

	attributeTypes := ManualDetailsWriteAttributeTypes()
	values := make(map[string]attr.Value, len(attributeTypes))
	for name := range attributeTypes {
		if value, ok := members[name]; ok {
			values[name] = types.StringValue(value)
			continue
		}
		values[name] = types.StringNull()
	}

	object, diags := types.ObjectValue(attributeTypes, values)
	if diags.HasError() {
		t.Fatalf("building manual_details failed: %v", diags.Errors())
	}

	return object
}

// TestManualDetailsWriteAndReadShapesAreDistinct proves the two Terraform
// object types are not interchangeable.
//
// The platform reports client_id and refuses it on write; it accepts
// cloudtrail_role, sqs_url and subscription_id on write and never reports them.
// Collapsing the two shapes into one would therefore either produce a payload
// the platform rejects, or record values it never sends. This mirrors the same
// assertion in the SDK, one layer up.
func TestManualDetailsWriteAndReadShapesAreDistinct(t *testing.T) {
	t.Parallel()

	write := ManualDetailsWriteAttributeTypes()
	read := ManualDetailsReadAttributeTypes()

	if _, ok := read["client_id"]; ok == false {
		t.Error("the read shape omits client_id, which the platform reports")
	}
	if _, ok := write["client_id"]; ok {
		t.Error("the write shape offers client_id, which the platform refuses on write")
	}

	for _, name := range []string{"cloudtrail_role", "sqs_url", "subscription_id"} {
		if _, ok := write[name]; ok == false {
			t.Errorf("the write shape omits %s, which the platform accepts on write", name)
		}
		if _, ok := read[name]; ok {
			t.Errorf("the read shape offers %s, which the platform never reports", name)
		}
	}

	if reflect.DeepEqual(write, read) {
		t.Error("the write and read shapes are identical; they are two different contracts and must not be collapsed into one")
	}
}

// manualDetailsGCPOnlyMembers are the members the SDK carries for GCP and the
// Terraform shapes deliberately omit, because manual onboarding does not
// support GCP.
//
// This list exists so the parity check below can permit exactly these keys and
// nothing else. If manual GCP onboarding is implemented, empty this map and the
// parity check will demand the Terraform shapes carry them again.
var manualDetailsGCPOnlyMembers = map[string]bool{
	"service_account_email":                 true,
	"outpost_scanner_service_account_email": true,
	"audit_service_account_email":           true,
	"audit_pubsub_subscription_id":          true,
	"account_group":                         true,
}

// TestManualDetailsShapesTrackTheSDKTypes proves the Terraform object types
// carry exactly the members of the SDK types they are converted to and from.
//
// A member present in one and not the other is silent data loss: the conversion
// compiles, the apply succeeds, and the value never reaches the platform.
func TestManualDetailsShapesTrackTheSDKTypes(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name           string
		sdkType        any
		attributeTypes map[string]attr.Type
	}{
		{name: "write", sdkType: cloudOnboardingTypes.ManualDetails{}, attributeTypes: ManualDetailsWriteAttributeTypes()},
		{name: "read", sdkType: cloudOnboardingTypes.ManualDetailsRead{}, attributeTypes: ManualDetailsReadAttributeTypes()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			sdkKeys := jsonKeys(t, tc.sdkType)

			for key := range sdkKeys {
				// The SDK deliberately retains the GCP members: the SDK models
				// the platform API, which has them, while this provider does
				// not expose manual GCP onboarding. Their absence from the
				// Terraform shape is intended, not silent data loss, so they
				// are the one permitted asymmetry. Keeping the exception
				// explicit means every OTHER mismatch still fails.
				if manualDetailsGCPOnlyMembers[key] {
					if _, ok := tc.attributeTypes[key]; ok {
						t.Errorf("the Terraform %s shape carries the GCP-only member %s, but manual onboarding does not support GCP", tc.name, key)
					}

					continue
				}

				if _, ok := tc.attributeTypes[key]; ok == false {
					t.Errorf("the SDK %s type carries %s but the Terraform shape does not, so the value is dropped", tc.name, key)
				}
			}
			for key := range tc.attributeTypes {
				if sdkKeys[key] == false {
					t.Errorf("the Terraform %s shape carries %s but the SDK type does not, so the value is never sent", tc.name, key)
				}
			}
		})
	}
}

// jsonKeys reports the JSON member names of a struct.
func jsonKeys(t *testing.T, value any) map[string]bool {
	t.Helper()

	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshalling %T failed: %v", value, err)
	}

	// Every member of both types is an omitempty pointer, so marshalling a zero
	// value yields no keys. Reflect over the tags instead.
	_ = encoded

	keys := map[string]bool{}
	structType := reflect.TypeOf(value)
	for i := 0; i < structType.NumField(); i++ {
		tag := structType.Field(i).Tag.Get("json")
		if tag == "" || tag == "-" {
			continue
		}
		name := tag
		for index := 0; index < len(tag); index++ {
			if tag[index] == ',' {
				name = tag[:index]
				break
			}
		}
		keys[name] = true
	}

	return keys
}

// TestToCreateRequestSendsConfiguredDetails proves the configured identity
// reaches the payload under the names the platform expects.
func TestToCreateRequestSendsConfiguredDetails(t *testing.T) {
	t.Parallel()

	model := CloudManualIntegrationInstanceModel{
		CloudProvider: types.StringValue("AWS"),
		Scope:         types.StringValue("ACCOUNT"),
		ScanMode:      types.StringValue("MANAGED"),
		InstanceName:  types.StringValue("example"),
		ManualDetails: manualDetailsObject(t, map[string]string{
			"account_id":      "782785052462",
			"account_name":    "example",
			"role_arn":        "arn:aws:iam::782785052462:role/example",
			"external_id":     "9d7ad021-5f2e-4f5b-9240-b2b43e367f42",
			"cloudtrail_role": "arn:aws:iam::782785052462:role/example-cloudtrail",
			"sqs_url":         "https://sqs.us-east-1.amazonaws.com/782785052462/example",
		}),
		AdditionalCapabilities:  types.ObjectNull(ManualAdditionalCapabilitiesAttributeTypes()),
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

	details, ok := payload["manual_details"].(map[string]any)
	if ok == false {
		t.Fatalf("the payload carries no manual_details object: %v", payload["manual_details"])
	}

	for name, want := range map[string]string{
		"account_id":      "782785052462",
		"account_name":    "example",
		"role_arn":        "arn:aws:iam::782785052462:role/example",
		"external_id":     "9d7ad021-5f2e-4f5b-9240-b2b43e367f42",
		"cloudtrail_role": "arn:aws:iam::782785052462:role/example-cloudtrail",
		"sqs_url":         "https://sqs.us-east-1.amazonaws.com/782785052462/example",
	} {
		if details[name] != want {
			t.Errorf("manual_details.%s = %v, want %q", name, details[name], want)
		}
	}

	// Unconfigured members must not reach the wire: the platform shapes this
	// object per provider, and a null sent as an empty string is not the same
	// as an absent key.
	if _, ok := details["tenant_id"]; ok {
		t.Error("manual_details carries tenant_id, which was not configured")
	}

	for name, want := range map[string]any{
		"cloud_provider": "AWS",
		"scope":          "ACCOUNT",
		"scan_mode":      "MANAGED",
		"instance_name":  "example",
	} {
		if payload[name] != want {
			t.Errorf("%s = %v, want %v", name, payload[name], want)
		}
	}
}

// TestToEditRequestSendsCompleteDesiredState proves the edit payload carries
// the whole desired state rather than a diff.
//
// The platform's edit is partial: a member left out of the payload keeps its
// previous value instead of being cleared. A payload built from a diff would
// therefore leave stale data behind with no error, so the edit payload must
// carry the same members as the create payload.
func TestToEditRequestSendsCompleteDesiredState(t *testing.T) {
	t.Parallel()

	model := CloudManualIntegrationInstanceModel{
		ID:            types.StringValue("02e4d33a104349f3bfcf3babf082f4a3"),
		CloudProvider: types.StringValue("AWS"),
		Scope:         types.StringValue("ACCOUNT"),
		ScanMode:      types.StringValue("MANAGED"),
		ManualDetails: manualDetailsObject(t, map[string]string{
			"account_id":   "782785052462",
			"account_name": "example",
			"role_arn":     "arn:aws:iam::782785052462:role/example",
			"external_id":  "9d7ad021-5f2e-4f5b-9240-b2b43e367f42",
		}),
		AdditionalCapabilities:  types.ObjectNull(ManualAdditionalCapabilitiesAttributeTypes()),
		CollectionConfiguration: types.ObjectNull(ManualCollectionConfigurationAttributeTypes()),
		ScopeModifications:      types.ObjectNull(ManualScopeModificationsAttributeTypes()),
		CustomResourcesTags:     types.SetNull(ManualCustomResourcesTagType()),
	}

	diagnostics := diag.Diagnostics{}
	request := model.ToEditRequest(context.Background(), &diagnostics)
	if diagnostics.HasError() {
		t.Fatalf("building the edit request failed: %v", diagnostics.Errors())
	}

	payload := marshalled(t, request)

	// The identity of the connector and the three members the platform fixes at
	// creation must all be resent: omitting the cloud provider is answered with
	// a server error rather than a validation message.
	for name, want := range map[string]any{
		"id":             "02e4d33a104349f3bfcf3babf082f4a3",
		"cloud_provider": "AWS",
		"scope":          "ACCOUNT",
		"scan_mode":      "MANAGED",
	} {
		if payload[name] != want {
			t.Errorf("%s = %v, want %v", name, payload[name], want)
		}
	}

	// The whole desired state, not a diff: these objects are required by the
	// endpoint and omitting scope_modifications is answered with a 500.
	for _, name := range []string{"manual_details", "additional_capabilities", "collection_configuration", "scope_modifications"} {
		if _, ok := payload[name]; ok == false {
			t.Errorf("the edit payload omits %s; the endpoint requires it and a partial edit leaves stale data behind", name)
		}
	}

	details, ok := payload["manual_details"].(map[string]any)
	if ok == false {
		t.Fatalf("the payload carries no manual_details object: %v", payload["manual_details"])
	}
	if details["account_id"] != "782785052462" {
		t.Errorf("manual_details.account_id = %v, want %q", details["account_id"], "782785052462")
	}
}

// TestRefreshFromReadResponseDoesNotEchoTheReadIntoTheWrite proves a refresh
// leaves the configured identity untouched.
//
// The read reply is not a legal write body. If a refresh copied it into
// manual_details, the next apply would send the platform a payload it refuses,
// and the practitioner's own configuration would have been overwritten by
// values they never wrote.
func TestRefreshFromReadResponseDoesNotEchoTheReadIntoTheWrite(t *testing.T) {
	t.Parallel()

	configured := manualDetailsObject(t, map[string]string{
		"account_id":   "782785052462",
		"account_name": "example",
	})

	model := CloudManualIntegrationInstanceModel{
		ManualDetails:       configured,
		CustomResourcesTags: types.SetNull(ManualCustomResourcesTagType()),
	}

	diagnostics := diag.Diagnostics{}
	model.RefreshFromReadResponse(context.Background(), &diagnostics, cloudOnboardingTypes.InstanceEditFields{
		InstanceName:  "example",
		CloudProvider: "AZURE",
		Scope:         "ACCOUNT",
		ScanMode:      "MANAGED",
		ManualDetails: &cloudOnboardingTypes.ManualDetailsRead{
			AccountID: stringPtr("a-different-account"),
			ClientID:  stringPtr("6f1b6f21-0b3f-4d3f-9f6a-1c8b0d2e5a77"),
			TenantID:  stringPtr("2a2b2c2d-0000-4444-8888-999999999999"),
		},
	})
	if diagnostics.HasError() {
		t.Fatalf("refreshing failed: %v", diagnostics.Errors())
	}

	if model.ManualDetails.Equal(configured) == false {
		t.Errorf("the refresh overwrote the configured manual_details with the read reply: %v", model.ManualDetails)
	}

	reported := model.ReportedManualDetails.Attributes()
	if reported["client_id"].Equal(types.StringValue("6f1b6f21-0b3f-4d3f-9f6a-1c8b0d2e5a77")) == false {
		t.Errorf("reported_manual_details.client_id = %v, want the reported value", reported["client_id"])
	}
	if reported["account_id"].Equal(types.StringValue("a-different-account")) == false {
		t.Errorf("reported_manual_details.account_id = %v, want the reported value", reported["account_id"])
	}
}

// TestRefreshFromReadResponseTakesAuditLogsFromTheReply proves every audit_logs
// member is refreshed from what the platform reports.
//
// This object used to carry cloudtrail_role and sqs_url, which the platform
// never reported, so the refresh had to copy them from the prior state. It
// never accepted them here either -- it answered "extra_forbidden" -- so both
// were removed, and with them the only reason to prefer prior state over the
// reply. Nothing in this object is write-only any more.
func TestRefreshFromReadResponseTakesAuditLogsFromTheReply(t *testing.T) {
	t.Parallel()

	auditLogTypes := ManualAuditLogsAttributeTypes()
	auditLogs, diags := types.ObjectValue(auditLogTypes, map[string]attr.Value{
		"enabled":               types.BoolValue(true),
		"data_events":           types.BoolValue(false),
		"collection_method":     types.StringValue("CUSTOM"),
		"is_control_tower_byob": types.BoolNull(),
	})
	if diags.HasError() {
		t.Fatalf("building audit_logs failed: %v", diags.Errors())
	}

	collection, diags := types.ObjectValue(ManualCollectionConfigurationAttributeTypes(), map[string]attr.Value{
		"audit_logs": auditLogs,
	})
	if diags.HasError() {
		t.Fatalf("building collection_configuration failed: %v", diags.Errors())
	}

	model := CloudManualIntegrationInstanceModel{
		ManualDetails:           types.ObjectNull(ManualDetailsWriteAttributeTypes()),
		CollectionConfiguration: collection,
		CustomResourcesTags:     types.SetNull(ManualCustomResourcesTagType()),
	}

	diagnostics := diag.Diagnostics{}
	model.RefreshFromReadResponse(context.Background(), &diagnostics, cloudOnboardingTypes.InstanceEditFields{
		CloudProvider: "AWS",
		Scope:         "ACCOUNT",
		ScanMode:      "MANAGED",
		CollectionConfiguration: &cloudOnboardingTypes.CollectionConfigurationRead{
			AuditLogs: cloudOnboardingTypes.AuditLogsRead{
				Enabled:          true,
				DataEvents:       true,
				CollectionMethod: "CUSTOM",
			},
		},
	})
	if diagnostics.HasError() {
		t.Fatalf("refreshing failed: %v", diagnostics.Errors())
	}

	refreshed := model.CollectionConfiguration.Attributes()["audit_logs"].(types.Object).Attributes()

	// The reply says true and the prior state said false: the reply wins.
	if refreshed["data_events"].Equal(types.BoolValue(true)) == false {
		t.Errorf("data_events = %v, want the reported value", refreshed["data_events"])
	}

	// The members the platform refuses must not reappear.
	for _, name := range []string{"cloudtrail_role", "sqs_url"} {
		if _, found := refreshed[name]; found {
			t.Errorf("audit_logs.%s is back; the platform refuses it there with extra_forbidden", name)
		}
	}
}

// TestRefreshFromReadResponseRecordsReportedCapabilities proves the capability
// toggles the platform reports reach state.
func TestRefreshFromReadResponseRecordsReportedCapabilities(t *testing.T) {
	t.Parallel()

	model := CloudManualIntegrationInstanceModel{
		ManualDetails:       types.ObjectNull(ManualDetailsWriteAttributeTypes()),
		CustomResourcesTags: types.SetNull(ManualCustomResourcesTagType()),
	}

	diagnostics := diag.Diagnostics{}
	model.RefreshFromReadResponse(context.Background(), &diagnostics, cloudOnboardingTypes.InstanceEditFields{
		CloudProvider: "AWS",
		Scope:         "ACCOUNT",
		ScanMode:      "MANAGED",
		AdditionalCapabilities: &cloudOnboardingTypes.AdditionalCapabilitiesRead{
			XSIAMAnalytics:        boolPtr(true),
			RegistryScanning:      boolPtr(false),
			AutomationLogLevel:    stringPtr("INFO"),
			UploadFilesToWildfire: boolPtr(true),
		},
	})
	if diagnostics.HasError() {
		t.Fatalf("refreshing failed: %v", diagnostics.Errors())
	}

	capabilities := model.AdditionalCapabilities.Attributes()

	if capabilities["xsiam_analytics"].Equal(types.BoolValue(true)) == false {
		t.Errorf("xsiam_analytics = %v, want the reported value", capabilities["xsiam_analytics"])
	}
	if capabilities["registry_scanning"].Equal(types.BoolValue(false)) == false {
		t.Errorf("registry_scanning = %v, want the reported value", capabilities["registry_scanning"])
	}

	// automation_log_level IS a write field, contrary to what this assertion
	// used to claim. The create endpoint validates it against a closed set --
	//
	//	422 {"loc": ["additional_capabilities", "automation_log_level"],
	//	     "msg": "Input should be 'OFF', 'Debug' or 'Verbose'"}
	//
	// -- and refuses automation sent without it. A value the platform both
	// validates and demands has to be recordable, or a refresh would drop it
	// and the next apply would send automation on its own and fail.
	if _, ok := capabilities["automation_log_level"]; !ok {
		t.Error("additional_capabilities does not record automation_log_level, which the manual write endpoints require alongside automation")
	}
}

// TestRefreshFromReadResponseKeepsPlatformInjectedTagsOutOfState proves a tag
// the platform adds by itself does not enter custom_resources_tags.
//
// Cortex Cloud stamps every connector it creates with its own
// "managed_by=paloaltonetworks" tag. That tag is not in the practitioner's
// configuration and cannot be put there -- the same key with any other value is
// refused outright -- so recording it in state makes the applied value differ
// from the planned one. Terraform calls that
//
//	Provider produced inconsistent result after apply:
//	.custom_resources_tags: length changed from 1 to 2
//
// and aborts, which is what a real "terraform apply" of the published AWS
// example did. Refreshing must therefore report only the tags a configuration
// can actually express.
func TestRefreshFromReadResponseKeepsPlatformInjectedTagsOutOfState(t *testing.T) {
	t.Parallel()

	model := CloudManualIntegrationInstanceModel{
		ManualDetails:       types.ObjectNull(ManualDetailsWriteAttributeTypes()),
		CustomResourcesTags: types.SetNull(ManualCustomResourcesTagType()),
	}

	diagnostics := diag.Diagnostics{}
	model.RefreshFromReadResponse(context.Background(), &diagnostics, cloudOnboardingTypes.InstanceEditFields{
		CloudProvider: "AWS",
		Scope:         "ACCOUNT",
		ScanMode:      "MANAGED",
		CustomResourcesTags: []cloudOnboardingTypes.Tag{
			{Key: "provisioned_by", Value: "terraform"},
			{Key: "managed_by", Value: "paloaltonetworks"},
		},
	})
	if diagnostics.HasError() {
		t.Fatalf("refreshing failed: %v", diagnostics.Errors())
	}

	elements := model.CustomResourcesTags.Elements()
	if len(elements) != 1 {
		t.Fatalf("custom_resources_tags has %d elements, want 1: the platform's own "+
			"managed_by tag must not be recorded, or every apply of a configuration "+
			"that sets tags fails as inconsistent. Got %v", len(elements), elements)
	}

	attributes := elements[0].(types.Object).Attributes()
	if !attributes["key"].Equal(types.StringValue("provisioned_by")) {
		t.Errorf("the surviving tag is %v, want the practitioner's own provisioned_by tag", attributes["key"])
	}
}

// TestRefreshFromReadResponseKeepsAConfigurableManagedByTag is a positive
// control for the filter above: near misses must survive it.
//
// It does NOT discriminate a key-only filter from the correct one -- neither
// "managed_by_team" nor "owner" equals "managed_by", so a key-only filter drops
// neither and passes this test unchanged. Mutating the filter to key-only
// proved exactly that. The test that does discriminate is
// TestRefreshFromReadResponseKeepsTheManagedByTagTheConfigurationDeclared.
func TestRefreshFromReadResponseKeepsAConfigurableManagedByTag(t *testing.T) {
	t.Parallel()

	model := CloudManualIntegrationInstanceModel{
		ManualDetails:       types.ObjectNull(ManualDetailsWriteAttributeTypes()),
		CustomResourcesTags: types.SetNull(ManualCustomResourcesTagType()),
	}

	diagnostics := diag.Diagnostics{}
	model.RefreshFromReadResponse(context.Background(), &diagnostics, cloudOnboardingTypes.InstanceEditFields{
		CloudProvider: "AWS",
		Scope:         "ACCOUNT",
		ScanMode:      "MANAGED",
		CustomResourcesTags: []cloudOnboardingTypes.Tag{
			{Key: "managed_by_team", Value: "platform"},
			{Key: "owner", Value: "paloaltonetworks"},
		},
	})
	if diagnostics.HasError() {
		t.Fatalf("refreshing failed: %v", diagnostics.Errors())
	}

	if got := len(model.CustomResourcesTags.Elements()); got != 2 {
		t.Fatalf("custom_resources_tags has %d elements, want 2: neither a near-miss key "+
			"nor the platform's value under a different key is the reserved pair, so both "+
			"must survive", got)
	}
}

// TestRefreshFromReadResponseKeepsTheManagedByTagTheConfigurationDeclared
// proves the filter is driven by the configuration, not by the pair alone.
//
// "managed_by=paloaltonetworks" is not forbidden -- it is the ONE value the key
// accepts. Onboarding with it returns 200 and the connector is created, so a
// practitioner may legitimately write it. Dropping it unconditionally is then
// the same defect the filter was added to fix, only mirrored: the plan holds
// one tag, the refreshed state holds none, and Terraform aborts with
//
//	Provider produced inconsistent result after apply:
//	.custom_resources_tags: length changed from 1 to 0
//
// So the tag is discarded only when the configuration did not ask for it.
func TestRefreshFromReadResponseKeepsTheManagedByTagTheConfigurationDeclared(t *testing.T) {
	t.Parallel()

	declared, diags := types.SetValueFrom(
		context.Background(),
		ManualCustomResourcesTagType(),
		[]cloudOnboardingTypes.Tag{{Key: "managed_by", Value: "paloaltonetworks"}},
	)
	if diags.HasError() {
		t.Fatalf("building the configured tag set failed: %v", diags.Errors())
	}

	model := CloudManualIntegrationInstanceModel{
		ManualDetails:       types.ObjectNull(ManualDetailsWriteAttributeTypes()),
		CustomResourcesTags: declared,
	}

	diagnostics := diag.Diagnostics{}
	model.RefreshFromReadResponse(context.Background(), &diagnostics, cloudOnboardingTypes.InstanceEditFields{
		CloudProvider: "AWS",
		Scope:         "ACCOUNT",
		ScanMode:      "MANAGED",
		CustomResourcesTags: []cloudOnboardingTypes.Tag{
			{Key: "managed_by", Value: "paloaltonetworks"},
		},
	})
	if diagnostics.HasError() {
		t.Fatalf("refreshing failed: %v", diagnostics.Errors())
	}

	elements := model.CustomResourcesTags.Elements()
	if len(elements) != 1 {
		t.Fatalf("custom_resources_tags has %d elements, want 1: the configuration "+
			"declared managed_by=paloaltonetworks and the platform accepted it, so "+
			"dropping it makes the applied value differ from the planned one. Got %v",
			len(elements), elements)
	}
}

// TestRefreshFromReadResponseLeavesNoUnknownWhenTheReplyOmitsScopeModifications
// holds every Optional+Computed object to the one property Terraform enforces
// unconditionally: nothing may still be unknown once apply returns.
//
// scope_modifications is Optional+Computed, so a configuration that says
// nothing about scope plans as UNKNOWN. The read reply may leave the object out
// -- InstanceEditFields.ScopeModifications is a pointer with omitempty, so
// absence is representable -- and a refresh that hands the planned value back
// unchanged writes that UNKNOWN into state. Terraform answers with "Provider
// returned invalid result object after apply", and it does so after the
// connector has been created, leaving a live connector with no state.
//
// The three sibling objects are asserted alongside as in-test controls. They
// already resolve absence to null, so if this test ever fails for all four at
// once the cause is the harness, not the refresher.
func TestRefreshFromReadResponseLeavesNoUnknownWhenTheReplyOmitsScopeModifications(t *testing.T) {
	t.Parallel()

	// The plan shape of a configuration that mentions none of these objects.
	model := CloudManualIntegrationInstanceModel{
		ManualDetails:           types.ObjectNull(ManualDetailsWriteAttributeTypes()),
		ReportedManualDetails:   types.ObjectUnknown(ManualDetailsReadAttributeTypes()),
		AdditionalCapabilities:  types.ObjectUnknown(ManualAdditionalCapabilitiesAttributeTypes()),
		CollectionConfiguration: types.ObjectUnknown(ManualCollectionConfigurationAttributeTypes()),
		ScopeModifications:      types.ObjectUnknown(ManualScopeModificationsAttributeTypes()),
		CustomResourcesTags:     types.SetNull(ManualCustomResourcesTagType()),
	}

	// A reply that omits all four objects. Every one is a pointer with
	// omitempty, so this is a shape the SDK type permits.
	diagnostics := diag.Diagnostics{}
	model.RefreshFromReadResponse(context.Background(), &diagnostics, cloudOnboardingTypes.InstanceEditFields{
		InstanceName:  "example",
		CloudProvider: "AWS",
		Scope:         "ACCOUNT",
		ScanMode:      "MANAGED",
	})
	if diagnostics.HasError() {
		t.Fatalf("refreshing failed: %v", diagnostics.Errors())
	}

	for name, value := range map[string]types.Object{
		"scope_modifications":      model.ScopeModifications,
		"collection_configuration": model.CollectionConfiguration,
		"additional_capabilities":  model.AdditionalCapabilities,
		"reported_manual_details":  model.ReportedManualDetails,
	} {
		if value.IsUnknown() {
			t.Errorf("%s is still unknown after the refresh, so apply returns an "+
				"unknown value and Terraform aborts with \"Provider returned "+
				"invalid result object after apply\" -- after the connector was "+
				"created, leaving it live with no state", name)
		}
	}
}

// TestRefreshFromReadResponseKeepsConfiguredScopeModificationsTheReplyOmits is
// the counterpart control: absence in the reply must not discard a value the
// practitioner actually wrote.
//
// The two tests together pin the behaviour from both sides. Without this one,
// returning a null object unconditionally would satisfy the test above while
// silently erasing configuration and showing it as perpetual drift.
func TestRefreshFromReadResponseKeepsConfiguredScopeModificationsTheReplyOmits(t *testing.T) {
	t.Parallel()

	regionTypes := ManualScopeModificationsAttributeTypes()["regions"].(types.ObjectType).AttrTypes
	regions, diags := types.ObjectValue(regionTypes, map[string]attr.Value{
		"enabled": types.BoolValue(true),
		"type":    types.StringValue("INCLUDE"),
		"regions": types.ListValueMust(
			types.StringType,
			[]attr.Value{types.StringValue("us-east-1")},
		),
	})
	if diags.HasError() {
		t.Fatalf("building regions failed: %v", diags.Errors())
	}

	configured, diags := types.ObjectValue(ManualScopeModificationsAttributeTypes(), map[string]attr.Value{
		"accounts":      types.ObjectNull(ManualScopeModificationsAttributeTypes()["accounts"].(types.ObjectType).AttrTypes),
		"projects":      types.ObjectNull(ManualScopeModificationsAttributeTypes()["projects"].(types.ObjectType).AttrTypes),
		"subscriptions": types.ObjectNull(ManualScopeModificationsAttributeTypes()["subscriptions"].(types.ObjectType).AttrTypes),
		"regions":       regions,
	})
	if diags.HasError() {
		t.Fatalf("building scope_modifications failed: %v", diags.Errors())
	}

	model := CloudManualIntegrationInstanceModel{
		ManualDetails:       types.ObjectNull(ManualDetailsWriteAttributeTypes()),
		ScopeModifications:  configured,
		CustomResourcesTags: types.SetNull(ManualCustomResourcesTagType()),
	}

	diagnostics := diag.Diagnostics{}
	model.RefreshFromReadResponse(context.Background(), &diagnostics, cloudOnboardingTypes.InstanceEditFields{
		CloudProvider: "AWS",
		Scope:         "ACCOUNT",
		ScanMode:      "MANAGED",
	})
	if diagnostics.HasError() {
		t.Fatalf("refreshing failed: %v", diagnostics.Errors())
	}

	if model.ScopeModifications.IsNull() || model.ScopeModifications.IsUnknown() {
		t.Fatalf("a configured scope_modifications was discarded because the reply "+
			"omitted the object; the practitioner's own value must survive a reply "+
			"that says nothing about it, or every plan reports drift. Got %v",
			model.ScopeModifications)
	}
	if !model.ScopeModifications.Equal(configured) {
		t.Errorf("scope_modifications changed from the configured value to %v", model.ScopeModifications)
	}
}

// TestRefreshFromReadResponseIgnoresOnboardOnlyModeInTheReply proves a reply
// that reports onboard_only_mode does not disturb state.
//
// This is the shape of every real read: 24 of 24 captured successful
// get_edit_instance_details replies carry "onboard_only_mode": false inside
// scope_modifications, none of which asked for it. The provider no longer
// models the field, so the refresher must drop it silently. If it ever leaked
// into the object, the value would not match the schema's attribute types and
// every plan would fail.
func TestRefreshFromReadResponseIgnoresOnboardOnlyModeInTheReply(t *testing.T) {
	t.Parallel()

	model := CloudManualIntegrationInstanceModel{
		ManualDetails:       types.ObjectNull(ManualDetailsWriteAttributeTypes()),
		ScopeModifications:  types.ObjectNull(ManualScopeModificationsAttributeTypes()),
		CustomResourcesTags: types.SetNull(ManualCustomResourcesTagType()),
	}

	diagnostics := diag.Diagnostics{}
	model.RefreshFromReadResponse(context.Background(), &diagnostics, cloudOnboardingTypes.InstanceEditFields{
		CloudProvider: "AWS",
		Scope:         "ACCOUNT",
		ScanMode:      "MANAGED",
		ScopeModifications: &cloudOnboardingTypes.ScopeModificationsRead{
			Regions:         &cloudOnboardingTypes.ScopeModificationRegions{Enabled: false},
			OnboardOnlyMode: boolPtr(false),
		},
	})
	if diagnostics.HasError() {
		t.Fatalf("refreshing a reply that reports onboard_only_mode failed: %v", diagnostics.Errors())
	}

	if model.ScopeModifications.IsNull() || model.ScopeModifications.IsUnknown() {
		t.Fatalf("scope_modifications was discarded, got %v", model.ScopeModifications)
	}

	if _, found := model.ScopeModifications.Attributes()["onboard_only_mode"]; found {
		t.Errorf("the refreshed scope_modifications carries onboard_only_mode, which the " +
			"schema no longer declares; state would not match the schema and every plan " +
			"would fail")
	}

	if got, want := model.ScopeModifications.AttributeTypes(context.Background()),
		ManualScopeModificationsAttributeTypes(); len(got) != len(want) {
		t.Errorf("refreshed scope_modifications has %d members, want %d: %v", len(got), len(want), got)
	}
}

// TestRefreshFromReadResponseTracksAConfiguredOutpost proves an outpost the
// practitioner chose is refreshed, so moving the connector to a different
// outpost outside Terraform is reported as drift instead of staying invisible.
//
// scan_env_id is the read reply's name for the same value outpost_id is sent
// as: the identifier a connector's listing row reports as outpost_id appears
// verbatim as scan_env_id in that connector's edit-details reply.
func TestRefreshFromReadResponseTracksAConfiguredOutpost(t *testing.T) {
	t.Parallel()

	model := CloudManualIntegrationInstanceModel{
		ManualDetails:       types.ObjectNull(ManualDetailsWriteAttributeTypes()),
		OutpostID:           types.StringValue("749b0ae770164096b1300d3f9c38f5cf"),
		CustomResourcesTags: types.SetNull(ManualCustomResourcesTagType()),
	}

	diagnostics := diag.Diagnostics{}
	model.RefreshFromReadResponse(context.Background(), &diagnostics, cloudOnboardingTypes.InstanceEditFields{
		CloudProvider: "AWS",
		Scope:         "ACCOUNT",
		ScanMode:      "OUTPOST",
		ScanEnvID:     "7b44bf8f38f544d18ec427d523b51e25",
	})
	if diagnostics.HasError() {
		t.Fatalf("refreshing failed: %v", diagnostics.Errors())
	}

	if model.OutpostID.ValueString() != "7b44bf8f38f544d18ec427d523b51e25" {
		t.Errorf("outpost_id = %q, want the outpost the platform reports; the "+
			"connector was moved to a different outpost outside Terraform and "+
			"the refresh did not notice, so every plan reports \"No changes\"",
			model.OutpostID.ValueString())
	}
}

// TestRefreshFromReadResponseLeavesAnUnrequestedOutpostUnset is the dangerous
// direction, and the reason the refresh above is conditional.
//
// outpost_id is Optional and NOT Computed, so Terraform requires the applied
// value to equal the configuration exactly. The platform nonetheless reports an
// outpost for connectors that never asked for one: in the captured listings
// every MANAGED row carries a non-empty outpost identifier, the tenant's
// default. Adopting it for a configuration that left outpost_id unset would
// turn a null into a value and Terraform would reject the apply with "Provider
// produced inconsistent result after apply" -- and RefreshFromReadResponse runs
// after create and edit, not only during a read, so this would fire on the very
// first apply of a MANAGED connector.
func TestRefreshFromReadResponseLeavesAnUnrequestedOutpostUnset(t *testing.T) {
	t.Parallel()

	model := CloudManualIntegrationInstanceModel{
		ManualDetails:       types.ObjectNull(ManualDetailsWriteAttributeTypes()),
		OutpostID:           types.StringNull(),
		CustomResourcesTags: types.SetNull(ManualCustomResourcesTagType()),
	}

	diagnostics := diag.Diagnostics{}
	model.RefreshFromReadResponse(context.Background(), &diagnostics, cloudOnboardingTypes.InstanceEditFields{
		CloudProvider: "AWS",
		Scope:         "ACCOUNT",
		ScanMode:      "MANAGED",
		ScanEnvID:     "749b0ae770164096b1300d3f9c38f5cf",
	})
	if diagnostics.HasError() {
		t.Fatalf("refreshing failed: %v", diagnostics.Errors())
	}

	if model.OutpostID.IsNull() == false {
		t.Errorf("outpost_id = %q for a configuration that never set it; the "+
			"platform reports its default outpost for every MANAGED connector, "+
			"and recording it makes the applied value differ from the "+
			"configured one, which Terraform rejects outright",
			model.OutpostID.ValueString())
	}
}

// marshalled encodes a request and decodes it into a map, so assertions are
// made against the bytes the platform actually receives.
func marshalled(t *testing.T, request any) map[string]any {
	t.Helper()

	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("marshalling the request failed: %v", err)
	}

	payload := map[string]any{}
	if err := json.Unmarshal(encoded, &payload); err != nil {
		t.Fatalf("decoding the request failed: %v", err)
	}

	return payload
}
