// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package cloudonboarding

import (
	"context"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Manual onboarding supports AWS and Azure only. GCP is unsupported on the
// platform side, so the provider refuses it at plan time rather than letting a
// practitioner discover it from an API rejection at apply time.
//
// These tests pin that contract. They are deliberately written against the
// resource schema rather than a hand-built validator, so that re-adding "GCP"
// anywhere in the cloud_provider validator chain fails the build.

// cloudProviderValidators returns the validators guarding cloud_provider.
func cloudProviderValidators(t *testing.T) []validator.String {
	t.Helper()

	resp := manualInstanceSchema(t)

	attribute, ok := resp.Schema.Attributes["cloud_provider"]
	if !ok {
		t.Fatal("the schema has no cloud_provider attribute")
	}

	stringAttribute, ok := attribute.(schema.StringAttribute)
	if !ok {
		t.Fatalf("cloud_provider is %T, not a StringAttribute", attribute)
	}

	return stringAttribute.Validators
}

// validateCloudProvider runs the cloud_provider validator chain over a value
// and reports the diagnostics it produced.
func validateCloudProvider(t *testing.T, value string) validator.StringResponse {
	t.Helper()

	req := validator.StringRequest{
		ConfigValue: types.StringValue(value),
	}
	resp := validator.StringResponse{}

	for _, v := range cloudProviderValidators(t) {
		v.ValidateString(context.Background(), req, &resp)
	}

	return resp
}

// TestManualInstanceRejectsGCP proves a GCP connector is refused at plan time.
//
// This is the whole point of the change: manual onboarding is not supported for
// GCP on the platform, so a configuration naming it must never reach an apply.
func TestManualInstanceRejectsGCP(t *testing.T) {
	t.Parallel()

	resp := validateCloudProvider(t, "GCP")

	if !resp.Diagnostics.HasError() {
		t.Fatal("cloud_provider accepted \"GCP\", so a practitioner would only " +
			"discover manual GCP onboarding is unsupported when the apply fails")
	}
}

// TestManualInstanceGCPRejectionNamesTheProvider proves the refusal is
// actionable.
//
// A bare "value must be one of" message tells a practitioner what is allowed
// but not that GCP was deliberately withheld, which reads as a provider bug
// rather than an unsupported platform capability.
func TestManualInstanceGCPRejectionNamesTheProvider(t *testing.T) {
	t.Parallel()

	resp := validateCloudProvider(t, "GCP")

	if !resp.Diagnostics.HasError() {
		t.Fatal("cloud_provider accepted \"GCP\"")
	}

	var text strings.Builder
	for _, diagnostic := range resp.Diagnostics.Errors() {
		text.WriteString(diagnostic.Summary())
		text.WriteString(" ")
		text.WriteString(diagnostic.Detail())
		text.WriteString(" ")
	}

	message := text.String()
	if !strings.Contains(message, "GCP") {
		t.Errorf("the rejection never mentions GCP, so it does not explain what "+
			"was refused: %q", message)
	}
	if !strings.Contains(strings.ToLower(message), "not supported") &&
		!strings.Contains(strings.ToLower(message), "unsupported") {
		t.Errorf("the rejection does not say GCP is unsupported, so it reads as "+
			"a provider defect rather than a platform limitation: %q", message)
	}
}

// TestManualInstanceAcceptsSupportedProviders proves the gate is not simply
// refusing everything.
//
// Without this control the GCP tests above would pass against a validator that
// rejects every value, which would be a total outage rather than a fix.
func TestManualInstanceAcceptsSupportedProviders(t *testing.T) {
	t.Parallel()

	for _, provider := range []string{"AWS", "AZURE"} {
		resp := validateCloudProvider(t, provider)

		if resp.Diagnostics.HasError() {
			t.Errorf("cloud_provider rejected %q, which manual onboarding supports: %v",
				provider, resp.Diagnostics.Errors())
		}
	}
}

// TestManualInstanceDetailsOfferNoGCPMembers proves the GCP-only credential
// members are gone from both the write and the read object.
//
// Leaving them in place would advertise, in the generated documentation, a set
// of fields that no accepted cloud_provider value can ever use.
func TestManualInstanceDetailsOfferNoGCPMembers(t *testing.T) {
	t.Parallel()

	// account_id and organization_id are deliberately absent from this list:
	// AWS uses them too, so they stay.
	gcpOnly := []string{
		"service_account_email",
		"outpost_scanner_service_account_email",
		"audit_service_account_email",
		"audit_pubsub_subscription_id",
		"account_group",
	}

	for _, object := range []string{"manual_details", "reported_manual_details"} {
		names := nestedAttributeNames(t, object)

		for _, name := range gcpOnly {
			if names[name] {
				t.Errorf("%s still offers the GCP-only member %s, which no "+
					"supported cloud_provider can use", object, name)
			}
		}
	}
}
