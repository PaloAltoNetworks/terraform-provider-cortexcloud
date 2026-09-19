// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package cloudonboarding

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/cloudonboarding"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
)

// ----------------------------------------------------------------------------
// A connector this resource does not own must not be adopted silently
//
// Both connector resources take a bare connector identifier on import and
// neither inspects what provisioned the record, so nothing stops a practitioner
// importing a template-provisioned connector into this resource. The direction
// that matters is destructive: this resource's Delete really does call
// DeleteIntegrationInstances, so a subsequent "terraform destroy" removes a
// connector that a template -- possibly held in another state file -- still
// believes it owns. The template resource will not notice, because its own
// Delete is state-only.
//
// The discriminator is already being fetched and thrown away. Every read reply
// carries provisioning_method, and the values are not guessed at here: in the
// captured live listings this resource's own connectors report "MANUAL" (578
// rows), while template-provisioned connectors report "CF" for AWS
// CloudFormation, "ARM" for Azure and "TF" for Terraform.
//
// The guard therefore rejects anything that is present and not MANUAL rather
// than matching a list of known automated spellings. No enum for this field is
// published -- the API specification carries only an example -- so an allowlist
// would silently adopt any value the platform adds later, which is the failure
// this exists to prevent.
// ----------------------------------------------------------------------------

// readConnectorProvisionedBy drives Read against a connector the listing holds
// and whose read reply reports the given provisioning_method. An empty string
// omits the field entirely, which is what the platform does for the PENDING
// template rows.
func readConnectorProvisionedBy(t *testing.T, provisioningMethod string) *resource.ReadResponse {
	t.Helper()

	ctx := context.Background()
	census := listingCensus{present: []string{testManualInstanceID}}
	rejected := false

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, cloudonboarding.GetEditInstanceDetailsEndpoint):
			fields := map[string]any{
				"instance_name":  "manual-connector",
				"cloud_provider": "AWS",
				"scope":          "ACCOUNT",
				"scan_mode":      "MANAGED",
				"manual_details": map[string]any{
					"account_id":   "782785052462",
					"account_name": "an-account",
				},
			}
			if provisioningMethod != "" {
				fields["provisioning_method"] = provisioningMethod
			}

			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"reply": map[string]any{"fields": fields},
			})
		case strings.HasSuffix(r.URL.Path, cloudonboarding.ListIntegrationInstancesEndpoint):
			census.serveListing(t, w, r, &rejected)
		default:
			t.Errorf("unexpected request path: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)

	instanceResource := &CloudManualIntegrationInstanceResource{client: manualTestClient(t, server)}

	resourceSchema, attributeTypes := manualResourceSchema(t)

	state := tfsdk.State{Schema: resourceSchema}
	stateModel := manualTestModel(t, attributeTypes, true)
	if diags := state.Set(ctx, &stateModel); diags.HasError() {
		t.Fatalf("failed to build state: %v", diags.Errors())
	}

	req := resource.ReadRequest{State: state}
	resp := &resource.ReadResponse{State: tfsdk.State{Schema: resourceSchema, Raw: state.Raw}}

	instanceResource.Read(ctx, req, resp)

	return resp
}

// TestManualInstanceReadRefusesAConnectorItDidNotProvision covers each
// provisioning method observed in the captured live listings.
func TestManualInstanceReadRefusesAConnectorItDidNotProvision(t *testing.T) {
	for _, provisioningMethod := range []string{"CF", "ARM", "TF"} {
		t.Run(provisioningMethod, func(t *testing.T) {
			resp := readConnectorProvisionedBy(t, provisioningMethod)

			if !resp.Diagnostics.HasError() {
				t.Fatalf("Read accepted a connector provisioned by %q. The "+
					"practitioner now holds a resource whose destroy really "+
					"deletes a connector another resource provisioned, and "+
					"nothing told them.", provisioningMethod)
			}

			// The diagnostic has to name the value and the resource to use
			// instead, or the practitioner cannot act on it.
			var summary, detail string
			for _, diagnostic := range resp.Diagnostics.Errors() {
				summary += diagnostic.Summary()
				detail += diagnostic.Detail()
			}
			if !strings.Contains(detail, provisioningMethod) {
				t.Errorf("the error does not name the actual provisioning method %q: %s",
					provisioningMethod, detail)
			}
			if !strings.Contains(detail, "cortexcloud_cloud_integration_instance") {
				t.Errorf("the error does not point at the resource that should "+
					"manage this connector: %s", detail)
			}
		})
	}
}

// TestManualInstanceReadAcceptsItsOwnConnectors is the positive control.
//
// Without it a guard that refused everything would satisfy the test above while
// breaking every legitimate refresh. MANUAL is what this resource's own
// connectors report; an absent field is what the platform sends for the PENDING
// template rows, and refusing that would break imports for a shape the platform
// genuinely produces.
func TestManualInstanceReadAcceptsItsOwnConnectors(t *testing.T) {
	for name, provisioningMethod := range map[string]string{
		"reported as MANUAL":     "MANUAL",
		"omitted from the reply": "",
	} {
		t.Run(name, func(t *testing.T) {
			resp := readConnectorProvisionedBy(t, provisioningMethod)

			if resp.Diagnostics.HasError() {
				t.Fatalf("Read refused a connector this resource does manage: %v",
					resp.Diagnostics.Errors())
			}
			if resp.State.Raw.IsNull() {
				t.Fatal("Read dropped a connector this resource does manage")
			}
		})
	}
}
