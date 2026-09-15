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

	models "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/cloud_onboarding"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
)

// ----------------------------------------------------------------------------
// Read must decide existence from the listing, not from the read endpoint
//
// get_edit_instance_details keeps answering 200, with the connector's full
// details, after the connector has been deleted. Measured against a live
// tenant: a connector was deleted, the listing immediately stopped returning it
// (FILTER_COUNT 0, with a positive control on a live connector returning 1 at
// the same moment), and the read endpoint went on serving its complete record
// for at least the following two minutes over three samples. An identifier that
// never existed is a different case -- that is refused with
//
//	422 "connector id <id> doesn't exist"
//
// which is the only signal isConnectorGoneError can act on, and a deleted
// connector never produces it.
//
// The consequence is the one Terraform is least able to recover from: after an
// out-of-band delete, "terraform plan" reports "No changes", and so does
// "terraform apply -refresh-only". The resource stays in state, pointing at
// nothing, and Terraform never proposes to rebuild it. The infrastructure the
// configuration describes is gone and Terraform insists everything matches.
//
// So existence has to be established the way Delete already establishes it --
// by asking the listing, which does track deletion. The reply from the read
// endpoint is still what populates state; it is only the question "does this
// connector exist" that moves.
// ----------------------------------------------------------------------------

// readAgainstCensus drives Read against a fake platform where the read endpoint
// answers 200 with a full record regardless, and the listing holds census.
//
// This is the shape the live platform was measured to have. A Read that trusts
// the read endpoint cannot distinguish a live connector from a deleted one
// here, which is exactly the point.
func readAgainstCensus(t *testing.T, census listingCensus) *resource.ReadResponse {
	t.Helper()

	ctx := context.Background()
	rejected := false

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, cloudonboarding.GetEditInstanceDetailsEndpoint):
			// 200 with a complete record, whether or not the connector is
			// still there. This is the measured live behaviour.
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"reply": map[string]any{
					"fields": map[string]any{
						"instance_name":  "manual-connector",
						"cloud_provider": "AWS",
						"scope":          "ACCOUNT",
						"scan_mode":      "MANAGED",
						"manual_details": map[string]any{
							"account_id":   "782785052462",
							"account_name": "an-account",
						},
					},
				},
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

// TestManualInstanceReadRemovesAConnectorDeletedOutOfBand is the gate the
// shipped code failed against a live tenant.
//
// The connector is absent from the listing but the read endpoint still serves
// it. Read must remove the resource from state so the next plan offers to
// recreate it. Leaving it in state is the worst available outcome: Terraform
// reports that everything matches while the infrastructure does not exist.
func TestManualInstanceReadRemovesAConnectorDeletedOutOfBand(t *testing.T) {
	resp := readAgainstCensus(t, listingCensus{present: []string{}})

	if resp.Diagnostics.HasError() {
		t.Fatalf("Read reported an error; it should quietly drop the resource: %v",
			resp.Diagnostics.Errors())
	}

	if !resp.State.Raw.IsNull() {
		t.Error("Read left the connector in state although the listing no longer " +
			"holds it. The next plan will report \"No changes\" for infrastructure " +
			"that does not exist, and Terraform will never offer to recreate it.")
	}
}

// TestManualInstanceReadKeepsAConnectorThatStillExists is the positive control.
//
// Without it, a Read that removed the resource unconditionally would pass the
// test above -- and would destroy the state of every healthy connector on every
// refresh. The two tests are only meaningful together: one requires absence to
// be detected, the other requires presence to be respected.
func TestManualInstanceReadKeepsAConnectorThatStillExists(t *testing.T) {
	resp := readAgainstCensus(t, listingCensus{present: []string{testManualInstanceID}})

	if resp.Diagnostics.HasError() {
		t.Fatalf("Read failed for a connector that exists: %v", resp.Diagnostics.Errors())
	}

	if resp.State.Raw.IsNull() {
		t.Fatal("Read removed a connector the listing still holds. A refresh would " +
			"discard the state of live infrastructure.")
	}

	// The existence check must not replace the read as the source of state: the
	// listing carries far less than the read reply does, so a Read that
	// populated state from it would quietly lose most of the record.
	var refreshed models.CloudManualIntegrationInstanceModel
	if diags := resp.State.Get(context.Background(), &refreshed); diags.HasError() {
		t.Fatalf("could not read back the refreshed state: %v", diags.Errors())
	}
	if refreshed.InstanceName.ValueString() != "manual-connector" {
		t.Errorf("instance_name = %q, want the value the READ endpoint reported. "+
			"The existence check has displaced the read reply as the source of state.",
			refreshed.InstanceName.ValueString())
	}
}

// TestManualInstanceReadKeepsStateWhenTheListingFails proves an existence check
// that cannot be completed is not read as absence.
//
// This is the failure direction that destroys things. If a transport error, an
// authorization problem or a server fault were treated as "the connector is
// gone", a transient outage would evict live infrastructure from state across
// every resource at once. The listing here is refused the way the real endpoint
// refuses a malformed filter.
func TestManualInstanceReadKeepsStateWhenTheListingFails(t *testing.T) {
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, cloudonboarding.GetEditInstanceDetailsEndpoint):
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"reply": map[string]any{
					"fields": map[string]any{
						"instance_name":  "manual-connector",
						"cloud_provider": "AWS",
						"scope":          "ACCOUNT",
						"scan_mode":      "MANAGED",
					},
				},
			})
		case strings.HasSuffix(r.URL.Path, cloudonboarding.ListIntegrationInstancesEndpoint):
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(parseFiltersRejection))
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

	if resp.State.Raw.IsNull() {
		t.Error("Read removed the connector from state because the existence check " +
			"could not be completed. A failed check is not evidence of absence, and " +
			"treating it as such would evict live infrastructure during an outage.")
	}
	if !resp.Diagnostics.HasError() {
		t.Error("Read kept the resource but said nothing. A refresh that could not " +
			"confirm the connector exists must say so rather than appear to succeed.")
	}
}
