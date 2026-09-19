// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package cloudonboarding

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/cloudonboarding"

	models "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/cloud_onboarding"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// ----------------------------------------------------------------------------
// A listing fake that behaves like the real endpoint
//
// The delete tests elsewhere in this package answer the verification listing
// from a flag, without reading the request. That made a broken filter
// invisible: whatever the provider asked for, the fake replied with exactly
// what the test intended, so a request the platform refuses outright looked
// indistinguishable from one it honours.
//
// The listing this file serves reads the request instead, and enforces the two
// rules the live endpoint was measured to apply:
//
//  1. "filter" must be a boolean operator at its top level. A bare comparison
//     is answered
//
//     500 _parse_filters - Type mismatch, expected:
//     dict_values(['AND', 'NOT', 'OR']), Got: SEARCH_FIELD
//
//     for a connector that exists and for one that does not alike.
//
//  2. rows key the connector identifier as "instance_id", not "id".
//
// The point of the exercise is that the fake never decides on its own what to
// return. It holds a census of connectors, evaluates the predicate the provider
// actually sent, and answers from that. A request that cannot express "this one
// connector" therefore cannot accidentally produce the right answer.
// ----------------------------------------------------------------------------

// listingCensus is the set of connectors the fake platform is holding.
type listingCensus struct {
	present []string
}

// searchPredicate is one SEARCH_FIELD/SEARCH_TYPE/SEARCH_VALUE comparison.
type searchPredicate struct {
	Field string `json:"SEARCH_FIELD"`
	Type  string `json:"SEARCH_TYPE"`
	Value string `json:"SEARCH_VALUE"`
	And   []struct {
		Field string `json:"SEARCH_FIELD"`
		Type  string `json:"SEARCH_TYPE"`
		Value string `json:"SEARCH_VALUE"`
	} `json:"AND"`
}

// parseFiltersRejection is the reply the live endpoint gives to a filter whose
// top level is not a boolean operator. Reproduced verbatim so a failing test
// shows the practitioner the message they would really see.
const parseFiltersRejection = `{"reply":{"err_code":500,` +
	`"err_msg":"An error occurred while processing API call",` +
	`"err_extra":"_parse_filters - Type mismatch, expected: ` +
	`dict_values(['AND', 'NOT', 'OR']), Got: SEARCH_FIELD"}}`

// serveListing answers a get_instances request the way the platform does.
//
// rejected reports whether the request was refused for having a bare
// comparison at the top of "filter", which is the condition under test.
func (c listingCensus) serveListing(t *testing.T, w http.ResponseWriter, r *http.Request, rejected *bool) {
	t.Helper()

	body, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatalf("could not read the listing request: %v", err)
	}

	var envelope struct {
		RequestData struct {
			FilterData struct {
				Filter json.RawMessage `json:"filter"`
			} `json:"filter_data"`
		} `json:"request_data"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		t.Fatalf("the listing request was not valid JSON: %v\nbody: %s", err, body)
	}

	var predicate searchPredicate
	if len(envelope.RequestData.FilterData.Filter) > 0 {
		if err := json.Unmarshal(envelope.RequestData.FilterData.Filter, &predicate); err != nil {
			t.Fatalf("the listing filter was not an object: %v\nbody: %s", err, body)
		}
	}

	// Rule 1: a comparison at the top level is refused outright.
	if predicate.Field != "" {
		*rejected = true
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(parseFiltersRejection))
		return
	}

	// Evaluate the AND operands the provider sent. No operands means no
	// narrowing, which is how the platform behaves.
	matches := c.present
	for _, operand := range predicate.And {
		var kept []string
		for _, id := range matches {
			if operand.Field == "ID" && operand.Type == "EQ" && id == operand.Value {
				kept = append(kept, id)
			}
		}
		matches = kept
	}

	rows := make([]map[string]any, 0, len(matches))
	for _, id := range matches {
		rows = append(rows, map[string]any{
			"instance_id":         id,
			"cloud_provider":      "AWS",
			"instance_name":       "manual-connector",
			"scope":               "ACCOUNT",
			"scan_mode":           "MANAGED",
			"status":              "CONNECTED",
			"provisioning_method": "MANUAL",
		})
	}

	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"reply": map[string]any{
			"DATA":        rows,
			"TOTAL_COUNT": len(c.present),
		},
	})
}

// deleteAgainstCensus drives Delete against a fake platform holding census,
// where the delete endpoint answers 200 without removing anything.
//
// That no-op delete is the measured behaviour on a connector the platform will
// not remove, and it is the case the verification listing exists to catch. If
// verification is not actually working, Delete reports success here and
// Terraform drops a connector that is still running.
func deleteAgainstCensus(t *testing.T, census listingCensus) (*resource.DeleteResponse, bool) {
	t.Helper()

	ctx := context.Background()
	rejected := false

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, cloudonboarding.DeleteIntegrationInstancesEndpoint):
			// 200, and the connector stays exactly where it is.
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"reply":null}`))
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

	req := resource.DeleteRequest{State: state}
	resp := &resource.DeleteResponse{State: tfsdk.State{Schema: resourceSchema, Raw: state.Raw}}

	instanceResource.Delete(ctx, req, resp)

	return resp, rejected
}

// TestManualInstanceDeleteVerificationFilterIsAcceptedByThePlatform is the gate
// that the shipped code failed.
//
// A verification request the platform refuses is not a verification. The
// refusal is identical whether the connector survived or not, so the listing
// stops carrying any information about the outcome and the check that guards
// against dropping a live connector becomes decorative.
//
// This asserts on the request rather than the result, because the result was
// never the problem: the old request was refused for every connector, and a
// test that only ever looked at the answer could not see it.
func TestManualInstanceDeleteVerificationFilterIsAcceptedByThePlatform(t *testing.T) {
	_, rejected := deleteAgainstCensus(t, listingCensus{present: []string{testManualInstanceID}})

	if rejected {
		t.Fatal("the verification listing was refused with _parse_filters - Type mismatch, " +
			"expected: dict_values(['AND', 'NOT', 'OR']), Got: SEARCH_FIELD: the filter must " +
			"put a boolean operator at the top level, and until it does the listing cannot " +
			"tell a surviving connector from a removed one")
	}
}

// TestManualInstanceDeleteVerificationFindsAConnectorThatExists is the positive
// control.
//
// Everything else on this path checks that something is absent, and a check
// that can only ever observe absence proves nothing: a request that always
// comes back empty passes it too. So this one requires the listing to FIND a
// connector that is really there, and Delete to refuse on that basis.
func TestManualInstanceDeleteVerificationFindsAConnectorThatExists(t *testing.T) {
	resp, rejected := deleteAgainstCensus(t, listingCensus{present: []string{testManualInstanceID}})

	if rejected {
		t.Fatal("the platform refused the verification listing, so this control could not run")
	}
	if !resp.Diagnostics.HasError() {
		t.Fatal("delete reported success for a connector the platform still lists: the " +
			"verification found nothing even though the connector exists, so Terraform " +
			"would drop a live connector from state")
	}
	if !strings.Contains(resp.Diagnostics.Errors()[0].Detail(), "still present") {
		t.Errorf("the diagnostic must say the connector is still present; detail=%q",
			resp.Diagnostics.Errors()[0].Detail())
	}
	if resp.State.Raw.IsNull() {
		t.Error("state was removed for a connector that is still on the platform")
	}
}

// TestManualInstanceDeleteVerificationIgnoresOtherConnectors is the other half
// of the control.
//
// A listing that returned every connector regardless of the filter would pass
// the test above by accident. Here the connector under management is gone and
// two unrelated ones remain: the listing must narrow to the identifier asked
// for, and Delete must succeed.
func TestManualInstanceDeleteVerificationIgnoresOtherConnectors(t *testing.T) {
	resp, rejected := deleteAgainstCensus(t, listingCensus{present: []string{
		"11111111111111111111111111111111",
		"22222222222222222222222222222222",
	}})

	if rejected {
		t.Fatal("the platform refused the verification listing, so this control could not run")
	}
	if resp.Diagnostics.HasError() {
		t.Fatalf("delete refused although the connector is absent from the listing and only "+
			"unrelated connectors remain: %v", resp.Diagnostics.Errors())
	}
}

// TestManualInstanceDeleteVerificationRequestTargetsTheConnector pins the two
// properties of the request the platform was measured to require.
//
// It reads the marshalled request rather than a description of it, because the
// original defect was invisible in every description: the code plainly said it
// filtered on the identifier, and it did, in a shape the platform rejects.
func TestManualInstanceDeleteVerificationRequestTargetsTheConnector(t *testing.T) {
	t.Parallel()

	model := &models.CloudManualIntegrationInstanceModel{
		ID: types.StringValue(testManualInstanceID),
	}
	var diags diag.Diagnostics

	encoded, err := json.Marshal(model.ToDeleteVerificationRequest(context.Background(), &diags))
	if err != nil {
		t.Fatalf("the verification request could not be marshalled: %v", err)
	}

	var envelope struct {
		FilterData struct {
			Filter map[string]json.RawMessage `json:"filter"`
		} `json:"filter_data"`
	}
	if err := json.Unmarshal(encoded, &envelope); err != nil {
		t.Fatalf("the verification request was not the expected envelope: %v\nbody: %s", err, encoded)
	}

	if _, ok := envelope.FilterData.Filter["SEARCH_FIELD"]; ok {
		t.Errorf("the filter puts SEARCH_FIELD at its top level; the platform answers that with "+
			"_parse_filters - Type mismatch, expected: dict_values(['AND', 'NOT', 'OR']), "+
			"Got: SEARCH_FIELD, and the listing then cannot confirm a delete. body=%s", encoded)
	}
	if _, ok := envelope.FilterData.Filter["AND"]; !ok {
		t.Errorf("the filter has no AND at its top level; the platform accepts only AND, OR or "+
			"NOT there. body=%s", encoded)
	}
	if !strings.Contains(string(encoded), testManualInstanceID) {
		t.Errorf("the verification request does not mention the connector it is meant to look "+
			"for; it would report on some other set of connectors. body=%s", encoded)
	}
}
