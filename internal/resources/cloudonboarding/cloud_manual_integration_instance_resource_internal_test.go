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

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

// ----------------------------------------------------------------------------
// Fixtures
//
// The read reply below is modelled on a captured get_edit_instance_details
// response. Two of its properties are load-bearing for the tests and are not
// incidental:
//
//   - manual_details reports client_id, which no write endpoint accepts, and
//     omits cloudtrail_role, sqs_url and subscription_id, which the write
//     endpoints do accept. The read is therefore not a write payload.
//   - the reply carries no connector identifier at all, so a caller cannot
//     verify that the payload belongs to the connector it asked about.
// ----------------------------------------------------------------------------

const (
	testManualInstanceID = "0f7da3939a4d4b0da49ce9d09bfb5d32"

	// The values the practitioner configured. The read reply deliberately
	// reports different ones, so a test can tell configuration apart from
	// refreshed data.
	testConfiguredRoleARN        = "arn:aws:iam::782785052462:role/configured-role"
	testConfiguredCloudTrailRole = "arn:aws:iam::782785052462:role/configured-cloudtrail"
	testConfiguredSQSURL         = "https://sqs.us-east-1.amazonaws.com/782785052462/configured-queue"

	// What the platform reports back. Different from the configured role so
	// that a read echoing into manual_details is detectable.
	testReportedRoleARN = "arn:aws:iam::782785052462:role/reported-by-platform"
)

// manualReadReply is a get_edit_instance_details 200 body.
func manualReadReply(t *testing.T) []byte {
	t.Helper()

	return []byte(`{
	  "reply": {
	    "fields": {
	      "instance_name": "manual-connector",
	      "cloud_provider": "AWS",
	      "scope": "ACCOUNT",
	      "scan_mode": "MANAGED",
	      "provisioning_method": "MANUAL",
	      "cloud_partition": "aws",
	      "upgrade_available": false,
	      "custom_resources_tags": [{"key": "managed_by", "value": "terraform"}],
	      "manual_details": {
	        "account_id": "782785052462",
	        "role_arn": "` + testReportedRoleARN + `",
	        "external_id": "reported-external-id",
	        "client_id": "reported-client-id"
	      },
	      "additional_capabilities": {
	        "automation": false,
	        "xsiam_analytics": false,
	        "registry_scanning": false,
	        "kubernetes_security": false,
	        "serverless_scanning": false,
	        "agentless_disk_scanning": false,
	        "data_security_posture_management": false
	      },
	      "collection_configuration": {
	        "audit_logs": {
	          "enabled": true,
	          "data_events": false,
	          "collection_method": "CUSTOM",
	          "is_control_tower_byob": false
	        }
	      },
	      "scope_modifications": {"regions": {"enabled": false}}
	    }
	  }
	}`)
}

// manualTestClient builds an SDK client pointed at a test server.
func manualTestClient(t *testing.T, server *httptest.Server) *cloudonboarding.Client {
	t.Helper()

	client, err := cloudonboarding.NewClient(
		cloudonboarding.WithCortexAPIURL(server.URL),
		cloudonboarding.WithCortexAPIKey("test-key"),
		cloudonboarding.WithCortexAPIKeyID(1),
		cloudonboarding.WithTransport(server.Client().Transport.(*http.Transport)),
	)
	if err != nil {
		t.Fatalf("failed to build client: %v", err)
	}

	return client
}

// manualResourceSchema returns the resource schema and its attribute types.
func manualResourceSchema(t *testing.T) (schema.Schema, map[string]attr.Type) {
	t.Helper()

	var schemaResp resource.SchemaResponse
	NewCloudManualIntegrationInstanceResource().Schema(context.Background(), resource.SchemaRequest{}, &schemaResp)
	if schemaResp.Diagnostics.HasError() {
		t.Fatalf("unexpected schema diagnostics: %v", schemaResp.Diagnostics.Errors())
	}

	resourceSchema := schemaResp.Schema

	return resourceSchema, resourceSchema.Type().(types.ObjectType).AttrTypes
}

// manualTestModel builds a model holding a complete, configured AWS connector.
func manualTestModel(t *testing.T, attributeTypes map[string]attr.Type, withID bool) models.CloudManualIntegrationInstanceModel {
	t.Helper()

	writeDetails := map[string]attr.Value{}
	for name := range models.ManualDetailsWriteAttributeTypes() {
		writeDetails[name] = types.StringNull()
	}
	writeDetails["account_id"] = types.StringValue("782785052462")
	writeDetails["role_arn"] = types.StringValue(testConfiguredRoleARN)
	writeDetails["external_id"] = types.StringValue("configured-external-id")
	// The audit-log source fields live here, not in audit_logs: the platform
	// answers "extra_forbidden" when they appear in that object.
	writeDetails["cloudtrail_role"] = types.StringValue(testConfiguredCloudTrailRole)
	writeDetails["sqs_url"] = types.StringValue(testConfiguredSQSURL)

	manualDetails, diags := types.ObjectValue(models.ManualDetailsWriteAttributeTypes(), writeDetails)
	if diags.HasError() {
		t.Fatalf("failed to build manual_details: %v", diags.Errors())
	}

	auditLogs, diags := types.ObjectValue(models.ManualAuditLogsAttributeTypes(), map[string]attr.Value{
		"enabled":               types.BoolValue(true),
		"data_events":           types.BoolValue(false),
		"collection_method":     types.StringValue("CUSTOM"),
		"is_control_tower_byob": types.BoolValue(false),
	})
	if diags.HasError() {
		t.Fatalf("failed to build audit_logs: %v", diags.Errors())
	}

	collectionConfiguration, diags := types.ObjectValue(models.ManualCollectionConfigurationAttributeTypes(), map[string]attr.Value{
		"audit_logs": auditLogs,
	})
	if diags.HasError() {
		t.Fatalf("failed to build collection_configuration: %v", diags.Errors())
	}

	tagType := models.ManualCustomResourcesTagType().(types.ObjectType)
	tag, diags := types.ObjectValue(tagType.AttrTypes, map[string]attr.Value{
		"key":   types.StringValue("managed_by"),
		"value": types.StringValue("terraform"),
	})
	if diags.HasError() {
		t.Fatalf("failed to build a custom resources tag: %v", diags.Errors())
	}

	tags, diags := types.SetValue(tagType, []attr.Value{tag})
	if diags.HasError() {
		t.Fatalf("failed to build custom_resources_tags: %v", diags.Errors())
	}

	id := types.StringNull()
	if withID {
		id = types.StringValue(testManualInstanceID)
	}

	return models.CloudManualIntegrationInstanceModel{
		ID:                      id,
		CloudProvider:           types.StringValue("AWS"),
		Scope:                   types.StringValue("ACCOUNT"),
		ScanMode:                types.StringValue("MANAGED"),
		OutpostID:               types.StringNull(),
		InstanceName:            types.StringValue("manual-connector"),
		CloudPartition:          types.StringValue("aws"),
		ManualDetails:           manualDetails,
		ReportedManualDetails:   types.ObjectNull(models.ManualDetailsReadAttributeTypes()),
		AdditionalCapabilities:  types.ObjectNull(models.ManualAdditionalCapabilitiesAttributeTypes()),
		CollectionConfiguration: collectionConfiguration,
		ScopeModifications:      types.ObjectNull(models.ManualScopeModificationsAttributeTypes()),
		CustomResourcesTags:     tags,
	}
}

// ----------------------------------------------------------------------------
// Create
// ----------------------------------------------------------------------------

// TestManualInstanceCreateSendsConfiguredValuesAndRecordsID verifies the create
// payload and that the identifier the platform returns lands in state. Without
// the identifier Terraform has no handle on the connector it just created, and
// every later operation targets nothing.
func TestManualInstanceCreateSendsConfiguredValuesAndRecordsID(t *testing.T) {
	ctx := context.Background()

	var createCalls int
	var sentBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The create is followed by a read-back, because the create reply
		// carries only the identifier and Terraform requires every Computed
		// attribute to be known once the apply returns.
		if strings.HasSuffix(r.URL.Path, cloudonboarding.GetEditInstanceDetailsEndpoint) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(manualReadReply(t))
			return
		}
		if !strings.HasSuffix(r.URL.Path, cloudonboarding.CreateManualInstanceEndpoint) {
			t.Errorf("unexpected request path: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		createCalls++

		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("failed to read request body: %v", err)
		}
		if err := json.Unmarshal(raw, &sentBody); err != nil {
			t.Errorf("failed to decode request body: %v", err)
		}

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"reply":{"id":"` + testManualInstanceID + `"}}`))
	}))
	defer server.Close()

	instanceResource := &CloudManualIntegrationInstanceResource{client: manualTestClient(t, server)}

	resourceSchema, attributeTypes := manualResourceSchema(t)

	plan := tfsdk.Plan{Schema: resourceSchema}
	planModel := manualTestModel(t, attributeTypes, false)
	if diags := plan.Set(ctx, &planModel); diags.HasError() {
		t.Fatalf("failed to build plan: %v", diags.Errors())
	}

	req := resource.CreateRequest{Plan: plan}
	resp := &resource.CreateResponse{State: tfsdk.State{Schema: resourceSchema}}

	instanceResource.Create(ctx, req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected create diagnostics: %v", resp.Diagnostics.Errors())
	}
	if createCalls != 1 {
		t.Fatalf("create_instance calls = %d, want 1", createCalls)
	}

	requestData, ok := sentBody["request_data"].(map[string]any)
	if !ok {
		t.Fatalf("request body has no request_data object: %v", sentBody)
	}

	for field, want := range map[string]string{
		"cloud_provider": "AWS",
		"scope":          "ACCOUNT",
		"scan_mode":      "MANAGED",
		"instance_name":  "manual-connector",
	} {
		if got, _ := requestData[field].(string); got != want {
			t.Errorf("create payload %s = %q, want %q", field, got, want)
		}
	}

	manualDetails, ok := requestData["manual_details"].(map[string]any)
	if !ok {
		t.Fatalf("create payload has no manual_details object: %v", requestData)
	}
	if got, _ := manualDetails["role_arn"].(string); got != testConfiguredRoleARN {
		t.Errorf("create payload manual_details.role_arn = %q, want the configured value %q", got, testConfiguredRoleARN)
	}

	// client_id is reported by the platform and refused on write. Sending it
	// makes every create fail, so it must never reach the wire.
	if _, present := manualDetails["client_id"]; present {
		t.Error("create payload manual_details contains client_id, which the platform refuses on write")
	}

	var persisted models.CloudManualIntegrationInstanceModel
	if diags := resp.State.Get(ctx, &persisted); diags.HasError() {
		t.Fatalf("failed to read persisted state: %v", diags.Errors())
	}
	if persisted.ID.ValueString() != testManualInstanceID {
		t.Errorf("persisted id = %q, want %q: without it Terraform cannot address the connector it created",
			persisted.ID.ValueString(), testManualInstanceID)
	}
}

// TestManualInstanceCreateFailureReportsTheRejection verifies that a rejected
// create surfaces the platform's own message and points at the feature flag.
//
// The flag is the one cause a practitioner cannot see in their configuration:
// without it every create fails and nothing in the HCL explains why.
func TestManualInstanceCreateFailureReportsTheRejection(t *testing.T) {
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(`{"reply":{"err_code":422,"err_msg":"Validation failed","err_extra":"Invalid connector details"}}`))
	}))
	defer server.Close()

	instanceResource := &CloudManualIntegrationInstanceResource{client: manualTestClient(t, server)}

	resourceSchema, attributeTypes := manualResourceSchema(t)

	plan := tfsdk.Plan{Schema: resourceSchema}
	planModel := manualTestModel(t, attributeTypes, false)
	if diags := plan.Set(ctx, &planModel); diags.HasError() {
		t.Fatalf("failed to build plan: %v", diags.Errors())
	}

	req := resource.CreateRequest{Plan: plan}
	resp := &resource.CreateResponse{State: tfsdk.State{Schema: resourceSchema}}

	instanceResource.Create(ctx, req, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("expected an error diagnostic for the rejected create")
	}

	detail := resp.Diagnostics.Errors()[0].Detail()
	// The old warning about a leftover pending connector is gone: the platform
	// no longer leaves one.
	if strings.Contains(detail, "pending") {
		t.Errorf("diagnostic still warns about a leftover pending connector, which the "+
			"platform no longer creates; detail=%q", detail)
	}
	if !strings.Contains(detail, "feature flag") {
		t.Errorf("diagnostic must point at the feature flag, which is the cause a "+
			"practitioner cannot see in their own configuration; detail=%q", detail)
	}
	if !strings.Contains(detail, "Validation failed") && !strings.Contains(detail, "Invalid connector details") {
		t.Errorf("diagnostic must surface the platform's own message; detail=%q", detail)
	}
}

// ----------------------------------------------------------------------------
// Read
// ----------------------------------------------------------------------------

// readManualInstance drives Read against a server and returns the response.
func readManualInstance(t *testing.T, handler http.HandlerFunc) (*resource.ReadResponse, schema.Schema) {
	t.Helper()

	ctx := context.Background()

	server := httptest.NewServer(handler)
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

	return resp, resourceSchema
}

// withConnectorListed wraps a read-endpoint handler so the listing also answers
// that the connector is present.
//
// Read establishes existence from the listing, so a fake that serves only the
// read endpoint makes every Read fail for want of an existence check rather
// than for the reason the test is about. Tests that care about what Read does
// with a particular read reply use this; tests about existence itself live in
// cloud_manual_integration_instance_read_existence_test.go and drive the
// listing directly.
func withConnectorListed(t *testing.T, readHandler http.HandlerFunc) http.HandlerFunc {
	t.Helper()

	census := listingCensus{present: []string{testManualInstanceID}}
	rejected := false

	return func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, cloudonboarding.ListIntegrationInstancesEndpoint) {
			census.serveListing(t, w, r, &rejected)
			return
		}
		readHandler(w, r)
	}
}

// manualReadHandler serves a single 200 read reply, and a listing that holds
// the connector.
//
// Read now establishes existence from the listing rather than from the read
// endpoint, because the read endpoint keeps serving a deleted connector's full
// record while the listing drops it immediately. These tests are about what
// Read does with a reply for a connector that exists, so the listing answers
// that it does; the cases where it does not are covered separately, in
// cloud_manual_integration_instance_read_existence_test.go.
func manualReadHandler(t *testing.T, calls *int) http.HandlerFunc {
	t.Helper()

	census := listingCensus{present: []string{testManualInstanceID}}
	rejected := false

	return func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, cloudonboarding.GetEditInstanceDetailsEndpoint):
			*calls++
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(manualReadReply(t))
		case strings.HasSuffix(r.URL.Path, cloudonboarding.ListIntegrationInstancesEndpoint):
			census.serveListing(t, w, r, &rejected)
		default:
			t.Errorf("unexpected request path: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}
}

// TestManualInstanceReadDoesNotOverwriteManualDetails is the central guard on
// the read path.
//
// The write and read shapes of manual_details are different: the read reports a
// member the write endpoints refuse and omits members they accept. Copying the
// reply into manual_details would therefore build a configuration the platform
// rejects, and would silently replace what the practitioner wrote with what the
// platform happens to report. manual_details must come out of Read exactly as
// it went in, and the reported values must land in reported_manual_details
// instead.
func TestManualInstanceReadDoesNotOverwriteManualDetails(t *testing.T) {
	ctx := context.Background()

	var calls int
	resp, _ := readManualInstance(t, manualReadHandler(t, &calls))

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected read diagnostics: %v", resp.Diagnostics.Errors())
	}
	if calls != 1 {
		t.Fatalf("get_edit_instance_details calls = %d, want 1", calls)
	}

	var refreshed models.CloudManualIntegrationInstanceModel
	if diags := resp.State.Get(ctx, &refreshed); diags.HasError() {
		t.Fatalf("failed to read refreshed state: %v", diags.Errors())
	}

	configuredRole := refreshed.ManualDetails.Attributes()["role_arn"].(types.String)
	if configuredRole.ValueString() != testConfiguredRoleARN {
		t.Errorf("manual_details.role_arn = %q, want the configured %q: the read reply "+
			"was echoed into the configured object, which the write endpoints reject",
			configuredRole.ValueString(), testConfiguredRoleARN)
	}

	if refreshed.ReportedManualDetails.IsNull() {
		t.Fatal("reported_manual_details is null: the platform's values were discarded instead " +
			"of being recorded on the read-only object")
	}

	reportedRole := refreshed.ReportedManualDetails.Attributes()["role_arn"].(types.String)
	if reportedRole.ValueString() != testReportedRoleARN {
		t.Errorf("reported_manual_details.role_arn = %q, want the reported %q",
			reportedRole.ValueString(), testReportedRoleARN)
	}

	// client_id exists only on the reported object. Its presence there, and the
	// configured object keeping the configured role, together show the two
	// objects did not collapse into one.
	reportedClientID := refreshed.ReportedManualDetails.Attributes()["client_id"].(types.String)
	if reportedClientID.ValueString() != "reported-client-id" {
		t.Errorf("reported_manual_details.client_id = %q, want %q",
			reportedClientID.ValueString(), "reported-client-id")
	}
}

// TestManualInstanceReadDoesNotAdoptEmptyReportedAccountName pins the specific
// failure the two-object split exists to prevent.
//
// Azure rejects a write carrying manual_details.account_name as an empty
// string, and an empty string is exactly what the read reports for a connector
// that has no account name. Any path that lets the reported value reach the
// configured object therefore produces a configuration the platform refuses on
// the next write. This asserts the emptiness lands only on the reported object.
func TestManualInstanceReadDoesNotAdoptEmptyReportedAccountName(t *testing.T) {
	ctx := context.Background()

	resp, _ := readManualInstance(t, withConnectorListed(t, func(w http.ResponseWriter, r *http.Request) {
		reply := strings.Replace(
			string(manualReadReply(t)),
			`"account_id": "782785052462",`,
			`"account_id": "782785052462",
	        "account_name": "",`,
			1,
		)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(reply))
	}))

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected read diagnostics: %v", resp.Diagnostics.Errors())
	}

	var refreshed models.CloudManualIntegrationInstanceModel
	if diags := resp.State.Get(ctx, &refreshed); diags.HasError() {
		t.Fatalf("failed to read refreshed state: %v", diags.Errors())
	}

	configuredAccountName := refreshed.ManualDetails.Attributes()["account_name"].(types.String)
	if configuredAccountName.ValueString() == "" && !configuredAccountName.IsNull() {
		t.Error("manual_details.account_name became an empty string from the read reply: " +
			"the platform refuses an empty account name on write, so the next apply would fail")
	}

	reportedAccountName := refreshed.ReportedManualDetails.Attributes()["account_name"].(types.String)
	if reportedAccountName.IsNull() || reportedAccountName.ValueString() != "" {
		t.Errorf("reported_manual_details.account_name = %v, want the reported empty string: "+
			"the reported object is where an unusable platform value belongs", reportedAccountName)
	}
}

// TestManualInstanceReadCarriesWriteOnlyFieldsThrough verifies that fields the
// platform accepts but never reports survive a refresh.
//
// cloudtrail_role and sqs_url have no counterpart in the read reply. Nulling
// them would show a diff on every plan, and applying that diff would blank the
// values on the platform. They must be carried through from the prior state.
//
// They are read from manual_details. The platform refuses both inside
// collection_configuration.audit_logs, so the schema does not offer them there.
func TestManualInstanceReadCarriesWriteOnlyFieldsThrough(t *testing.T) {
	ctx := context.Background()

	var calls int
	resp, _ := readManualInstance(t, manualReadHandler(t, &calls))

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected read diagnostics: %v", resp.Diagnostics.Errors())
	}

	var refreshed models.CloudManualIntegrationInstanceModel
	if diags := resp.State.Get(ctx, &refreshed); diags.HasError() {
		t.Fatalf("failed to read refreshed state: %v", diags.Errors())
	}

	details := refreshed.ManualDetails.Attributes()

	cloudTrailRole := details["cloudtrail_role"].(types.String)
	if cloudTrailRole.ValueString() != testConfiguredCloudTrailRole {
		t.Errorf("manual_details.cloudtrail_role = %q, want the configured %q: "+
			"the platform never reports this field, so nulling it produces a permanent diff",
			cloudTrailRole.ValueString(), testConfiguredCloudTrailRole)
	}

	sqsURL := details["sqs_url"].(types.String)
	if sqsURL.ValueString() != testConfiguredSQSURL {
		t.Errorf("manual_details.sqs_url = %q, want the configured %q: "+
			"the platform never reports this field, so nulling it produces a permanent diff",
			sqsURL.ValueString(), testConfiguredSQSURL)
	}
}

// TestManualInstanceReadRemovesStateWhenConnectorIsGone verifies the one case
// in which Read may drop the resource: the platform explicitly says the
// connector does not exist. Failing to remove it here strands a deleted
// connector in state, and every later plan proposes an update that cannot
// apply.
func TestManualInstanceReadRemovesStateWhenConnectorIsGone(t *testing.T) {
	resp, _ := readManualInstance(t, withConnectorListed(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(`{"reply":{"err_code":422,"err_msg":"Validation failed",` +
			`"err_extra":"connector id ` + testManualInstanceID + ` doesn't exist"}}`))
	}))

	if resp.Diagnostics.HasError() {
		t.Fatalf("a connector the platform says is gone must not raise an error: %v",
			resp.Diagnostics.Errors())
	}
	if !resp.State.Raw.IsNull() {
		t.Error("state was not removed for a connector the platform reports as non-existent: " +
			"the deleted connector stays in state and every later plan proposes an un-appliable update")
	}
}

// TestManualInstanceReadKeepsStateOnAmbiguousSuccess is the counterweight to the
// removal test.
//
// The read endpoint has been observed answering 200 with a payload belonging to
// a different connector, and the reply carries no identifier to check against.
// A 200 therefore proves nothing about existence. Treating one as confirmation
// would be harmless; treating its absence as deletion would not. This test
// pins the direction that matters: a 200 must never remove the resource, and
// must never be used as a claim that the connector is the one we asked for.
func TestManualInstanceReadKeepsStateOnAmbiguousSuccess(t *testing.T) {
	ctx := context.Background()

	// The reply is a valid 200 for some connector. Nothing in it ties it to
	// the identifier that was requested.
	var calls int
	resp, _ := readManualInstance(t, manualReadHandler(t, &calls))

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected read diagnostics: %v", resp.Diagnostics.Errors())
	}
	if resp.State.Raw.IsNull() {
		t.Fatal("state was removed on a 200 reply: this endpoint answers 200 for identifiers " +
			"it does not hold, so a successful read must never be treated as evidence of absence")
	}

	var refreshed models.CloudManualIntegrationInstanceModel
	if diags := resp.State.Get(ctx, &refreshed); diags.HasError() {
		t.Fatalf("failed to read refreshed state: %v", diags.Errors())
	}
	if refreshed.ID.ValueString() != testManualInstanceID {
		t.Errorf("id = %q, want %q: the identifier is held by Terraform, not returned by the "+
			"read endpoint, so it must survive a refresh unchanged",
			refreshed.ID.ValueString(), testManualInstanceID)
	}
}

// TestManualInstanceReadKeepsStateOnServerError verifies that a transport-level
// or server-side failure is not mistaken for deletion. A 500 during an outage
// must surface as an error; removing the resource would make the next apply
// recreate infrastructure that already exists.
func TestManualInstanceReadKeepsStateOnServerError(t *testing.T) {
	resp, _ := readManualInstance(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"reply":{"err_code":500,"err_msg":"internal error"}}`))
	})

	if !resp.Diagnostics.HasError() {
		t.Fatal("a server error must be reported, not swallowed")
	}
	if resp.State.Raw.IsNull() {
		t.Error("state was removed on a server error: a transient failure would destroy the " +
			"record of live infrastructure")
	}
}

// TestIsConnectorGoneErrorIsNarrow pins the absence rule itself.
//
// Only the platform's explicit rejection naming this connector counts as
// absence. Everything else — a different connector's rejection, a generic
// validation failure, a server fault — must not be, because the read endpoint
// cannot otherwise distinguish a missing connector from a present one.
func TestIsConnectorGoneErrorIsNarrow(t *testing.T) {
	const instanceID = "0f7da3939a4d4b0da49ce9d09bfb5d32"

	testCases := map[string]struct {
		message string
		want    bool
	}{
		"the platform names this connector as missing": {
			message: "Error Code: 422\nError Message: Validation failed\n    Message: \"connector id " +
				instanceID + " doesn't exist\"\n",
			want: true,
		},
		"the platform names a different connector as missing": {
			message: "Error Code: 422\n    Message: \"connector id ffffffffffffffffffffffffffffffff doesn't exist\"\n",
			want:    false,
		},
		"a generic validation failure": {
			message: "Error Code: 422\nError Message: Validation failed\n    Message: \"Invalid connector details\"\n",
			want:    false,
		},
		"a server fault": {
			message: "Error Code: 500\nError Message: internal error\n",
			want:    false,
		},
		"a transport failure": {
			message: "Post \"https://example.invalid\": dial tcp: connection refused",
			want:    false,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			got := isConnectorGoneError(&stubError{message: testCase.message}, instanceID)
			if got != testCase.want {
				t.Errorf("isConnectorGoneError(%q) = %v, want %v: treating this as absence would %s",
					testCase.message, got, testCase.want,
					map[bool]string{
						true:  "strand a deleted connector in state",
						false: "delete a live connector from state",
					}[testCase.want])
			}
		})
	}
}

type stubError struct {
	message string
}

func (e *stubError) Error() string { return e.message }

// ----------------------------------------------------------------------------
// Update and Delete
// ----------------------------------------------------------------------------

// updateManualInstance drives Update against a server and returns the response.
//
// The plan is mutated from the state fixture by the caller, so every test
// starts from the same connector and differs only in what it is asking to
// change.
func updateManualInstance(
	t *testing.T,
	handler http.HandlerFunc,
	mutate func(plan *models.CloudManualIntegrationInstanceModel),
) *resource.UpdateResponse {
	t.Helper()

	ctx := context.Background()

	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	instanceResource := &CloudManualIntegrationInstanceResource{client: manualTestClient(t, server)}

	resourceSchema, attributeTypes := manualResourceSchema(t)

	state := tfsdk.State{Schema: resourceSchema}
	stateModel := manualTestModel(t, attributeTypes, true)
	if diags := state.Set(ctx, &stateModel); diags.HasError() {
		t.Fatalf("failed to build state: %v", diags.Errors())
	}

	planModel := manualTestModel(t, attributeTypes, true)
	if mutate != nil {
		mutate(&planModel)
	}
	plan := tfsdk.Plan{Schema: resourceSchema}
	if diags := plan.Set(ctx, &planModel); diags.HasError() {
		t.Fatalf("failed to build plan: %v", diags.Errors())
	}

	req := resource.UpdateRequest{Plan: plan, State: state}
	resp := &resource.UpdateResponse{State: tfsdk.State{Schema: resourceSchema, Raw: state.Raw}}

	instanceResource.Update(ctx, req, resp)

	return resp
}

// manualEditHandler records the edit payload and answers with the endpoint's
// empty success reply.
func manualEditHandler(t *testing.T, calls *int, sent *map[string]any) http.HandlerFunc {
	t.Helper()

	return func(w http.ResponseWriter, r *http.Request) {
		// The edit reply is empty, so the update reads the connector back to
		// record what the platform now holds. Serving that read here keeps the
		// handler focused on the payload it exists to capture.
		if strings.HasSuffix(r.URL.Path, cloudonboarding.GetEditInstanceDetailsEndpoint) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(manualReadReply(t))
			return
		}
		if !strings.HasSuffix(r.URL.Path, cloudonboarding.EditManualInstanceEndpoint) {
			t.Errorf("unexpected request path: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		*calls++

		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("failed to read request body: %v", err)
		}
		var body map[string]any
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Errorf("failed to decode request body: %v", err)
		}
		requestData, _ := body["request_data"].(map[string]any)
		*sent = requestData

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"reply":null}`))
	}
}

// TestManualInstanceUpdateIsImplemented pins that the loud stub is gone.
//
// Update used to refuse every call. That was the right behaviour while nothing
// was wired up, and exactly the wrong behaviour now: a resource whose update
// always fails cannot be changed at all. This asserts a well-formed change is
// carried out rather than rejected.
func TestManualInstanceUpdateIsImplemented(t *testing.T) {
	var calls int
	var sent map[string]any

	resp := updateManualInstance(t, manualEditHandler(t, &calls, &sent), func(plan *models.CloudManualIntegrationInstanceModel) {
		plan.InstanceName = types.StringValue("renamed-connector")
	})

	if resp.Diagnostics.HasError() {
		t.Fatalf("update refused a well-formed change: %v", resp.Diagnostics.Errors())
	}
	if calls != 1 {
		t.Fatalf("edit_manual_instance calls = %d, want 1: the update did not reach the platform", calls)
	}
	if got, _ := sent["instance_name"].(string); got != "renamed-connector" {
		t.Errorf("edit payload instance_name = %q, want %q", got, "renamed-connector")
	}
}

// TestManualInstanceUpdateSendsCompleteDesiredState is the central guard on the
// update path.
//
// The platform's edit is partial: whatever the request leaves out keeps the
// value the platform already holds. An update that sent only what changed would
// therefore be accepted while leaving the rest of the connector stale, with no
// error to show for it. The payload has to carry the whole desired
// configuration, including the members that did not change.
func TestManualInstanceUpdateSendsCompleteDesiredState(t *testing.T) {
	var calls int
	var sent map[string]any

	resp := updateManualInstance(t, manualEditHandler(t, &calls, &sent), func(plan *models.CloudManualIntegrationInstanceModel) {
		plan.InstanceName = types.StringValue("renamed-connector")
	})

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected update diagnostics: %v", resp.Diagnostics.Errors())
	}

	// The connector's identity and the three members the platform fixes at
	// creation must all be resent even though none of them changed.
	for field, want := range map[string]string{
		"id":             testManualInstanceID,
		"cloud_provider": "AWS",
		"scope":          "ACCOUNT",
		"scan_mode":      "MANAGED",
	} {
		if got, _ := sent[field].(string); got != want {
			t.Errorf("edit payload %s = %q, want %q: an omitted field is not updated, so the "+
				"payload must carry the complete desired state", field, got, want)
		}
	}

	// The nested objects are part of the desired state too. Dropping one
	// leaves whatever the platform holds for it in place.
	for _, field := range []string{"manual_details", "additional_capabilities", "collection_configuration", "scope_modifications"} {
		if _, present := sent[field]; !present {
			t.Errorf("edit payload omits %s: the platform keeps its existing value for anything "+
				"the request does not carry, so omitting it silently leaves stale data", field)
		}
	}

	// An unchanged member of manual_details must still be on the wire. This is
	// the difference between sending the desired state and sending a diff.
	manualDetails, ok := sent["manual_details"].(map[string]any)
	if !ok {
		t.Fatalf("edit payload has no manual_details object: %v", sent)
	}
	if got, _ := manualDetails["role_arn"].(string); got != testConfiguredRoleARN {
		t.Errorf("edit payload manual_details.role_arn = %q, want the configured %q: role_arn did "+
			"not change, and a diff-based update would have dropped it", got, testConfiguredRoleARN)
	}
	if got, _ := manualDetails["account_id"].(string); got != "782785052462" {
		t.Errorf("edit payload manual_details.account_id = %q, want %q: an unchanged member must "+
			"still be sent", got, "782785052462")
	}
}

// TestManualInstanceUpdateNeverSendsClientID verifies the read-only member stays
// off the wire.
//
// client_id is reported by the platform and refused on write. It exists only on
// reported_manual_details, and this asserts that nothing on the update path
// folds that object back into the request.
func TestManualInstanceUpdateNeverSendsClientID(t *testing.T) {
	var calls int
	var sent map[string]any

	resp := updateManualInstance(t, manualEditHandler(t, &calls, &sent), func(plan *models.CloudManualIntegrationInstanceModel) {
		// Give the plan a populated reported object, which is what state
		// holds after a refresh. If anything echoed it into the request, this
		// is the shape that would carry it.
		reported := map[string]attr.Value{}
		for name := range models.ManualDetailsReadAttributeTypes() {
			reported[name] = types.StringNull()
		}
		reported["client_id"] = types.StringValue("reported-client-id")
		reported["role_arn"] = types.StringValue(testReportedRoleARN)

		object, diags := types.ObjectValue(models.ManualDetailsReadAttributeTypes(), reported)
		if diags.HasError() {
			t.Fatalf("failed to build reported_manual_details: %v", diags.Errors())
		}
		plan.ReportedManualDetails = object
		plan.InstanceName = types.StringValue("renamed-connector")
	})

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected update diagnostics: %v", resp.Diagnostics.Errors())
	}

	manualDetails, ok := sent["manual_details"].(map[string]any)
	if !ok {
		t.Fatalf("edit payload has no manual_details object: %v", sent)
	}
	if _, present := manualDetails["client_id"]; present {
		t.Error("edit payload manual_details contains client_id, which the platform refuses on write")
	}
	if got, _ := manualDetails["role_arn"].(string); got == testReportedRoleARN {
		t.Errorf("edit payload manual_details.role_arn = %q, which is the value the platform "+
			"reported rather than the one configured: the read was echoed into the write", got)
	}
}

// TestManualInstanceUpdateDoesNotSendEmptyAzureAccountName covers the Azure trap
// on the update path.
//
// Azure refuses manual_details.account_name when it is an empty string, and an
// empty string is exactly what the read reports for a connector without one. If
// any part of the update path turned a reported empty value into a configured
// one, every subsequent Azure update would fail. The configured object is what
// is sent, so an empty reported value must not reach the payload.
func TestManualInstanceUpdateDoesNotSendEmptyAzureAccountName(t *testing.T) {
	var calls int
	var sent map[string]any

	resp := updateManualInstance(t, manualEditHandler(t, &calls, &sent), func(plan *models.CloudManualIntegrationInstanceModel) {
		reported := map[string]attr.Value{}
		for name := range models.ManualDetailsReadAttributeTypes() {
			reported[name] = types.StringNull()
		}
		// What the platform reports for an Azure connector with no account
		// name, and what it will not accept back.
		reported["account_name"] = types.StringValue("")

		object, diags := types.ObjectValue(models.ManualDetailsReadAttributeTypes(), reported)
		if diags.HasError() {
			t.Fatalf("failed to build reported_manual_details: %v", diags.Errors())
		}
		plan.ReportedManualDetails = object
		plan.InstanceName = types.StringValue("renamed-connector")
	})

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected update diagnostics: %v", resp.Diagnostics.Errors())
	}

	manualDetails, ok := sent["manual_details"].(map[string]any)
	if !ok {
		t.Fatalf("edit payload has no manual_details object: %v", sent)
	}
	if value, present := manualDetails["account_name"]; present {
		if text, _ := value.(string); text == "" {
			t.Error("edit payload manual_details.account_name is an empty string: Azure refuses " +
				"that value, so the update would fail for every Azure connector")
		}
	}
}

// TestManualInstanceUpdateRefusesToClearManualDetails proves the update does not
// claim a change it cannot make.
//
// A cleared member is absent from the request, and an absent member leaves the
// stored value alone, so the platform would answer 200 having changed nothing.
// Terraform would write the cleared value into state and never mention the
// difference again. Refusing the plan is the only way to keep state honest.
func TestManualInstanceUpdateRefusesToClearManualDetails(t *testing.T) {
	var calls int
	var sent map[string]any

	resp := updateManualInstance(t, manualEditHandler(t, &calls, &sent), func(plan *models.CloudManualIntegrationInstanceModel) {
		details := plan.ManualDetails.Attributes()
		details["external_id"] = types.StringNull()

		object, diags := types.ObjectValue(models.ManualDetailsWriteAttributeTypes(), details)
		if diags.HasError() {
			t.Fatalf("failed to build manual_details: %v", diags.Errors())
		}
		plan.ManualDetails = object
	})

	if !resp.Diagnostics.HasError() {
		t.Fatal("update accepted a plan that clears a manual_details member: the platform would " +
			"keep the old value and Terraform would record the clear as applied")
	}
	if calls != 0 {
		t.Errorf("edit_manual_instance calls = %d, want 0: an unachievable change must not be sent", calls)
	}

	detail := resp.Diagnostics.Errors()[0].Detail()
	if !strings.Contains(detail, "external_id") {
		t.Errorf("the diagnostic must name the field that cannot be cleared; detail=%q", detail)
	}
	if !strings.Contains(detail, "NOT been changed") {
		t.Errorf("the diagnostic must state that the platform was not modified; detail=%q", detail)
	}
}

// TestManualInstanceUpdateRefusesImmutableFieldChange verifies the replace-only
// fields fail loudly if a change ever reaches Update.
//
// cloud_provider, scope and scan_mode carry RequiresReplace, so Terraform
// should have planned a replacement and Update should never see a change in
// them. Should one arrive anyway, ignoring it would leave the platform holding
// a value the configuration no longer asks for, with state claiming otherwise.
func TestManualInstanceUpdateRefusesImmutableFieldChange(t *testing.T) {
	testCases := map[string]struct {
		mutate func(plan *models.CloudManualIntegrationInstanceModel)
		field  string
	}{
		"cloud_provider": {
			mutate: func(plan *models.CloudManualIntegrationInstanceModel) {
				plan.CloudProvider = types.StringValue("AZURE")
			},
			field: "cloud_provider",
		},
		"scope": {
			mutate: func(plan *models.CloudManualIntegrationInstanceModel) {
				plan.Scope = types.StringValue("ORGANIZATION")
			},
			field: "scope",
		},
		"scan_mode": {
			mutate: func(plan *models.CloudManualIntegrationInstanceModel) {
				plan.ScanMode = types.StringValue("OUTPOST")
			},
			field: "scan_mode",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			var calls int
			var sent map[string]any

			resp := updateManualInstance(t, manualEditHandler(t, &calls, &sent), testCase.mutate)

			if !resp.Diagnostics.HasError() {
				t.Fatalf("update accepted a change to %s, which the platform fixes at creation",
					testCase.field)
			}
			if calls != 0 {
				t.Errorf("edit_manual_instance calls = %d, want 0: the change cannot be applied "+
					"and must not be attempted", calls)
			}
			if !strings.Contains(resp.Diagnostics.Errors()[0].Detail(), testCase.field) {
				t.Errorf("the diagnostic must name %s; detail=%q",
					testCase.field, resp.Diagnostics.Errors()[0].Detail())
			}
		})
	}
}

// TestManualInstanceUpdateReportsPlatformRejection verifies a refused edit is
// surfaced rather than swallowed.
func TestManualInstanceUpdateReportsPlatformRejection(t *testing.T) {
	resp := updateManualInstance(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(`{"reply":{"err_code":422,"err_msg":"Validation failed",` +
			`"err_extra":"Invalid connector details"}}`))
	}, func(plan *models.CloudManualIntegrationInstanceModel) {
		plan.InstanceName = types.StringValue("renamed-connector")
	})

	if !resp.Diagnostics.HasError() {
		t.Fatal("a rejected edit must be reported, not swallowed")
	}
	if !strings.Contains(resp.Diagnostics.Errors()[0].Detail(), "Invalid connector details") {
		t.Errorf("the diagnostic must surface the platform's own message; detail=%q",
			resp.Diagnostics.Errors()[0].Detail())
	}
}

// ----------------------------------------------------------------------------
// Delete
// ----------------------------------------------------------------------------

// manualDeleteHandler serves the delete endpoint and the listing that verifies
// it.
//
// stillListed decides what the verification listing reports, which is how the
// tests distinguish a delete that worked from one that quietly did nothing.
func manualDeleteHandler(t *testing.T, deleteCalls, listCalls *int, stillListed bool) http.HandlerFunc {
	t.Helper()

	return func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, cloudonboarding.DeleteIntegrationInstancesEndpoint):
			*deleteCalls++
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"reply":null}`))

		case strings.HasSuffix(r.URL.Path, cloudonboarding.ListIntegrationInstancesEndpoint):
			*listCalls++
			w.WriteHeader(http.StatusOK)
			if stillListed {
				_, _ = w.Write([]byte(`{"reply":{"DATA":[{"instance_id":"` + testManualInstanceID +
					`","cloud_provider":"AWS","instance_name":"manual-connector","scope":"ACCOUNT",` +
					`"scan_mode":"MANAGED","status":"CONNECTED","custom_resources_tags":"",` +
					`"collection_configuration":"","additional_capabilities":"",` +
					`"provisioning_method":"MANUAL","outpost_id":""}],"TOTAL_COUNT":1}}`))
				return
			}
			_, _ = w.Write([]byte(`{"reply":{"DATA":[],"TOTAL_COUNT":0}}`))

		default:
			t.Errorf("unexpected request path: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}
}

// deleteManualInstance drives Delete against a server and returns the response.
func deleteManualInstance(t *testing.T, handler http.HandlerFunc) *resource.DeleteResponse {
	t.Helper()

	ctx := context.Background()

	server := httptest.NewServer(handler)
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

	return resp
}

// TestManualInstanceDeleteIsImplemented pins that the loud stub is gone and
// that the connector delete endpoint is the one called.
//
// The platform exposes two deletes that act on different records. The connector
// delete removes the row the manual create returns an identifier for; the
// template delete removes a separate row Terraform never learns the identifier
// of. Calling the wrong one succeeds and removes nothing.
func TestManualInstanceDeleteIsImplemented(t *testing.T) {
	var deleteCalls, listCalls int

	resp := deleteManualInstance(t, manualDeleteHandler(t, &deleteCalls, &listCalls, false))

	if resp.Diagnostics.HasError() {
		t.Fatalf("delete refused a connector it should have removed: %v", resp.Diagnostics.Errors())
	}
	if deleteCalls != 1 {
		t.Errorf("delete_instance calls = %d, want 1: the connector delete endpoint is the one "+
			"that removes a connector created by the manual create", deleteCalls)
	}
}

// TestManualInstanceDeleteVerifiesRemovalBeforeSucceeding proves the delete does
// not take the endpoint's word for it.
//
// The delete endpoint answers 200 whether it removed a connector or matched
// nothing at all. A provider that trusted the status code would report success
// for both. The listing afterwards is what makes the difference observable, so
// it has to happen on the success path, not only when something looks wrong.
func TestManualInstanceDeleteVerifiesRemovalBeforeSucceeding(t *testing.T) {
	var deleteCalls, listCalls int

	resp := deleteManualInstance(t, manualDeleteHandler(t, &deleteCalls, &listCalls, false))

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected delete diagnostics: %v", resp.Diagnostics.Errors())
	}
	if listCalls != 1 {
		t.Errorf("verification listings = %d, want 1: a 200 from the delete endpoint is returned "+
			"for a delete that removed nothing, so it cannot be the evidence", listCalls)
	}
}

// TestManualInstanceDeleteFailsWhenConnectorSurvives is the test that matters
// most on this path.
//
// This is the measured no-op: the endpoint returns 200 and the connector is
// still there. Accepting that would make Terraform drop a live connector from
// state, leaving it running with nothing tracking it and the practitioner
// believing it was destroyed. The delete must fail and the resource must stay.
func TestManualInstanceDeleteFailsWhenConnectorSurvives(t *testing.T) {
	var deleteCalls, listCalls int

	resp := deleteManualInstance(t, manualDeleteHandler(t, &deleteCalls, &listCalls, true))

	if !resp.Diagnostics.HasError() {
		t.Fatal("delete reported success while the connector was still listed: Terraform would " +
			"drop a live connector from state and nothing would be managing it")
	}
	if resp.State.Raw.IsNull() {
		t.Error("state was removed for a connector that still exists on the platform")
	}
	if !strings.Contains(resp.Diagnostics.Errors()[0].Detail(), "still present") {
		t.Errorf("the diagnostic must state that the connector still exists; detail=%q",
			resp.Diagnostics.Errors()[0].Detail())
	}
}

// TestManualInstanceDeleteFailsWhenVerificationFails verifies an unverifiable
// delete is not reported as a success.
//
// If the listing cannot be obtained, the outcome is unknown. Unknown is not
// success: the connector may well be live, and dropping it from state would
// strand it. The resource is kept until removal can actually be confirmed.
func TestManualInstanceDeleteFailsWhenVerificationFails(t *testing.T) {
	resp := deleteManualInstance(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, cloudonboarding.DeleteIntegrationInstancesEndpoint) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"reply":null}`))
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"reply":{"err_code":500,"err_msg":"internal error"}}`))
	})

	if !resp.Diagnostics.HasError() {
		t.Fatal("delete reported success without being able to confirm the connector was removed")
	}
	if resp.State.Raw.IsNull() {
		t.Error("state was removed although the removal could not be confirmed")
	}
}

// TestManualInstanceDeleteReportsRejection verifies a refused delete is
// surfaced and the resource kept.
//
// The batch delete has been observed answering with a server error after having
// already removed rows, so an error here does not prove the connector survived.
// Keeping it in state is still right: a connector left in state can be removed
// later, whereas one dropped from state while live is simply lost.
func TestManualInstanceDeleteReportsRejection(t *testing.T) {
	var listCalls int

	resp := deleteManualInstance(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, cloudonboarding.ListIntegrationInstancesEndpoint) {
			listCalls++
		}
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"reply":{"err_code":500,"err_msg":"An error occurred while ` +
			`processing API call","err_extra":"Connector not found"}}`))
	})

	if !resp.Diagnostics.HasError() {
		t.Fatal("a rejected delete must be reported, not swallowed")
	}
	if resp.State.Raw.IsNull() {
		t.Error("state was removed after a failed delete: the connector may still be live")
	}
	if !strings.Contains(resp.Diagnostics.Errors()[0].Detail(), "still exist") {
		t.Errorf("the diagnostic must warn that the connector may still exist; detail=%q",
			resp.Diagnostics.Errors()[0].Detail())
	}
}

// ----------------------------------------------------------------------------
// Import
// ----------------------------------------------------------------------------

// TestManualInstanceImplementsImportState proves the resource offers import at
// all.
//
// Without it a practitioner who already onboarded a connector by hand has no
// route into Terraform other than deleting and recreating live infrastructure.
func TestManualInstanceImplementsImportState(t *testing.T) {
	t.Parallel()

	if _, ok := NewCloudManualIntegrationInstanceResource().(resource.ResourceWithImportState); !ok {
		t.Fatal("the resource does not implement resource.ResourceWithImportState, so \"terraform import\" cannot adopt an existing connector")
	}
}

// TestManualInstanceImportPlacesIDInState proves import writes the supplied
// identifier into the id attribute.
//
// The identifier is the only thing import is given and the only thing the read
// path addresses the connector by. If it does not reach state under the name
// "id", the refresh that follows the import reads an empty identifier.
func TestManualInstanceImportPlacesIDInState(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	resourceSchema, _ := manualResourceSchema(t)

	importer, ok := NewCloudManualIntegrationInstanceResource().(resource.ResourceWithImportState)
	if !ok {
		t.Fatal("the resource does not implement resource.ResourceWithImportState")
	}

	resp := resource.ImportStateResponse{
		State: tfsdk.State{Schema: resourceSchema, Raw: nullRawObject(resourceSchema)},
	}
	importer.ImportState(ctx, resource.ImportStateRequest{ID: testManualInstanceID}, &resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("importing %q produced errors: %v", testManualInstanceID, resp.Diagnostics.Errors())
	}

	var imported models.CloudManualIntegrationInstanceModel
	if diags := resp.State.Get(ctx, &imported); diags.HasError() {
		t.Fatalf("reading the imported state failed: %v", diags.Errors())
	}

	if imported.ID.ValueString() != testManualInstanceID {
		t.Errorf("import put %q in the id attribute, want %q: the read path addresses the connector by this value, so anything else refreshes the wrong connector or none",
			imported.ID.ValueString(), testManualInstanceID)
	}
}

// TestManualInstanceImportLeavesManualDetailsNull records that import cannot
// recover the configurable manual_details, and pins that this is what happens.
//
// The read populates reported_manual_details only, and three write members --
// cloudtrail_role, sqs_url and subscription_id -- are never reported at all, so
// there is nothing to recover them from. The practitioner must therefore
// re-declare manual_details after importing, and the first plan is not empty.
// This test exists so that if someone later makes the read populate
// manual_details from the reply, the change is deliberate rather than a silent
// adoption of platform-reported values the write endpoints may reject.
func TestManualInstanceImportLeavesManualDetailsNull(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	resourceSchema, _ := manualResourceSchema(t)

	importer, ok := NewCloudManualIntegrationInstanceResource().(resource.ResourceWithImportState)
	if !ok {
		t.Fatal("the resource does not implement resource.ResourceWithImportState")
	}

	resp := resource.ImportStateResponse{
		State: tfsdk.State{Schema: resourceSchema, Raw: nullRawObject(resourceSchema)},
	}
	importer.ImportState(ctx, resource.ImportStateRequest{ID: testManualInstanceID}, &resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("importing %q produced errors: %v", testManualInstanceID, resp.Diagnostics.Errors())
	}

	var imported models.CloudManualIntegrationInstanceModel
	if diags := resp.State.Get(ctx, &imported); diags.HasError() {
		t.Fatalf("reading the imported state failed: %v", diags.Errors())
	}

	if !imported.ManualDetails.IsNull() {
		t.Errorf("import left manual_details as %v, want null: the platform never reports cloudtrail_role, sqs_url or subscription_id, so any non-null value here was invented rather than read",
			imported.ManualDetails)
	}
}

// TestManualInstanceImportedStateDoesNotTripTheClearGuard proves the update
// guard does not fire on the first plan after an import.
//
// This is the failure mode worth ruling out. manual_details is null after an
// import and the practitioner must supply it, so the first plan moves every
// member from null to a value. Were ClearedManualDetails to read that as a
// removal, the only plan an imported connector can produce would be refused and
// import would be useless. It does not, because it returns early on null prior
// state -- and this test fails if that early return is ever removed.
func TestManualInstanceImportedStateDoesNotTripTheClearGuard(t *testing.T) {
	t.Parallel()

	_, attributeTypes := manualResourceSchema(t)

	// State as import leaves it: an identifier and nothing configured.
	imported := models.CloudManualIntegrationInstanceModel{
		ID:            types.StringValue(testManualInstanceID),
		ManualDetails: types.ObjectNull(models.ManualDetailsWriteAttributeTypes()),
	}

	// The plan the practitioner's re-declared configuration produces.
	planned := manualTestModel(t, attributeTypes, true)

	var diagnostics diag.Diagnostics
	assertNoManualDetailsCleared(&diagnostics, imported, planned)

	if diagnostics.HasError() {
		t.Errorf("the first plan after an import was refused as clearing manual_details: %v. Import leaves manual_details null by design, so treating null-to-value as a removal makes every imported connector unmanageable",
			diagnostics.Errors())
	}
}

// TestManualInstanceImportedStateDoesNotTripTheImmutableGuard proves the
// immutable-field guard does not fire on the first update after an import.
//
// cloud_provider, scope and scan_mode are populated by the refresh that follows
// the import, so a configuration that agrees with the connector produces no
// change in them. The guard treats a null prior value as "nothing to compare",
// which is what makes a partially populated imported state safe to update.
func TestManualInstanceImportedStateDoesNotTripTheImmutableGuard(t *testing.T) {
	t.Parallel()

	_, attributeTypes := manualResourceSchema(t)

	refreshed := manualTestModel(t, attributeTypes, true)
	planned := manualTestModel(t, attributeTypes, true)

	var diagnostics diag.Diagnostics
	assertImmutableFieldsUnchanged(&diagnostics, refreshed, planned)

	if diagnostics.HasError() {
		t.Errorf("a configuration matching the imported connector was refused: %v. After an import the refresh supplies cloud_provider, scope and scan_mode, so a matching configuration must plan cleanly",
			diagnostics.Errors())
	}
}

// nullRawObject builds an all-null raw value for a schema, which is the state
// Terraform hands to ImportState before the importer writes anything.
func nullRawObject(resourceSchema schema.Schema) tftypes.Value {
	return tftypes.NewValue(resourceSchema.Type().TerraformType(context.Background()), nil)
}
