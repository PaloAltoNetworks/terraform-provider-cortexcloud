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

	"github.com/PaloAltoNetworks/cortex-cloud-go/cloudonboarding"
	cloudOnboardingTypes "github.com/PaloAltoNetworks/cortex-cloud-go/types/cloudonboarding"

	models "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/cloud_onboarding"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// TestAddImportRequiredError verifies that the Create-path helper emits exactly
// one error diagnostic (no warnings) with the import-guidance summary and an
// actionable `terraform import` instruction in the detail. This mirrors the
// Create behavior without needing a live API or a fully-constructed request.
func TestAddImportRequiredError(t *testing.T) {
	var diags diag.Diagnostics

	addImportRequiredError(&diags)

	if !diags.HasError() {
		t.Fatalf("expected an error diagnostic, got none; diags=%v", diags)
	}
	if got := diags.ErrorsCount(); got != 1 {
		t.Errorf("ErrorsCount()=%d, want 1", got)
	}
	if got := diags.WarningsCount(); got != 0 {
		t.Errorf("WarningsCount()=%d, want 0", got)
	}

	d := diags.Errors()[0]
	if got, want := d.Summary(), "Resource Must Be Imported"; got != want {
		t.Errorf("Summary()=%q, want %q", got, want)
	}
	if !strings.Contains(d.Detail(), "terraform import cortexcloud_cloud_integration_instance") {
		t.Errorf("Detail() missing import instruction; detail=%q", d.Detail())
	}
	if !strings.Contains(d.Detail(), "EXISTING") {
		t.Errorf("Detail() should explain the resource manages an existing instance; detail=%q", d.Detail())
	}
}

// TestAddStateOnlyDeletionWarning verifies that the Delete-path helper emits
// exactly one warning diagnostic (no errors) that references the specific
// instance ID and explains the integration is not deleted server-side. This
// mirrors the Delete behavior without needing a live API or a fully-constructed
// request.
func TestAddStateOnlyDeletionWarning(t *testing.T) {
	const instanceID = "instance-abc-123"

	var diags diag.Diagnostics

	addStateOnlyDeletionWarning(&diags, instanceID)

	if diags.HasError() {
		t.Fatalf("expected no error diagnostics, got %v", diags.Errors())
	}
	if got := diags.WarningsCount(); got != 1 {
		t.Fatalf("WarningsCount()=%d, want 1", got)
	}

	d := diags.Warnings()[0]
	if got, want := d.Summary(), "Cloud Integration Instance Not Deleted from Cortex Cloud"; got != want {
		t.Errorf("Summary()=%q, want %q", got, want)
	}
	if !strings.Contains(d.Detail(), instanceID) {
		t.Errorf("Detail() should reference the instance ID %q; detail=%q", instanceID, d.Detail())
	}
	if !strings.Contains(d.Detail(), "Terraform state") {
		t.Errorf("Detail() should explain state-only removal; detail=%q", d.Detail())
	}
}

// TestSelectManagedOutpostID verifies the pure outpost-selection logic used to
// derive scan_env_id: it must pick the managed outpost whose cloud_provider
// matches the instance, ignore non-managed and non-matching outposts, and error
// when no suitable managed outpost exists.
func TestSelectManagedOutpostID(t *testing.T) {
	testCases := []struct {
		name          string
		outposts      []cloudOnboardingTypes.Outpost
		cloudProvider string
		want          string
		wantErr       bool
	}{
		{
			name: "picks matching managed outpost",
			outposts: []cloudOnboardingTypes.Outpost{
				{CloudProvider: "AWS", OutpostID: "aws-managed", Type: "MANAGED"},
				{CloudProvider: "AZURE", OutpostID: "azure-managed", Type: "MANAGED"},
			},
			cloudProvider: "AWS",
			want:          "aws-managed",
		},
		{
			name: "ignores non-managed outpost of the same provider",
			outposts: []cloudOnboardingTypes.Outpost{
				{CloudProvider: "AWS", OutpostID: "aws-outpost", Type: "OUTPOST"},
				{CloudProvider: "AWS", OutpostID: "aws-managed", Type: "MANAGED"},
			},
			cloudProvider: "AWS",
			want:          "aws-managed",
		},
		{
			name: "matches provider case-insensitively",
			outposts: []cloudOnboardingTypes.Outpost{
				{CloudProvider: "AWS", OutpostID: "aws-managed", Type: "MANAGED"},
			},
			cloudProvider: "aws",
			want:          "aws-managed",
		},
		{
			name: "errors when only non-managed outposts exist",
			outposts: []cloudOnboardingTypes.Outpost{
				{CloudProvider: "AWS", OutpostID: "aws-outpost", Type: "OUTPOST"},
			},
			cloudProvider: "AWS",
			wantErr:       true,
		},
		{
			name: "errors when provider does not match",
			outposts: []cloudOnboardingTypes.Outpost{
				{CloudProvider: "AZURE", OutpostID: "azure-managed", Type: "MANAGED"},
			},
			cloudProvider: "AWS",
			wantErr:       true,
		},
		{
			name: "errors when the matching managed outpost has an empty id",
			outposts: []cloudOnboardingTypes.Outpost{
				{CloudProvider: "AWS", OutpostID: "", Type: "MANAGED"},
			},
			cloudProvider: "AWS",
			wantErr:       true,
		},
		{
			name:          "errors on empty outpost list",
			outposts:      nil,
			cloudProvider: "AWS",
			wantErr:       true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := selectManagedOutpostID(tc.outposts, tc.cloudProvider)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got outpost_id=%q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("selectManagedOutpostID() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestSelectManagedOutpostIDRejectsAmbiguousMatches verifies that more than one
// matching managed outpost is surfaced as an actionable error rather than
// silently resolved. get_outposts result ordering is not a documented stability
// guarantee, so picking the first would make the derived scan_env_id vary
// between runs and could point a full-replace edit at a different outpost.
func TestSelectManagedOutpostIDRejectsAmbiguousMatches(t *testing.T) {
	outposts := []cloudOnboardingTypes.Outpost{
		{CloudProvider: "AWS", OutpostID: "aws-managed-b", Type: "MANAGED"},
		{CloudProvider: "AWS", OutpostID: "aws-managed-a", Type: "MANAGED"},
		{CloudProvider: "AWS", OutpostID: "aws-not-managed", Type: "OUTPOST"},
		{CloudProvider: "AZURE", OutpostID: "azure-managed", Type: "MANAGED"},
	}

	got, err := selectManagedOutpostID(outposts, "AWS")
	if err == nil {
		t.Fatalf("expected an error for ambiguous managed outposts, got outpost_id=%q", got)
	}
	if got != "" {
		t.Errorf("expected an empty outpost_id alongside the error, got %q", got)
	}

	// The message has to be actionable: name every candidate and say how to
	// disambiguate.
	for _, candidate := range []string{"aws-managed-a", "aws-managed-b"} {
		if !strings.Contains(err.Error(), candidate) {
			t.Errorf("error should list candidate %q; error=%q", candidate, err.Error())
		}
	}
	if !strings.Contains(err.Error(), "outpost_id") {
		t.Errorf("error should tell the practitioner to set outpost_id; error=%q", err.Error())
	}
}

// instanceDetailsReply builds a get_instance_details reply body. The API returns
// collection_configuration and additional_capabilities as JSON-encoded strings,
// which the SDK unmarshals a second time.
func instanceDetailsReply(t *testing.T, instanceID string, serverlessScanning bool) []byte {
	t.Helper()

	capabilities, err := json.Marshal(map[string]any{
		"xsiam_analytics":                  true,
		"data_security_posture_management": false,
		"registry_scanning":                false,
		"serverless_scanning":              serverlessScanning,
		"agentless_disk_scanning":          true,
	})
	if err != nil {
		t.Fatalf("failed to encode additional_capabilities: %v", err)
	}
	collection, err := json.Marshal(map[string]any{
		"audit_logs": map[string]any{
			"enabled":           true,
			"collection_method": "AUTOMATED",
			"data_events":       false,
		},
	})
	if err != nil {
		t.Fatalf("failed to encode collection_configuration: %v", err)
	}

	body, err := json.Marshal(map[string]any{
		"reply": map[string]any{
			"id":                       instanceID,
			"collector":                "collector-1",
			"instance_name":            "live-instance",
			"scope":                    "ACCOUNT",
			"tags":                     []map[string]string{{"key": "owner", "value": "platform"}},
			"scan":                     map[string]any{"scan_method": "MANAGED"},
			"status":                   "CONNECTED",
			"cloud_provider":           "AWS",
			"security_capabilities":    []any{},
			"collection_configuration": string(collection),
			"additional_capabilities":  string(capabilities),
		},
	})
	if err != nil {
		t.Fatalf("failed to encode reply: %v", err)
	}
	return body
}

// updateTestModel builds a complete resource model for the Update path, with
// every attribute the schema declares set to a known or typed-null value.
func updateTestModel(t *testing.T, attributeTypes map[string]attr.Type, serverlessScanning bool) models.CloudIntegrationInstanceResourceModel {
	t.Helper()

	capabilityTypes := attributeTypes["additional_capabilities"].(types.ObjectType).AttrTypes
	registryOptionTypes := capabilityTypes["registry_scanning_options"].(types.ObjectType).AttrTypes
	collectionTypes := attributeTypes["collection_configuration"].(types.ObjectType).AttrTypes
	auditLogTypes := collectionTypes["audit_logs"].(types.ObjectType).AttrTypes

	capabilities := types.ObjectValueMust(capabilityTypes, map[string]attr.Value{
		"xsiam_analytics":                  types.BoolValue(true),
		"data_security_posture_management": types.BoolValue(false),
		"registry_scanning":                types.BoolValue(false),
		"registry_scanning_options":        types.ObjectNull(registryOptionTypes),
		"serverless_scanning":              types.BoolValue(serverlessScanning),
		"agentless_disk_scanning":          types.BoolValue(true),
	})
	collection := types.ObjectValueMust(collectionTypes, map[string]attr.Value{
		"audit_logs": types.ObjectValueMust(auditLogTypes, map[string]attr.Value{
			"enabled":           types.BoolValue(true),
			"collection_method": types.StringValue("AUTOMATED"),
			"data_events":       types.BoolValue(false),
		}),
	})

	return models.CloudIntegrationInstanceResourceModel{
		ID:                      types.StringValue("instance-1"),
		InstanceName:            types.StringValue("live-instance"),
		OutpostID:               types.StringValue("outpost-1"),
		CloudProvider:           types.StringValue("AWS"),
		CloudPartition:          types.StringNull(),
		AdditionalCapabilities:  capabilities,
		CollectionConfiguration: collection,
		CustomResourcesTags:     types.SetNull(attributeTypes["custom_resources_tags"].(types.SetType).ElemType),
		ScopeModifications:      types.ObjectNull(attributeTypes["scope_modifications"].(types.ObjectType).AttrTypes),
		Collector:               types.StringValue("collector-1"),
		Scope:                   types.StringValue("ACCOUNT"),
		Status:                  types.StringValue("CONNECTED"),
		SecurityCapabilities:    types.SetNull(attributeTypes["security_capabilities"].(types.SetType).ElemType),
		Scan:                    types.ObjectNull(attributeTypes["scan"].(types.ObjectType).AttrTypes),
		UpgradeAvailable:        types.BoolValue(false),
	}
}

// TestUpdatePersistsStateWhenReadBackFails verifies that a failed read-back
// after a SUCCESSFUL edit still writes state. The platform has already been
// mutated at that point, so returning without writing state would leave
// Terraform believing the pre-apply values are live: the change is invisible to
// the practitioner and the next plan proposes an edit that has already been
// applied. State must record the mutation, and the diagnostic must say the edit
// landed but the refresh did not.
func TestUpdatePersistsStateWhenReadBackFails(t *testing.T) {
	ctx := context.Background()

	var detailsCalls int
	var editCalls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, cloudonboarding.GetIntegrationInstanceDetailsEndpoint):
			detailsCalls++
			if detailsCalls > 1 {
				// The read-back after the edit fails. 500 is not retried by the
				// SDK, so this resolves immediately.
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte(`{"reply":{"err_msg":"internal error"}}`))
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(instanceDetailsReply(t, "instance-1", false))
		case strings.HasSuffix(r.URL.Path, cloudonboarding.EditIntegrationInstanceEndpoint):
			editCalls++
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"reply":{}}`))
		default:
			t.Errorf("unexpected request path: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client, err := cloudonboarding.NewClient(
		cloudonboarding.WithCortexAPIURL(server.URL),
		cloudonboarding.WithCortexAPIKey("test-key"),
		cloudonboarding.WithCortexAPIKeyID(1),
		cloudonboarding.WithTransport(server.Client().Transport.(*http.Transport)),
	)
	if err != nil {
		t.Fatalf("failed to build client: %v", err)
	}

	instanceResource := &CloudIntegrationInstanceResource{client: client}

	var schemaResp resource.SchemaResponse
	instanceResource.Schema(ctx, resource.SchemaRequest{}, &schemaResp)
	if schemaResp.Diagnostics.HasError() {
		t.Fatalf("unexpected schema diagnostics: %v", schemaResp.Diagnostics.Errors())
	}
	resourceSchema := schemaResp.Schema
	attributeTypes := resourceSchema.Type().(types.ObjectType).AttrTypes

	// Prior state has serverless_scanning disabled; the plan enables it.
	priorState := tfsdk.State{Schema: resourceSchema}
	stateModel := updateTestModel(t, attributeTypes, false)
	if diags := priorState.Set(ctx, &stateModel); diags.HasError() {
		t.Fatalf("failed to build prior state: %v", diags.Errors())
	}

	plan := tfsdk.Plan{Schema: resourceSchema}
	planModel := updateTestModel(t, attributeTypes, true)
	if diags := plan.Set(ctx, &planModel); diags.HasError() {
		t.Fatalf("failed to build plan: %v", diags.Errors())
	}

	req := resource.UpdateRequest{Plan: plan, State: priorState}
	resp := &resource.UpdateResponse{State: tfsdk.State{Schema: resourceSchema, Raw: priorState.Raw}}

	instanceResource.Update(ctx, req, resp)

	if editCalls != 1 {
		t.Fatalf("edit_instance calls = %d, want 1 (the edit must have been applied)", editCalls)
	}
	if !resp.Diagnostics.HasError() {
		t.Fatal("expected an error diagnostic for the failed read-back")
	}

	detail := resp.Diagnostics.Errors()[0].Detail()
	if !strings.Contains(detail, "edit was applied") {
		t.Errorf("diagnostic should say the edit was applied; detail=%q", detail)
	}
	if !strings.Contains(detail, "refresh") {
		t.Errorf("diagnostic should tell the practitioner to refresh; detail=%q", detail)
	}

	if resp.State.Raw.IsNull() {
		t.Fatal("state was not written after a successful edit: the platform was " +
			"mutated but Terraform state still reflects the pre-apply values")
	}

	var persisted models.CloudIntegrationInstanceResourceModel
	if diags := resp.State.Get(ctx, &persisted); diags.HasError() {
		t.Fatalf("failed to read persisted state: %v", diags.Errors())
	}

	serverless := persisted.AdditionalCapabilities.Attributes()["serverless_scanning"].(types.Bool)
	if !serverless.ValueBool() {
		t.Errorf("persisted serverless_scanning = %v, want true: state must record "+
			"the values that were successfully applied", serverless)
	}
}
