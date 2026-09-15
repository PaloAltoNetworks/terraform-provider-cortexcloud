// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package cloudonboarding

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"

	types "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/types/cloudonboarding"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func strPtr(s string) *string { return &s }
func boolPtr(b bool) *bool    { return &b }

// captureBody returns a handler that records the raw request_data JSON and
// replies with the supplied status/body.
func captureBody(t *testing.T, wantPath string, status int, respBody string, got *json.RawMessage) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, fmt.Sprintf("/%s", wantPath), r.URL.Path)

		raw, err := io.ReadAll(r.Body)
		require.NoError(t, err)

		var envelope struct {
			RequestData json.RawMessage `json:"request_data"`
		}
		require.NoError(t, json.Unmarshal(raw, &envelope))
		*got = envelope.RequestData

		w.WriteHeader(status)
		fmt.Fprint(w, respBody)
	}
}

func TestClient_CreateManualInstance(t *testing.T) {
	// Goldens are byte-for-byte the request_data of captured HTTP 200 responses.
	tests := []struct {
		name       string
		input      *types.CreateManualInstanceRequest
		wantJSON   string
		wantID     string
		evidenceIs string
	}{
		{
			// evidence: postman-verification/stage2/raw/A5-control-no-name-field-at-all.json (200)
			name: "aws account minimal, no instance_name",
			input: types.NewCreateManualInstanceRequest(
				"AWS", "ACCOUNT", "MANAGED",
				types.ManualDetails{
					AccountID:   strPtr("782785052462"),
					AccountName: strPtr("pc-qa-auto-1"),
					RoleARN:     strPtr("arn:aws:iam::782785052462:role/CortexPlatformRole-m-a-9996114313562"),
					ExternalID:  strPtr("9d7ad021-5f2e-4f5b-9240-b2b43e367f42"),
				},
				types.WithManualCreateCollectionConfiguration(types.ManualCollectionConfiguration{
					AuditLogs: types.ManualAuditLogsConfiguration{CollectionMethod: "CUSTOM"},
				}),
				types.WithManualCreateScopeModifications(types.ManualScopeModifications{
					Regions: &types.ScopeModificationRegions{Enabled: false},
				}),
				types.WithManualCreateCustomResourcesTags([]types.Tag{
					{Key: "owner", Value: "example"},
				}),
			),
			wantJSON: `{
				"cloud_provider": "AWS",
				"scope": "ACCOUNT",
				"scan_mode": "MANAGED",
				"manual_details": {
					"account_id": "782785052462",
					"account_name": "pc-qa-auto-1",
					"role_arn": "arn:aws:iam::782785052462:role/CortexPlatformRole-m-a-9996114313562",
					"external_id": "9d7ad021-5f2e-4f5b-9240-b2b43e367f42"
				},
				"additional_capabilities": {},
				"collection_configuration": {
					"audit_logs": {
						"enabled": false,
						"data_events": false,
						"collection_method": "CUSTOM"
					}
				},
				"scope_modifications": {"regions": {"enabled": false}},
				"custom_resources_tags": [{"key": "owner", "value": "example"}]
			}`,
			wantID: "1040f5c980d94f6aa35e2ab2dcf1f171",
		},
		{
			// evidence: postman-verification/stage2/raw/C0-azure-11keys-no-client_id.json (200)
			// client_id is deliberately absent: every capture that sent it returned 422.
			name: "azure account with instance_name and 11 manual_details keys",
			input: types.NewCreateManualInstanceRequest(
				"AZURE", "ACCOUNT", "MANAGED",
				types.ManualDetails{
					TenantID:                            strPtr("194cfdc7-41f0-4eec-8bfb-1b805cf74f53"),
					SubscriptionID:                      strPtr("a00175b3-230f-49db-b68f-0b35f61bf305"),
					ResourceGroupName:                   strPtr("cortex-platform-ee"),
					ResourceGroupLocation:               strPtr("eastus"),
					ADSImageGalleryResourceID:           strPtr("/subscriptions/a00175b3/galleries/CortexAdsGalleryEe"),
					EventHubName:                        strPtr("cortex-eventhub-ee"),
					EventHubResourceGroupName:           strPtr("cortex-platform-ee"),
					EventHubNamespace:                   strPtr("cortex-eh-namespace-ee"),
					AzureAuditEventHubConsumerGroupName: strPtr("cortex-cg-ee"),
					StorageAccountName:                  strPtr("cortexstorageaccountee"),
					EventHubAuditClientID:               strPtr("c4e5b52a-c846-486c-a2ba-66254ad37eb0"),
				},
				types.WithManualCreateInstanceName("azure-connector"),
				types.WithManualCreateCollectionConfiguration(types.ManualCollectionConfiguration{
					AuditLogs: types.ManualAuditLogsConfiguration{CollectionMethod: "CUSTOM"},
				}),
				types.WithManualCreateScopeModifications(types.ManualScopeModifications{
					Regions: &types.ScopeModificationRegions{Enabled: false},
				}),
			),
			wantJSON: `{
				"cloud_provider": "AZURE",
				"scope": "ACCOUNT",
				"scan_mode": "MANAGED",
				"instance_name": "azure-connector",
				"manual_details": {
					"tenant_id": "194cfdc7-41f0-4eec-8bfb-1b805cf74f53",
					"subscription_id": "a00175b3-230f-49db-b68f-0b35f61bf305",
					"resource_group_name": "cortex-platform-ee",
					"resource_group_location": "eastus",
					"ads_image_gallery_resource_id": "/subscriptions/a00175b3/galleries/CortexAdsGalleryEe",
					"eventhub_name": "cortex-eventhub-ee",
					"eventhub_resource_group_name": "cortex-platform-ee",
					"eventhub_namespace": "cortex-eh-namespace-ee",
					"azure_audit_eventhub_consumer_group_name": "cortex-cg-ee",
					"storage_account_name": "cortexstorageaccountee",
					"eventhub_audit_client_id": "c4e5b52a-c846-486c-a2ba-66254ad37eb0"
				},
				"additional_capabilities": {},
				"collection_configuration": {
					"audit_logs": {
						"enabled": false,
						"data_events": false,
						"collection_method": "CUSTOM"
					}
				},
				"scope_modifications": {"regions": {"enabled": false}}
			}`,
			wantID: "1040f5c980d94f6aa35e2ab2dcf1f171",
		},
		{
			// evidence: postman-verification/stage2/raw/E1-maximal-all-caps-on-audit-on.json (200)
			// All seven capability toggles are sent explicitly as booleans.
			name: "aws with all capability toggles explicitly set",
			input: types.NewCreateManualInstanceRequest(
				"AWS", "ACCOUNT", "MANAGED",
				types.ManualDetails{
					AccountID:  strPtr("782785052462"),
					RoleARN:    strPtr("arn:aws:iam::782785052462:role/Role"),
					ExternalID: strPtr("9d7ad021"),
				},
				types.WithManualCreateAdditionalCapabilities(types.ManualAdditionalCapabilities{
					Automation:                    boolPtr(false),
					XSIAMAnalytics:                boolPtr(true),
					RegistryScanning:              boolPtr(false),
					KubernetesSecurity:            boolPtr(true),
					ServerlessScanning:            boolPtr(false),
					AgentlessDiskScanning:         boolPtr(true),
					DataSecurityPostureManagement: boolPtr(false),
				}),
				types.WithManualCreateCollectionConfiguration(types.ManualCollectionConfiguration{
					AuditLogs: types.ManualAuditLogsConfiguration{
						Enabled:          true,
						DataEvents:       true,
						CollectionMethod: "CUSTOM",
					},
				}),
				types.WithManualCreateScopeModifications(types.ManualScopeModifications{
					Regions: &types.ScopeModificationRegions{Enabled: false},
				}),
			),
			wantJSON: `{
				"cloud_provider": "AWS",
				"scope": "ACCOUNT",
				"scan_mode": "MANAGED",
				"manual_details": {
					"account_id": "782785052462",
					"role_arn": "arn:aws:iam::782785052462:role/Role",
					"external_id": "9d7ad021"
				},
				"additional_capabilities": {
					"automation": false,
					"xsiam_analytics": true,
					"registry_scanning": false,
					"kubernetes_security": true,
					"serverless_scanning": false,
					"agentless_disk_scanning": true,
					"data_security_posture_management": false
				},
				"collection_configuration": {
					"audit_logs": {
						"enabled": true,
						"data_events": true,
						"collection_method": "CUSTOM"
					}
				},
				"scope_modifications": {"regions": {"enabled": false}}
			}`,
			wantID: "1040f5c980d94f6aa35e2ab2dcf1f171",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got json.RawMessage
			client, server := setupTest(t, captureBody(
				t, CreateManualInstanceEndpoint, http.StatusOK,
				fmt.Sprintf(`{"reply":{"id":%q}}`, tt.wantID), &got,
			))
			defer server.Close()

			resp, err := client.CreateManualInstance(context.Background(), tt.input)
			require.NoError(t, err)
			assert.Equal(t, tt.wantID, resp.ID)
			require.JSONEq(t, tt.wantJSON, string(got))
		})
	}

	t.Run("propagates API errors", func(t *testing.T) {
		var got json.RawMessage
		client, server := setupTest(t, captureBody(
			t, CreateManualInstanceEndpoint, http.StatusUnprocessableEntity,
			`{"reply":{"err_code":422,"err_msg":"Validation failed"}}`, &got,
		))
		defer server.Close()

		_, err := client.CreateManualInstance(context.Background(),
			types.NewCreateManualInstanceRequest("AWS", "ACCOUNT", "MANAGED", types.ManualDetails{}))
		require.Error(t, err)
	})
}

func TestClient_EditManualInstance(t *testing.T) {
	// evidence: task-00-edit-endpoint/raw/11-edit_manual_instance-ladder1-contract-full.json (200)
	fullAWS := func(opts ...types.EditManualInstanceRequestOption) *types.EditManualInstanceRequest {
		base := []types.EditManualInstanceRequestOption{
			types.WithManualEditInstanceName("t0-m1-044604"),
			types.WithManualEditCloudPartition("COMMERCIAL"),
			types.WithManualEditAdditionalCapabilities(types.ManualAdditionalCapabilities{
				Automation:                    boolPtr(false),
				XSIAMAnalytics:                boolPtr(false),
				RegistryScanning:              boolPtr(false),
				KubernetesSecurity:            boolPtr(false),
				ServerlessScanning:            boolPtr(false),
				AgentlessDiskScanning:         boolPtr(false),
				DataSecurityPostureManagement: boolPtr(false),
			}),
			types.WithManualEditCollectionConfiguration(types.ManualCollectionConfiguration{
				AuditLogs: types.ManualAuditLogsConfiguration{
					CollectionMethod:   "CUSTOM",
					IsControlTowerBYOB: boolPtr(false),
				},
			}),
			types.WithManualEditScopeModifications(types.ManualScopeModifications{
				Regions:         &types.ScopeModificationRegions{Enabled: false},
				OnboardOnlyMode: boolPtr(false),
			}),
			types.WithManualEditCustomResourcesTags([]types.Tag{
				{Key: "managed_by", Value: "paloaltonetworks"},
			}),
		}
		return types.NewEditManualInstanceRequest(
			"3ee1db259f16463ab09424441c314711", "AWS", "ACCOUNT", "MANAGED",
			types.ManualDetails{
				AccountID:             strPtr("782785052462"),
				AccountName:           strPtr("pc-qa-auto-1"),
				OrganizationID:        strPtr(""),
				RoleARN:               strPtr("arn:aws:iam::782785052462:role/CortexPlatformRole-m-a-9996114313562"),
				ExternalID:            strPtr("9d7ad021-5f2e-4f5b-9240-b2b43e367f42"),
				OutpostScannerRoleARN: strPtr(""),
			},
			append(base, opts...)...,
		)
	}

	t.Run("sends the full captured contract body", func(t *testing.T) {
		var got json.RawMessage
		client, server := setupTest(t, captureBody(
			t, EditManualInstanceEndpoint, http.StatusOK, `{"reply":{}}`, &got,
		))
		defer server.Close()

		require.NoError(t, client.EditManualInstance(context.Background(), fullAWS()))

		require.JSONEq(t, `{
			"id": "3ee1db259f16463ab09424441c314711",
			"cloud_provider": "AWS",
			"scope": "ACCOUNT",
			"scan_mode": "MANAGED",
			"manual_details": {
				"account_id": "782785052462",
				"account_name": "pc-qa-auto-1",
				"organization_id": "",
				"role_arn": "arn:aws:iam::782785052462:role/CortexPlatformRole-m-a-9996114313562",
				"external_id": "9d7ad021-5f2e-4f5b-9240-b2b43e367f42",
				"outpost_scanner_role_arn": ""
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
					"enabled": false,
					"data_events": false,
					"collection_method": "CUSTOM",
					"is_control_tower_byob": false
				}
			},
			"scope_modifications": {
				"regions": {"enabled": false},
				"onboard_only_mode": false
			},
			"instance_name": "t0-m1-044604",
			"cloud_partition": "COMMERCIAL",
			"custom_resources_tags": [{"key": "managed_by", "value": "paloaltonetworks"}]
		}`, string(got))
	})

	// Regression guard. Omitting cloud_provider returns HTTP 500
	// (task-00-edit-endpoint/raw/31-edit_manual_instance-cp-omit.json), so the
	// key must always reach the wire — never `omitempty`.
	t.Run("always marshals cloud_provider even when empty", func(t *testing.T) {
		var got json.RawMessage
		client, server := setupTest(t, captureBody(
			t, EditManualInstanceEndpoint, http.StatusOK, `{"reply":{}}`, &got,
		))
		defer server.Close()

		err := client.EditManualInstance(context.Background(),
			types.NewEditManualInstanceRequest("id-1", "", "ACCOUNT", "MANAGED", types.ManualDetails{}))
		require.NoError(t, err)

		var body map[string]any
		require.NoError(t, json.Unmarshal(got, &body))
		require.Contains(t, body, "cloud_provider", "cloud_provider must never be omitted")
		assert.Equal(t, "", body["cloud_provider"])
	})

	// scope and scan_mode are immutable server-side and must also always be sent.
	t.Run("always marshals the immutable identity fields", func(t *testing.T) {
		var got json.RawMessage
		client, server := setupTest(t, captureBody(
			t, EditManualInstanceEndpoint, http.StatusOK, `{"reply":{}}`, &got,
		))
		defer server.Close()

		require.NoError(t, client.EditManualInstance(context.Background(),
			types.NewEditManualInstanceRequest("id-1", "AWS", "", "", types.ManualDetails{})))

		var body map[string]any
		require.NoError(t, json.Unmarshal(got, &body))
		for _, k := range []string{"id", "cloud_provider", "scope", "scan_mode", "manual_details"} {
			require.Contains(t, body, k, "%s must always be present", k)
		}
	})

	// cloud_partition was absent from 17 of 24 accepted edits, so it must stay optional.
	t.Run("omits cloud_partition when unset", func(t *testing.T) {
		var got json.RawMessage
		client, server := setupTest(t, captureBody(
			t, EditManualInstanceEndpoint, http.StatusOK, `{"reply":{}}`, &got,
		))
		defer server.Close()

		require.NoError(t, client.EditManualInstance(context.Background(),
			types.NewEditManualInstanceRequest("id-1", "AWS", "ACCOUNT", "MANAGED", types.ManualDetails{})))

		var body map[string]any
		require.NoError(t, json.Unmarshal(got, &body))
		assert.NotContains(t, body, "cloud_partition")
		assert.NotContains(t, body, "instance_name")
		assert.NotContains(t, body, "custom_resources_tags")
	})

	t.Run("propagates API errors", func(t *testing.T) {
		var got json.RawMessage
		client, server := setupTest(t, captureBody(
			t, EditManualInstanceEndpoint, http.StatusBadRequest,
			`{"reply":{"err_code":400,"err_msg":"cloud_provider cannot be changed"}}`, &got,
		))
		defer server.Close()

		err := client.EditManualInstance(context.Background(),
			types.NewEditManualInstanceRequest("id-1", "AZURE", "ACCOUNT", "MANAGED", types.ManualDetails{}))
		require.Error(t, err)
	})
}
