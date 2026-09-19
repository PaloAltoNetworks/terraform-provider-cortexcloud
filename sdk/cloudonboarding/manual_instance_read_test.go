// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package cloudonboarding

import (
	"context"
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"

	types "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/types/cloudonboarding"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// awsReadBody is the reply of a captured HTTP 200 from get_edit_instance_details,
// reproduced byte-for-byte from
// task-00-edit-endpoint/raw/01-read-chosen.json.
const awsReadBody = `{
  "reply": {
    "fields": {
      "instance_name": "cmprobe-off-custom",
      "cloud_provider": "AWS",
      "scope": "ACCOUNT",
      "scan_mode": "MANAGED",
      "custom_resources_tags": [
        {"key": "managed_by", "value": "paloaltonetworks"}
      ],
      "provisioning_method": "MANUAL",
      "account_details": {
        "account_id": "782785052462",
        "csp_org_id": "",
        "account_name": "pc-qa-auto-1",
        "account_group": "",
        "organization_id": ""
      },
      "scope_modifications": {
        "regions": {"enabled": false},
        "onboard_only_mode": false
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
      "scan_env_id": "749b0ae770164096b1300d3f9c38f5cf",
      "cloud_partition": "COMMERCIAL",
      "upgrade_available": false,
      "gcp_workspace": {"enabled": false},
      "manual_details": {
        "account_id": "782785052462",
        "account_name": "pc-qa-auto-1",
        "organization_id": "",
        "role_arn": "arn:aws:iam::782785052462:role/CortexPlatformRole-m-a-9996114313562",
        "external_id": "9d7ad021-5f2e-4f5b-9240-b2b43e367f42",
        "outpost_scanner_role_arn": ""
      }
    },
    "pending_changes": {}
  }
}`

// azureReadBody is the reply of a captured HTTP 200 from
// get_edit_instance_details for an AZURE ORGANIZATION connector, reproduced
// from probe-11-contract-conformance/phase3-checks.json (record E1-C1 tail,
// $[18].observed.body.reply).
const azureReadBody = `{
  "reply": {
    "fields": {
      "instance_name": "ORG-Created by PAPI- Enabled-18.08",
      "cloud_provider": "AZURE",
      "scope": "ORGANIZATION",
      "scan_mode": "MANAGED",
      "custom_resources_tags": [
        {"key": "env", "value": "prod"},
        {"key": "managed_by", "value": "paloaltonetworks"}
      ],
      "provisioning_method": "MANUAL",
      "account_details": {
        "account_id": "194cfdc7-41f0-4eec-8bfb-1b805cf74f53",
        "csp_org_id": "194cfdc7-41f0-4eec-8bfb-1b805cf74f53",
        "account_name": "",
        "account_group": "194cfdc7-41f0-4eec-8bfb-1b805cf74f53",
        "organization_id": "194cfdc7-41f0-4eec-8bfb-1b805cf74f53"
      },
      "scope_modifications": {
        "regions": {"enabled": false},
        "subscriptions": {"enabled": false}
      },
      "additional_capabilities": {
        "automation": true,
        "xsiam_analytics": true,
        "registry_scanning": true,
        "kubernetes_security": true,
        "serverless_scanning": true,
        "automation_log_level": "OFF",
        "agentless_disk_scanning": true,
        "upload_files_to_wildfire": false,
        "registry_scanning_options": {"type": "ALL"},
        "data_security_posture_management": true
      },
      "collection_configuration": {
        "audit_logs": {
          "enabled": true,
          "data_events": false,
          "collection_method": "CUSTOM",
          "is_control_tower_byob": false,
          "custom_collectors": {
            "eventhub_name": "cortex-eventhub-ee2",
            "eventhub_resource_group_name": "cortex-platform-ee2",
            "namespace": "cortex-eh-namespace-ee2"
          }
        }
      },
      "scan_env_id": "7b44bf8f38f544d18ec427d523b51e25",
      "cloud_partition": "COMMERCIAL",
      "upgrade_available": false,
      "gcp_workspace": {},
      "manual_details": {
        "account_name": "",
        "tenant_id": "194cfdc7-41f0-4eec-8bfb-1b805cf74f53",
        "client_id": "6a01ce18-259c-4fbe-b2e1-8469cf60cf61",
        "eventhub_name": "cortex-eventhub-ee2",
        "eventhub_resource_group_name": "cortex-platform-ee2",
        "eventhub_namespace": "cortex-eh-namespace-ee2",
        "azure_audit_eventhub_consumer_group_name": "cortex-cg-ee2",
        "storage_account_name": "cortexstorageaccountee2",
        "eventhub_audit_client_id": "40b77f9c-d1a5-44a8-8dc3-0faba3cfa1cb",
        "ads_image_gallery_resource_id": "/subscriptions/c04e24d1/galleries/CortexAdsGalleryEe2",
        "resource_group_name": "cortex-platform-ee2",
        "resource_group_location": "eastus"
      }
    },
    "pending_changes": {}
  }
}`

func TestClient_GetEditInstanceDetails(t *testing.T) {
	t.Run("sends only the id in request_data", func(t *testing.T) {
		var got json.RawMessage
		client, server := setupTest(t, captureBody(
			t, GetEditInstanceDetailsEndpoint, http.StatusOK, awsReadBody, &got,
		))
		defer server.Close()

		_, err := client.GetEditInstanceDetails(context.Background(),
			types.NewGetEditInstanceDetailsRequest("3ee1db259f16463ab09424441c314711"))
		require.NoError(t, err)

		// evidence: task-00-edit-endpoint/raw/01-read-chosen.json request_data.
		require.JSONEq(t, `{"id": "3ee1db259f16463ab09424441c314711"}`, string(got))
	})

	t.Run("decodes a captured AWS reply", func(t *testing.T) {
		var got json.RawMessage
		client, server := setupTest(t, captureBody(
			t, GetEditInstanceDetailsEndpoint, http.StatusOK, awsReadBody, &got,
		))
		defer server.Close()

		ans, err := client.GetEditInstanceDetails(context.Background(),
			types.NewGetEditInstanceDetailsRequest("3ee1db259f16463ab09424441c314711"))
		require.NoError(t, err)

		f := ans.Fields
		assert.Equal(t, "cmprobe-off-custom", f.InstanceName)
		assert.Equal(t, "AWS", f.CloudProvider)
		assert.Equal(t, "ACCOUNT", f.Scope)
		assert.Equal(t, "MANAGED", f.ScanMode)
		assert.Equal(t, "MANUAL", f.ProvisioningMethod)
		assert.Equal(t, "749b0ae770164096b1300d3f9c38f5cf", f.ScanEnvID)
		assert.Equal(t, "COMMERCIAL", f.CloudPartition)
		assert.False(t, f.UpgradeAvailable)
		assert.Equal(t, types.ReadTagList{{Key: "managed_by", Value: "paloaltonetworks"}}, f.CustomResourcesTags)

		require.NotNil(t, f.AccountDetails)
		assert.Equal(t, "782785052462", f.AccountDetails.AccountID)
		assert.Equal(t, "pc-qa-auto-1", f.AccountDetails.AccountName)

		require.NotNil(t, f.ManualDetails)
		require.NotNil(t, f.ManualDetails.RoleARN)
		assert.Equal(t, "arn:aws:iam::782785052462:role/CortexPlatformRole-m-a-9996114313562", *f.ManualDetails.RoleARN)
		require.NotNil(t, f.ManualDetails.ExternalID)
		assert.Equal(t, "9d7ad021-5f2e-4f5b-9240-b2b43e367f42", *f.ManualDetails.ExternalID)
		require.NotNil(t, f.ManualDetails.OutpostScannerRoleARN)
		assert.Equal(t, "", *f.ManualDetails.OutpostScannerRoleARN)
		// Azure-only keys are absent from an AWS reply.
		assert.Nil(t, f.ManualDetails.TenantID)
		assert.Nil(t, f.ManualDetails.ClientID)

		require.NotNil(t, f.CollectionConfiguration)
		assert.Equal(t, "CUSTOM", f.CollectionConfiguration.AuditLogs.CollectionMethod)
		require.NotNil(t, f.CollectionConfiguration.AuditLogs.IsControlTowerBYOB)
		assert.False(t, *f.CollectionConfiguration.AuditLogs.IsControlTowerBYOB)

		require.NotNil(t, f.ScopeModifications)
		require.NotNil(t, f.ScopeModifications.Regions)
		assert.False(t, f.ScopeModifications.Regions.Enabled)
		require.NotNil(t, f.ScopeModifications.OnboardOnlyMode)
		assert.False(t, *f.ScopeModifications.OnboardOnlyMode)

		require.NotNil(t, f.AdditionalCapabilities)
		require.NotNil(t, f.AdditionalCapabilities.Automation)
		assert.False(t, *f.AdditionalCapabilities.Automation)
		// Only present on connectors that carry them; absent here.
		assert.Nil(t, f.AdditionalCapabilities.AutomationLogLevel)
		assert.Nil(t, f.AdditionalCapabilities.RegistryScanningOptions)
	})

	// The read shape is NOT the write shape. This reply carries client_id, which
	// the create/edit endpoints reject with 422, and it omits subscription_id,
	// which the write shape carries. Decoding it into the read type must not
	// lose either signal.
	t.Run("decodes a captured Azure reply including read-only keys", func(t *testing.T) {
		var got json.RawMessage
		client, server := setupTest(t, captureBody(
			t, GetEditInstanceDetailsEndpoint, http.StatusOK, azureReadBody, &got,
		))
		defer server.Close()

		ans, err := client.GetEditInstanceDetails(context.Background(),
			types.NewGetEditInstanceDetailsRequest("some-azure-id"))
		require.NoError(t, err)

		f := ans.Fields
		assert.Equal(t, "AZURE", f.CloudProvider)
		assert.Equal(t, "ORGANIZATION", f.Scope)

		md := f.ManualDetails
		require.NotNil(t, md)
		require.NotNil(t, md.TenantID)
		assert.Equal(t, "194cfdc7-41f0-4eec-8bfb-1b805cf74f53", *md.TenantID)
		// client_id is read-only: it is returned here but is rejected on write.
		require.NotNil(t, md.ClientID)
		assert.Equal(t, "6a01ce18-259c-4fbe-b2e1-8469cf60cf61", *md.ClientID)
		require.NotNil(t, md.EventHubNamespace)
		assert.Equal(t, "cortex-eh-namespace-ee2", *md.EventHubNamespace)
		require.NotNil(t, md.ResourceGroupLocation)
		assert.Equal(t, "eastus", *md.ResourceGroupLocation)

		// AWS-only keys are absent from an Azure reply.
		assert.Nil(t, md.RoleARN)
		assert.Nil(t, md.AccountID)

		require.NotNil(t, f.AdditionalCapabilities.AutomationLogLevel)
		assert.Equal(t, "OFF", *f.AdditionalCapabilities.AutomationLogLevel)
		require.NotNil(t, f.AdditionalCapabilities.RegistryScanningOptions)
		assert.Equal(t, "ALL", f.AdditionalCapabilities.RegistryScanningOptions.Type)
		require.NotNil(t, f.AdditionalCapabilities.UploadFilesToWildfire)
		assert.False(t, *f.AdditionalCapabilities.UploadFilesToWildfire)

		cc := f.CollectionConfiguration.AuditLogs.CustomCollectors
		require.NotNil(t, cc)
		require.NotNil(t, cc.EventHubName)
		assert.Equal(t, "cortex-eventhub-ee2", *cc.EventHubName)
		require.NotNil(t, cc.Namespace)
		assert.Equal(t, "cortex-eh-namespace-ee2", *cc.Namespace)

		require.NotNil(t, f.ScopeModifications.Subscriptions)
		assert.False(t, f.ScopeModifications.Subscriptions.Enabled)
		// onboard_only_mode is absent from this reply.
		assert.Nil(t, f.ScopeModifications.OnboardOnlyMode)
	})

	t.Run("propagates the 422 returned for an unknown id", func(t *testing.T) {
		var got json.RawMessage
		client, server := setupTest(t, captureBody(
			t, GetEditInstanceDetailsEndpoint, http.StatusUnprocessableEntity,
			// evidence: task-00-edit-endpoint/raw/02-read-bogus-NEGATIVE-CONTROL.json
			`{"reply":{"err_code":422,"err_msg":"Validation failed",`+
				`"err_extra":"connector id deadbeefdeadbeefdeadbeefdeadbeef doesn't exist"}}`, &got,
		))
		defer server.Close()

		_, err := client.GetEditInstanceDetails(context.Background(),
			types.NewGetEditInstanceDetailsRequest("deadbeefdeadbeefdeadbeefdeadbeef"))
		require.Error(t, err)
	})
}

// jsonKeys returns the JSON object keys a struct type marshals to.
func jsonKeys(t *testing.T, v any) map[string]bool {
	t.Helper()
	rt := reflect.TypeOf(v)
	keys := make(map[string]bool, rt.NumField())
	for i := 0; i < rt.NumField(); i++ {
		tag := rt.Field(i).Tag.Get("json")
		if tag == "" || tag == "-" {
			continue
		}
		if comma := strings.Index(tag, ","); comma >= 0 {
			tag = tag[:comma]
		}
		keys[tag] = true
	}
	return keys
}

// The read and write shapes of manual_details are not interchangeable. This
// asserts the specific divergences that captured traffic proves, so that
// collapsing the two types into one breaks the build's tests rather than
// silently producing requests the API rejects or drops.
func TestManualDetailsReadWriteAsymmetry(t *testing.T) {
	read := jsonKeys(t, types.ManualDetailsRead{})
	write := jsonKeys(t, types.ManualDetails{})

	// Read-only. client_id appears in captured replies
	// (probe-11-contract-conformance/phase3-checks.json) but every create that
	// sent it was refused with HTTP 422, so it must not be writable.
	require.True(t, read["client_id"], "client_id must be readable")
	require.False(t, write["client_id"], "client_id must not be writable")

	// Write-only. subscription_id is accepted by create
	// (postman-verification/stage2/raw/C0-azure-11keys-no-client_id.json) but has
	// never appeared in a reply, so modelling it as readable would invent a field.
	require.True(t, write["subscription_id"], "subscription_id must be writable")
	require.False(t, read["subscription_id"], "subscription_id must not be readable")

	// cloudtrail_role and sqs_url are accepted on write but absent from every
	// captured reply.
	for _, k := range []string{"cloudtrail_role", "sqs_url"} {
		require.True(t, write[k], "%s must be writable", k)
		require.False(t, read[k], "%s must not be readable", k)
	}

	// Keys observed on both sides, for every captured AWS reply.
	for _, k := range []string{"account_id", "account_name", "organization_id", "role_arn", "external_id", "outpost_scanner_role_arn"} {
		require.True(t, read[k], "%s must be readable", k)
		require.True(t, write[k], "%s must be writable", k)
	}
}

func TestClient_DeleteInstanceTemplate(t *testing.T) {
	t.Run("sends only template_id in request_data", func(t *testing.T) {
		var got json.RawMessage
		client, server := setupTest(t, captureBody(
			t, DeleteInstanceTemplateEndpoint, http.StatusOK, `{"reply": null}`, &got,
		))
		defer server.Close()

		require.NoError(t, client.DeleteInstanceTemplate(context.Background(),
			types.NewDeleteInstanceTemplateRequest("384e0a948e0840ccad9cc8e24ff2011f")))

		// evidence: postman-verification/stage2/raw/Z03-delete_template-384e0a94.json
		// All 17 captured deletes send exactly this one key.
		require.JSONEq(t, `{"template_id": "384e0a948e0840ccad9cc8e24ff2011f"}`, string(got))
	})

	// The API returns HTTP 200 with a null reply for a template that does not
	// exist. That is by design (adjudicated Won't Fix), so the client must
	// surface it as success and must not synthesise a not-found error.
	t.Run("treats a 200 for an unknown template as success", func(t *testing.T) {
		var got json.RawMessage
		client, server := setupTest(t, captureBody(
			t, DeleteInstanceTemplateEndpoint, http.StatusOK, `{"reply": null}`, &got,
		))
		defer server.Close()

		err := client.DeleteInstanceTemplate(context.Background(),
			types.NewDeleteInstanceTemplateRequest("deadbeefdeadbeefdeadbeefdeadbeef"))
		require.NoError(t, err)
	})

	t.Run("propagates API errors", func(t *testing.T) {
		var got json.RawMessage
		client, server := setupTest(t, captureBody(
			t, DeleteInstanceTemplateEndpoint, http.StatusUnprocessableEntity,
			`{"reply":{"err_code":422,"err_msg":"Validation failed"}}`, &got,
		))
		defer server.Close()

		err := client.DeleteInstanceTemplate(context.Background(),
			types.NewDeleteInstanceTemplateRequest(""))
		require.Error(t, err)
	})
}
