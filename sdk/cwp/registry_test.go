// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package cwp

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	types "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/types/cwp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const registryInstancesPath = "/" + RegistryOnboardingInstancesEndpoint

func intPtr(i int) *int { return &i }

func sampleRegistryConnector() types.RegistryConnector {
	return types.RegistryConnector{
		Vendor:        "DOCKER_HUB",
		Name:          "my-dockerhub",
		Enabled:       true,
		URL:           "https://registry-1.docker.io",
		Username:      "svc-user",
		Password:      "s3cret",
		ScanningMode:  "CLOUD",
		CloudProvider: "AWS",
		Region:        "us-east-1",
		InitialScanConfiguration: types.InitialScanConfiguration{
			Mode:    "TAGS_MODIFIED_DAYS",
			NumDays: intPtr(7),
		},
		VendorSpecificConfiguration: &types.VendorSpecificConfig{Repository: "my-repo"},
	}
}

func decodeBody(t *testing.T, r *http.Request) map[string]any {
	t.Helper()
	raw, err := io.ReadAll(r.Body)
	require.NoError(t, err)
	var body map[string]any
	require.NoError(t, json.Unmarshal(raw, &body))
	return body
}

func TestCreateRegistryConnector(t *testing.T) {
	var body map[string]any
	client, server := setupTest(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, registryInstancesPath, r.URL.Path)
		body = decodeBody(t, r)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"connector_id":"conn-123"}`))
	})
	defer server.Close()

	id, err := client.CreateRegistryConnector(context.Background(), sampleRegistryConnector())
	require.NoError(t, err)
	assert.Equal(t, "conn-123", id)

	// connector_id must not be sent on create.
	_, hasID := body["connector_id"]
	assert.False(t, hasID, "connector_id must be omitted on create")

	// initial_scan_configuration uses camelCase numDays.
	isc, ok := body["initial_scan_configuration"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "TAGS_MODIFIED_DAYS", isc["mode"])
	assert.Equal(t, float64(7), isc["numDays"])
	_, snake := isc["num_days"]
	assert.False(t, snake, "num_days (snake_case) must not be sent")

	// Only the Docker Hub variant of vendor_specific_configuration is sent.
	vsc, ok := body["vendor_specific_configuration"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, map[string]any{"repository": "my-repo"}, vsc)
}

func TestCreateRegistryConnector_RequiredFieldsAlwaysSent(t *testing.T) {
	var body map[string]any
	client, server := setupTest(t, func(w http.ResponseWriter, r *http.Request) {
		body = decodeBody(t, r)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"connector_id":"conn-1"}`))
	})
	defer server.Close()

	// A token-authenticated connector: username/password empty, insecure_pull false.
	input := types.RegistryConnector{
		Vendor:                   "HARBOR",
		Name:                     "harbor",
		URL:                      "https://harbor.example.com",
		AuthToken:                "tok",
		ScanningMode:             "OUTPOST",
		OutpostID:                "op-1",
		InitialScanConfiguration: types.InitialScanConfiguration{Mode: "ALL"},
	}
	_, err := client.CreateRegistryConnector(context.Background(), input)
	require.NoError(t, err)

	// The spec lists these as required; they must be present even when empty/false.
	for _, key := range []string{"vendor", "name", "url", "username", "password", "auth_token", "scanning_mode", "region", "insecure_pull", "initial_scan_configuration", "enabled"} {
		_, ok := body[key]
		assert.Truef(t, ok, "required field %q must always be sent", key)
	}
	// Optional fields that are unset must be omitted.
	for _, key := range []string{"cloud_provider", "broker_type", "broker_id", "asset_scope_filters", "vendor_specific_configuration", "allow_static_ips"} {
		_, ok := body[key]
		assert.Falsef(t, ok, "unset optional field %q must be omitted", key)
	}
	isc := body["initial_scan_configuration"].(map[string]any)
	_, hasDays := isc["numDays"]
	assert.False(t, hasDays, "numDays must be omitted when not set")
}

func TestCreateRegistryConnector_MissingConnectorID(t *testing.T) {
	client, server := setupTest(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{}`))
	})
	defer server.Close()

	_, err := client.CreateRegistryConnector(context.Background(), sampleRegistryConnector())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "connector_id")
}

func TestGetRegistryConnector(t *testing.T) {
	client, server := setupTest(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, registryInstancesPath+"/conn-123", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"connector_id": "conn-123",
			"vendor": "GITLAB_CONTAINER_REGISTRY",
			"name": "gl",
			"enabled": true,
			"url": "https://registry.gitlab.com",
			"username": "",
			"password": "",
			"auth_token": "",
			"scanning_mode": "BROKER",
			"broker_type": "BROKER_VM",
			"broker_id": "b-1",
			"region": "",
			"insecure_pull": false,
			"initial_scan_configuration": {"mode": "LATEST_TAG"},
			"filter_type": "EXCLUDE",
			"asset_scope_filters": {"AND": [{"SEARCH_FIELD": "Registry", "SEARCH_TYPE": "EQ", "SEARCH_VALUE": "library/ubuntu"}]},
			"vendor_specific_configuration": {"group_ids": "1,2", "api_domain_name": "gitlab.example.com"},
			"tenant_id": "t-1"
		}`))
	})
	defer server.Close()

	got, err := client.GetRegistryConnector(context.Background(), "conn-123")
	require.NoError(t, err)
	assert.Equal(t, "conn-123", got.ConnectorID)
	assert.Equal(t, "GITLAB_CONTAINER_REGISTRY", got.Vendor)
	assert.Equal(t, "BROKER", got.ScanningMode)
	assert.Equal(t, "BROKER_VM", got.BrokerType)
	assert.Equal(t, "LATEST_TAG", got.InitialScanConfiguration.Mode)
	assert.Nil(t, got.InitialScanConfiguration.NumDays)
	assert.Equal(t, "EXCLUDE", got.FilterType)
	require.NotNil(t, got.AssetScopeFilters)
	require.NotNil(t, got.VendorSpecificConfiguration)
	assert.Equal(t, "1,2", got.VendorSpecificConfiguration.GroupIDs)
	assert.Equal(t, "gitlab.example.com", got.VendorSpecificConfiguration.APIDomainName)
	assert.Equal(t, "t-1", got.TenantID)
}

func TestGetRegistryConnector_NotFound(t *testing.T) {
	client, server := setupTest(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"err_msg":"Connector ID not found","metadata":{"code":"NOT_FOUND"}}`))
	})
	defer server.Close()

	got, err := client.GetRegistryConnector(context.Background(), "missing")
	require.Error(t, err)
	assert.Nil(t, got)
	assert.True(t, IsNotFound(err), "a documented 404 body must be recognised as not found: %v", err)
}

func TestIsNotFound_UnrecognisedBody(t *testing.T) {
	client, server := setupTest(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`page not found`))
	})
	defer server.Close()

	_, err := client.GetRegistryConnector(context.Background(), "missing")
	require.Error(t, err)
	assert.True(t, IsNotFound(err), "a 404 with an unparseable body must be recognised: %v", err)
}

func TestIsNotFound_OtherErrorsAreNotNotFound(t *testing.T) {
	client, server := setupTest(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"err_msg":"Bad Request","metadata":{"code":"BAD_REQUEST"}}`))
	})
	defer server.Close()

	_, err := client.GetRegistryConnector(context.Background(), "x")
	require.Error(t, err)
	assert.False(t, IsNotFound(err))
	assert.False(t, IsNotFound(nil))
}

func TestUpdateRegistryConnector(t *testing.T) {
	var body map[string]any
	client, server := setupTest(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPut, r.Method)
		assert.Equal(t, registryInstancesPath+"/conn-123", r.URL.Path)
		body = decodeBody(t, r)
		w.WriteHeader(http.StatusNoContent)
	})
	defer server.Close()

	err := client.UpdateRegistryConnector(context.Background(), "conn-123", sampleRegistryConnector())
	require.NoError(t, err)

	// Full replacement: credentials and the ID are part of the body.
	assert.Equal(t, "conn-123", body["connector_id"])
	assert.Equal(t, "s3cret", body["password"])
	assert.Equal(t, "my-dockerhub", body["name"])
}

func TestDeleteRegistryConnector(t *testing.T) {
	called := false
	client, server := setupTest(t, func(w http.ResponseWriter, r *http.Request) {
		called = true
		assert.Equal(t, http.MethodDelete, r.Method)
		assert.Equal(t, registryInstancesPath+"/conn-123", r.URL.Path)
		w.WriteHeader(http.StatusNoContent)
	})
	defer server.Close()

	require.NoError(t, client.DeleteRegistryConnector(context.Background(), "conn-123"))
	assert.True(t, called)
}
