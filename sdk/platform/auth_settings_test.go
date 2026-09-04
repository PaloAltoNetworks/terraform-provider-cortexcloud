// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package platform

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/types/platform"
	"github.com/stretchr/testify/assert"
)

func TestClient_ListIDPMetadata(t *testing.T) {
	t.Run("should list idp metadata successfully", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodPost, r.Method)
			assert.Equal(t, "/"+ListIDPMetadataEndpoint, r.URL.Path)

			var req map[string]types.ListIDPMetadataRequest
			err := json.NewDecoder(r.Body).Decode(&req)
			assert.NoError(t, err)

			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{
				"tenant_id": "my-tenant",
				"sp_entity_id": "sp-entity-id",
				"sp_logout_url": "https://logout.url",
				"sp_url": "https://sp.url"
			}`)
		})
		client, server := setupTest(t, handler)
		defer server.Close()

		resp, err := client.ListIDPMetadata(context.Background())
		assert.NoError(t, err)
		assert.Equal(t, "my-tenant", resp.TenantID)
		assert.Equal(t, "sp-entity-id", resp.SpEntityID)
	})
}

func TestClient_ListAuthSettings(t *testing.T) {
	t.Run("should list auth settings successfully", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodPost, r.Method)
			assert.Equal(t, "/"+ListAuthSettingsEndpoint, r.URL.Path)

			var req map[string]types.ListAuthSettingsRequest
			err := json.NewDecoder(r.Body).Decode(&req)
			assert.NoError(t, err)

			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{
				"reply": [
					{
						"tenant_id": "my-tenant",
						"name": "Test Setting",
						"domain": "example.com"
					}
				]
			}`)
		})
		client, server := setupTest(t, handler)
		defer server.Close()

		resp, err := client.ListAuthSettings(context.Background())
		assert.NoError(t, err)
		assert.Len(t, resp, 1)
		assert.Equal(t, "Test Setting", resp[0].Name)
		assert.Equal(t, "example.com", resp[0].Domain)
	})
}

func TestClient_CreateAuthSettings(t *testing.T) {
	t.Run("should create auth settings successfully", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodPost, r.Method)
			assert.Equal(t, "/"+CreateAuthSettingsEndpoint, r.URL.Path)

			var req map[string]types.CreateAuthSettingsRequest
			err := json.NewDecoder(r.Body).Decode(&req)
			assert.NoError(t, err)
			assert.Equal(t, "New Setting", req["request_data"].Name)
			assert.Equal(t, "new.example.com", req["request_data"].Domain)

			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"reply": true}`)
		})
		client, server := setupTest(t, handler)
		defer server.Close()

		createReq := types.CreateAuthSettingsRequest{
			Name:   "New Setting",
			Domain: "new.example.com",
		}
		resp, err := client.CreateAuthSettings(context.Background(), createReq)
		assert.NoError(t, err)
		assert.True(t, resp)
	})
}

func TestClient_UpdateAuthSettings(t *testing.T) {
	t.Run("should update auth settings successfully", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodPost, r.Method)
			assert.Equal(t, "/"+UpdateAuthSettingsEndpoint, r.URL.Path)

			var req map[string]types.UpdateAuthSettingsRequest
			err := json.NewDecoder(r.Body).Decode(&req)
			assert.NoError(t, err)
			assert.Equal(t, "Updated Setting", req["request_data"].Name)
			assert.Equal(t, "old.example.com", req["request_data"].CurrentDomain)
			assert.Equal(t, "new.example.com", req["request_data"].NewDomain)

			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"reply": true}`)
		})
		client, server := setupTest(t, handler)
		defer server.Close()

		updateReq := types.UpdateAuthSettingsRequest{
			Name:          "Updated Setting",
			CurrentDomain: "old.example.com",
			NewDomain:     "new.example.com",
		}
		resp, err := client.UpdateAuthSettings(context.Background(), updateReq)
		assert.NoError(t, err)
		assert.True(t, resp)
	})
}

func TestClient_DeleteAuthSettings(t *testing.T) {
	t.Run("should delete auth settings successfully", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodPost, r.Method)
			assert.Equal(t, "/"+DeleteAuthSettingsEndpoint, r.URL.Path)

			var req map[string]types.DeleteAuthSettingsRequest
			err := json.NewDecoder(r.Body).Decode(&req)
			assert.NoError(t, err)
			assert.Equal(t, "delete.example.com", req["request_data"].Domain)

			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"reply": true}`)
		})
		client, server := setupTest(t, handler)
		defer server.Close()

		resp, err := client.DeleteAuthSettings(context.Background(), "delete.example.com")
		assert.NoError(t, err)
		assert.True(t, resp)
	})
}
