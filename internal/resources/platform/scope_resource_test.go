// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package platform_test

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/provider"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestUnitScopeResource(t *testing.T) {
	var edited atomic.Bool

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && strings.Contains(r.URL.String(), "/scope") {
			w.WriteHeader(http.StatusOK)
			if !edited.Load() {
				_, _ = fmt.Fprintln(w, `{
					"data": {
						"assets": {
							"mode": "scope",
							"asset_groups": [
								{
									"asset_group_id": 1,
									"asset_group_name": "Asset Group 1"
								}
							]
						}
					}
				}`)
				return
			}
			_, _ = fmt.Fprintln(w, `{
				"data": {
					"assets": {
						"mode": "scope",
						"asset_groups": [
							{
								"asset_group_id": 2,
								"asset_group_name": "Asset Group 2"
							}
						]
					}
				}
			}`)
			return
		}

		if r.Method == http.MethodPut && strings.Contains(r.URL.String(), "/scope") {
			bodyBytes, _ := io.ReadAll(r.Body)
			r.Body = io.NopCloser(bytes.NewReader(bodyBytes))

			if strings.Contains(string(bodyBytes), `"asset_group_ids":[2]`) {
				edited.Store(true)
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			return
		}

		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	resource.Test(t, resource.TestCase{
		IsUnitTest: true,
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"cortexcloud": providerserver.NewProtocol6WithError(provider.New("test")()),
		},
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
					provider "cortexcloud" {
						api_url   = "%s"
						api_key   = "test"
						api_key_id = 123
					}

					resource "cortexcloud_scope" "s" {
						entity_type = "user"
						entity_id   = "test@example.com"
						assets = {
							mode = "scope"
							asset_groups = [
								{
									asset_group_id = 1
								}
							]
						}
					}
				`, server.URL),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("cortexcloud_scope.s", "entity_type", "user"),
					resource.TestCheckResourceAttr("cortexcloud_scope.s", "entity_id", "test@example.com"),
					resource.TestCheckResourceAttr("cortexcloud_scope.s", "assets.mode", "scope"),
					resource.TestCheckResourceAttr("cortexcloud_scope.s", "assets.asset_groups.0.asset_group_id", "1"),
				),
			},
			{
				Config: fmt.Sprintf(`
					provider "cortexcloud" {
						api_url   = "%s"
						api_key   = "test"
						api_key_id = 123
					}

					resource "cortexcloud_scope" "s" {
						entity_type = "user"
						entity_id   = "test@example.com"
						assets = {
							mode = "scope"
							asset_groups = [
								{
									asset_group_id = 2
								}
							]
						}
					}
				`, server.URL),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("cortexcloud_scope.s", "assets.asset_groups.0.asset_group_id", "2"),
				),
			},
		},
	})
}
