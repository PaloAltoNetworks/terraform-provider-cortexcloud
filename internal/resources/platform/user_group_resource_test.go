// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package platform_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/provider"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestUnitUserGroupResource(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			if strings.HasSuffix(r.URL.String(), "/user-groups") {
				w.WriteHeader(http.StatusCreated)
				fmt.Fprintln(w, `{
					"group_id": "test-group-1",
					"group_name": "test-group-1",
					"description": "This is a test user group.",
					"role_name": "test-role"
				}`) //nolint:errcheck
				return
			}
		} else if r.Method == http.MethodGet {
			if strings.HasSuffix(r.URL.String(), "/user-groups") {
				w.WriteHeader(http.StatusOK)
				//nolint:errcheck
				fmt.Fprintln(w, `{
					"data": [
						{
							"group_id": "test-group-1",
							"group_name": "test-group-1",
							"description": "This is a test user group.",
							"role_name": "test-role"
						}
					]
				}`)
				return
			}
		} else if r.Method == http.MethodPatch {
			if strings.Contains(r.URL.String(), "/user-groups/") {
				w.WriteHeader(http.StatusOK)
				fmt.Fprintln(w, `{"reply": {"success": true}}`) //nolint:errcheck
				return
			}
		} else if r.Method == http.MethodDelete {
			if strings.Contains(r.URL.String(), "/user-groups/") {
				w.WriteHeader(http.StatusOK)
				fmt.Fprintln(w, `{"reply": {"success": true}}`) //nolint:errcheck
				return
			}
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
						api_url = "%s"
						api_key = "test"
						api_key_id = 123
					}
					resource "cortexcloud_user_group" "test" {
						name        = "test-group-1"
						description = "This is a test user group."
						role_name   = "test-role"
					}
				`, server.URL),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("cortexcloud_user_group.test", "name", "test-group-1"),
					resource.TestCheckResourceAttr("cortexcloud_user_group.test", "description", "This is a test user group."),
					resource.TestCheckResourceAttr("cortexcloud_user_group.test", "role_name", "test-role"),
				),
			},
		},
	})
}
