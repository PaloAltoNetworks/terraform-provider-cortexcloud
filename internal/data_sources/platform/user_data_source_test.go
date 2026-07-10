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

// TestUnitUserDataSource is a regression test for the user data
// source previously crashed with "Struct defines fields not found in object:
// group_ids" because the shared UserModel declared a `group_ids` field that the
// data source schema did not define. This test reads a user (with groups) via
// the data source and asserts a clean read, including the computed group_ids.
func TestUnitUserDataSource(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && strings.Contains(r.URL.String(), "user") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprintln(w, `{
				"data": {
					"user_email": "test@example.com",
					"user_first_name": "Jane",
					"user_last_name": "Doe",
					"phone_number": "123-456-7890",
					"status": "ACTIVE",
					"role_name": "Instance Administrator",
					"last_logged_in": 0,
					"is_hidden": false,
					"user_type": "standard",
					"groups": [
						{"group_id": "11111111-1111-1111-1111-111111111111", "group_name": "security-team"},
						{"group_id": "22222222-2222-2222-2222-222222222222", "group_name": "analysts"}
					]
				}
			}`)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	resource.Test(t, resource.TestCase{
		IsUnitTest: true,
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"cortexcloud": providerserver.NewProtocol6WithError(provider.New("test", "test")()),
		},
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
					provider "cortexcloud" {
						api_url    = "%s"
						api_key    = "test"
						api_key_id = 123
					}

					data "cortexcloud_user" "u" {
						user_email = "test@example.com"
					}
				`, server.URL),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("data.cortexcloud_user.u", "user_email", "test@example.com"),
					resource.TestCheckResourceAttr("data.cortexcloud_user.u", "status", "active"),
					// Computed group_ids must be populated from the user's groups,
					// proving the data source no longer crashes on this field.
					resource.TestCheckResourceAttr("data.cortexcloud_user.u", "group_ids.#", "2"),
					resource.TestCheckResourceAttr("data.cortexcloud_user.u", "group_ids.0", "11111111-1111-1111-1111-111111111111"),
					resource.TestCheckResourceAttr("data.cortexcloud_user.u", "group_ids.1", "22222222-2222-2222-2222-222222222222"),
					// The nested groups list should still be populated.
					resource.TestCheckResourceAttr("data.cortexcloud_user.u", "groups.#", "2"),
					resource.TestCheckResourceAttr("data.cortexcloud_user.u", "groups.0.group_name", "security-team"),
				),
			},
		},
	})
}
