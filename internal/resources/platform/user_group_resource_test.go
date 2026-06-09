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
			if strings.HasSuffix(r.URL.String(), "/user-group") {
				w.WriteHeader(http.StatusCreated)
				fmt.Fprintln(w, `{
					"data": {
						"message": "user group with group id test-group-1 created successfully"
					}
				}`) //nolint:errcheck
				return
			}
			// ListUsers endpoint (POST)
			if strings.HasSuffix(r.URL.String(), "/rbac/get_users/") {
				w.WriteHeader(http.StatusOK)
				//nolint:errcheck
				fmt.Fprintln(w, `{"reply": []}`)
				return
			}
		} else if r.Method == http.MethodGet {
			if strings.HasSuffix(r.URL.String(), "/user-group") {
				w.WriteHeader(http.StatusOK)
				//nolint:errcheck
				fmt.Fprintln(w, `{
					"data": [
						{
							"group_id": "test-group-1",
							"group_name": "test-group-1",
							"description": "This is a test user group.",
							"role_id": "test-role"
						}
					]
				}`)
				return
			}
		} else if r.Method == http.MethodPatch {
			if strings.Contains(r.URL.String(), "/user-group/") {
				w.WriteHeader(http.StatusOK)
				fmt.Fprintln(w, `{
					"data": {
						"message": "user group with group id test-group-1 updated successfully"
					}
				}`) //nolint:errcheck
				return
			}
		} else if r.Method == http.MethodDelete {
			if strings.Contains(r.URL.String(), "/user-group/") {
				w.WriteHeader(http.StatusOK)
				fmt.Fprintln(w, `{
					"data": {
						"message": "user group with group id test-group-1 deleted successfully"
					}
				}`) //nolint:errcheck
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
						group_name        = "test-group-1"
						description = "This is a test user group."
						role_id   = "test-role"
					}
				`, server.URL),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("cortexcloud_user_group.test", "group_name", "test-group-1"),
					resource.TestCheckResourceAttr("cortexcloud_user_group.test", "description", "This is a test user group."),
					resource.TestCheckResourceAttr("cortexcloud_user_group.test", "role_id", "test-role"),
				),
			},
		},
	})
}

// TestUnitUserGroupResourceSSOJITIntegration creates a new user group and
// simulates the association of new user principals via SSO JIT
// authentication to test the parsing of these values into the `users` and
// `all_users` attributes
func TestUnitUserGroupResourceSSOJITIntegration(t *testing.T) {
	// groupUpdated tracks whether the PATCH has been called. Before the update,
	// the group has 1 directly-configured user (CSP). After the PATCH, the API
	// also returns 2 SSO/JIT users — simulating users added via an IDP group.
	// The test verifies that:
	//   - step 1: users=["email1@test.com"], idp_users=[]
	//   - step 2: users=["email1@test.com"], idp_users=["email2@test.com","email3@test.com"]
	groupUpdated := false
	groupName := "test-group-1"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			if strings.HasSuffix(r.URL.String(), "/user-group") {
				w.WriteHeader(http.StatusCreated)
				fmt.Fprintln(w, `{
					"data": {
						"message": "user group with group id test-group-1 created successfully"
					}
				}`) //nolint:errcheck
				return
			}
			// ListUsers endpoint (POST)
			if strings.HasSuffix(r.URL.String(), "/rbac/get_users/") {
				w.WriteHeader(http.StatusOK)
				if groupUpdated {
					//nolint:errcheck
					fmt.Fprintln(w, `{
						"reply": [
							{"user_email": "email1@test.com", "user_type": "CSP"},
							{"user_email": "email2@test.com", "user_type": "SSO"},
							{"user_email": "email3@test.com", "user_type": "SSO"}
						]
					}`)
				} else {
					//nolint:errcheck
					fmt.Fprintln(w, `{
						"reply": [
							{"user_email": "email1@test.com", "user_type": "CSP"}
						]
					}`)
				}
				return
			}
		} else if r.Method == http.MethodGet {
			if strings.HasSuffix(r.URL.String(), "/user-group") {
				w.WriteHeader(http.StatusOK)

				var users string
				if groupUpdated {
					users = `["email1@test.com", "email2@test.com", "email3@test.com"]`
				} else {
					users = `["email1@test.com"]`
				}

				//nolint:errcheck
				fmt.Fprintf(w, `{
					"data": [
						{
							"group_id": "test-group-1",
							"group_name": %q,
							"description": "This is a test user group.",
							"role_id": "test-role",
							"users": %s,
							"idp_groups": ["test group"]
						}
					]
				}`, groupName, users)
				return
			}
		} else if r.Method == http.MethodPatch {
			if strings.Contains(r.URL.String(), "/user-group/") {
				groupUpdated = true
				groupName = "test-group-2"
				w.WriteHeader(http.StatusOK)
				fmt.Fprintln(w, `{
					"data": {
						"message": "user group updated successfully"
					}
				}`) //nolint:errcheck
				return
			}
		} else if r.Method == http.MethodDelete {
			if strings.Contains(r.URL.String(), "/user-group/") {
				w.WriteHeader(http.StatusOK)
				fmt.Fprintln(w, `{
					"data": {
						"message": "user group deleted successfully"
					}
				}`) //nolint:errcheck
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
						group_name        = "test-group-1"
						description = "This is a test user group."
						role_id   = "test-role"
						users = [
							"email1@test.com",
						]
						idp_groups = [ "test group" ]
					}
				`, server.URL),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("cortexcloud_user_group.test", "group_name", "test-group-1"),
					resource.TestCheckResourceAttr("cortexcloud_user_group.test", "description", "This is a test user group."),
					resource.TestCheckResourceAttr("cortexcloud_user_group.test", "role_id", "test-role"),
					resource.TestCheckResourceAttr("cortexcloud_user_group.test", "users.#", "1"),
					resource.TestCheckResourceAttr("cortexcloud_user_group.test", "users.0", "email1@test.com"),
					resource.TestCheckResourceAttr("cortexcloud_user_group.test", "idp_groups.#", "1"),
					resource.TestCheckResourceAttr("cortexcloud_user_group.test", "idp_groups.0", "test group"),
				),
			},
			{
				Config: fmt.Sprintf(`
					provider "cortexcloud" {
						api_url = "%s"
						api_key = "test"
						api_key_id = 123
					}
					resource "cortexcloud_user_group" "test" {
						group_name        = "test-group-2"
						description = "This is a test user group."
						role_id   = "test-role"
						users = [
							"email1@test.com",
						]
						idp_groups = [ "test group" ]
					}
				`, server.URL),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("cortexcloud_user_group.test", "group_name", "test-group-2"),
					resource.TestCheckResourceAttr("cortexcloud_user_group.test", "description", "This is a test user group."),
					resource.TestCheckResourceAttr("cortexcloud_user_group.test", "role_id", "test-role"),
					// users contains only the directly-configured CSP user
					resource.TestCheckResourceAttr("cortexcloud_user_group.test", "users.#", "1"),
					resource.TestCheckResourceAttr("cortexcloud_user_group.test", "users.0", "email1@test.com"),
					// all_users contains the configured user AND the
					// two SSO/JIT-added users
					resource.TestCheckResourceAttr("cortexcloud_user_group.test", "all_users.#", "3"),
					resource.TestCheckTypeSetElemAttr("cortexcloud_user_group.test", "all_users.*", "email2@test.com"),
					resource.TestCheckTypeSetElemAttr("cortexcloud_user_group.test", "all_users.*", "email3@test.com"),
					resource.TestCheckResourceAttr("cortexcloud_user_group.test", "idp_groups.#", "1"),
					resource.TestCheckResourceAttr("cortexcloud_user_group.test", "idp_groups.0", "test group"),
				),
			},
		},
	})
}
