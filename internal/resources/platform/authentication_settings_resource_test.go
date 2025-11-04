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

func TestUnitAuthenticationSettingsResource(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			if strings.HasSuffix(r.URL.String(), "/create") || strings.HasSuffix(r.URL.String(), "/delete") {
				w.WriteHeader(http.StatusOK)
				fmt.Fprintln(w, `{ "reply": true }`) //nolint:errcheck
				return
			} else if strings.HasSuffix(r.URL.String(), "/get/settings") {
				w.WriteHeader(http.StatusOK)
				//nolint:errcheck
				fmt.Fprintln(w, `
				{
					"reply": [
						{
							"tenant_id": "0123456789012",
							"name": "test-auth-settings",
							"domain": "test.domain",
							"idp_enabled": true,
							"default_role": "Instance Administrator",
							"is_account_role": false,
							"idp_certificate": "",
							"idp_issuer": "",
							"idp_sso_url": "",
							"metadata_url": "http://test.com/metadata",
							"mappings": {
								"email": "email",
								"firstname": "firstName",
								"lastname": "lastName",
								"group_name": "groupName"
							},
							"advanced_settings": {
								"relay_state": "",
								"idp_single_logout_url":"",
								"service_provider_public_cert": "",
								"service_provider_private_key": "",
								"authn_context_enabled": false,
								"force_authn": null
							},
							"sp_entity_id":"",
							"sp_logout_url": "",
							"sp_url": ""
						}
					]
				}`)
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
					resource "cortexcloud_authentication_settings" "test" {
						name   = "test-auth-settings"
						domain = "test.domain"
						default_role = "Instance Administrator"
						mappings = {
							email      = "email"
							first_name = "firstName"
							last_name  = "lastName"
							group_name = "groupName"
						}
					}
				`, server.URL),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("cortexcloud_authentication_settings.test", "name", "test-auth-settings"),
					resource.TestCheckResourceAttr("cortexcloud_authentication_settings.test", "domain", "test.domain"),
				),
			},
		},
	})
}
