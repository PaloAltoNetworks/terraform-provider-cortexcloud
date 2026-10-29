// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package platform_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/provider"
	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/resources/platform"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	fwresource "github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// TestUnitAuthenticationSettingsResource_ImportStateIDParsing exercises the
// "name,domain" import identifier parsing directly, including the default SSO
// case (empty domain) and names that contain commas.
func TestUnitAuthenticationSettingsResource_ImportStateIDParsing(t *testing.T) {
	ctx := context.Background()

	r, ok := platform.NewAuthenticationSettingsResource().(fwresource.ResourceWithImportState)
	if !ok {
		t.Fatal("authentication settings resource does not implement ResourceWithImportState")
	}

	schemaResp := &fwresource.SchemaResponse{}
	r.Schema(ctx, fwresource.SchemaRequest{}, schemaResp)
	if schemaResp.Diagnostics.HasError() {
		t.Fatalf("unexpected schema diagnostics: %v", schemaResp.Diagnostics)
	}

	tests := []struct {
		name           string
		id             string
		expectedName   string
		expectedDomain string
		expectError    bool
	}{
		{name: "default SSO with empty domain", id: "default-sso,", expectedName: "default-sso", expectedDomain: ""},
		{name: "name and domain", id: "corp-sso,example.com", expectedName: "corp-sso", expectedDomain: "example.com"},
		{name: "name containing comma", id: "Acme, Inc,example.com", expectedName: "Acme, Inc", expectedDomain: "example.com"},
		{name: "name containing comma with empty domain", id: "Acme, Inc,", expectedName: "Acme, Inc", expectedDomain: ""},
		{name: "missing separator", id: "no-separator", expectError: true},
		{name: "empty name", id: ",example.com", expectError: true},
		{name: "empty identifier", id: "", expectError: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp := &fwresource.ImportStateResponse{
				State: tfsdk.State{
					Schema: schemaResp.Schema,
					Raw:    tftypes.NewValue(schemaResp.Schema.Type().TerraformType(ctx), nil),
				},
			}

			r.ImportState(ctx, fwresource.ImportStateRequest{ID: tc.id}, resp)

			if tc.expectError {
				if !resp.Diagnostics.HasError() {
					t.Fatalf("expected an error for import ID %q, got none", tc.id)
				}
				if got := resp.Diagnostics.Errors()[0].Summary(); got != "Invalid Import Identifier" {
					t.Fatalf("expected error summary %q, got %q", "Invalid Import Identifier", got)
				}
				return
			}

			if resp.Diagnostics.HasError() {
				t.Fatalf("unexpected diagnostics for import ID %q: %v", tc.id, resp.Diagnostics)
			}

			var gotName, gotDomain types.String
			resp.Diagnostics.Append(resp.State.GetAttribute(ctx, path.Root("name"), &gotName)...)
			resp.Diagnostics.Append(resp.State.GetAttribute(ctx, path.Root("domain"), &gotDomain)...)
			if resp.Diagnostics.HasError() {
				t.Fatalf("unexpected diagnostics reading state: %v", resp.Diagnostics)
			}

			if gotName.ValueString() != tc.expectedName {
				t.Errorf("name: expected %q, got %q", tc.expectedName, gotName.ValueString())
			}
			if gotDomain.IsNull() {
				t.Errorf("domain: expected %q, got null", tc.expectedDomain)
			} else if gotDomain.ValueString() != tc.expectedDomain {
				t.Errorf("domain: expected %q, got %q", tc.expectedDomain, gotDomain.ValueString())
			}
		})
	}
}

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

	config := fmt.Sprintf(`
					provider "cortexcloud" {
						api_url    = "%s"
						api_key    = "test"
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
				`, server.URL)

	resource.Test(t, resource.TestCase{
		IsUnitTest: true,
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"cortexcloud": providerserver.NewProtocol6WithError(provider.New("test", "test")()),
		},
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("cortexcloud_authentication_settings.test", "name", "test-auth-settings"),
					resource.TestCheckResourceAttr("cortexcloud_authentication_settings.test", "domain", "test.domain"),
				),
			},
			// Import using the "name,domain" identifier.
			{
				Config:            config,
				ResourceName:      "cortexcloud_authentication_settings.test",
				ImportState:       true,
				ImportStateId:     "test-auth-settings,test.domain",
				ImportStateVerify: true,
				// This resource has no "id" attribute; "name" identifies it.
				ImportStateVerifyIdentifierAttribute: "name",
			},
			// Malformed import identifier (missing the domain separator).
			{
				Config:        config,
				ResourceName:  "cortexcloud_authentication_settings.test",
				ImportState:   true,
				ImportStateId: "test-auth-settings",
				ExpectError:   regexp.MustCompile(`Invalid Import Identifier`),
			},
			// Malformed import identifier (empty name).
			{
				Config:        config,
				ResourceName:  "cortexcloud_authentication_settings.test",
				ImportState:   true,
				ImportStateId: ",test.domain",
				ExpectError:   regexp.MustCompile(`Invalid Import Identifier`),
			},
		},
	})
}

// TestUnitAuthenticationSettingsResource_ImportNameWithComma verifies that an
// SSO integration whose name contains a comma can be imported. The import
// identifier is split on the last comma because only the name (free text) can
// contain commas; email domains cannot.
func TestUnitAuthenticationSettingsResource_ImportNameWithComma(t *testing.T) {
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
							"name": "Acme, Inc SSO",
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

	config := fmt.Sprintf(`
					provider "cortexcloud" {
						api_url    = "%s"
						api_key    = "test"
						api_key_id = 123
					}
					resource "cortexcloud_authentication_settings" "test" {
						name   = "Acme, Inc SSO"
						domain = "test.domain"
						default_role = "Instance Administrator"
						mappings = {
							email      = "email"
							first_name = "firstName"
							last_name  = "lastName"
							group_name = "groupName"
						}
					}
				`, server.URL)

	resource.Test(t, resource.TestCase{
		IsUnitTest: true,
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"cortexcloud": providerserver.NewProtocol6WithError(provider.New("test", "test")()),
		},
		Steps: []resource.TestStep{
			{
				Config: config,
			},
			{
				Config:                               config,
				ResourceName:                         "cortexcloud_authentication_settings.test",
				ImportState:                          true,
				ImportStateId:                        "Acme, Inc SSO,test.domain",
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: "name",
			},
		},
	})
}
