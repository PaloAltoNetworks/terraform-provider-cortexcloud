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

func TestUnitUserResource(t *testing.T) {
	var edited atomic.Bool

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && strings.Contains(r.URL.String(), "/user") {
			w.WriteHeader(http.StatusOK)
			if !edited.Load() {
				_, _ = fmt.Fprintln(w, `{
                "data": {
                    "user_email": "test@example.com",
                    "phone_number": "123-456-7890",
                    "status": "ACTIVE",
                    "hidden": false
                }
            }`)
				return
			}
			_, _ = fmt.Fprintln(w, `{
            "data": {
                "user_email": "test@example.com",
                "phone_number": "123-456-7890",
                "status": "ACTIVE",
                "hidden": false
            }
        }`)
			return
		}

		if r.Method == http.MethodPatch && strings.Contains(r.URL.String(), "/user") {
			bodyBytes, _ := io.ReadAll(r.Body)
			r.Body = io.NopCloser(bytes.NewReader(bodyBytes))

			if strings.Contains(string(bodyBytes), `"Jane"`) {
				edited.Store(true)
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprintln(w, `{"data":{"message":"user updated successfully"}}`)
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

					resource "cortexcloud_user" "u" {
						user_email      = "test@example.com"
						phone_number    = "123-456-7890"
						status          = "ACTIVE"
						hidden          = false
					}
				`, server.URL),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("cortexcloud_user.u", "user_email", "test@example.com"),
					resource.TestCheckResourceAttr("cortexcloud_user.u", "status", "ACTIVE"),
					resource.TestCheckResourceAttr("cortexcloud_user.u", "hidden", "false"),
				),
			},
			{
				Config: fmt.Sprintf(`
					provider "cortexcloud" {
						api_url   = "%s"
						api_key   = "test"
						api_key_id = 123
					}

					resource "cortexcloud_user" "u" {
						user_email      = "test@example.com"
						phone_number    = "123-456-7890"
						status          = "ACTIVE"
						hidden          = false
					}
				`, server.URL),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("cortexcloud_user.u", "user_email", "test@example.com"),
				),
			},
		},
	})
}
