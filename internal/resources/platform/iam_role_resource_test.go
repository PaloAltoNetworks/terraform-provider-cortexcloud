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

func TestUnitIamRoleResource(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		for strings.Contains(path, "//") {
			path = strings.ReplaceAll(path, "//", "/")
		}
		if strings.HasSuffix(path, "/") && path != "/" {
			path = strings.TrimSuffix(path, "/")
		}

		switch {
		case path == "/platform/iam/v1/role" && r.Method == http.MethodPost:
			w.WriteHeader(http.StatusCreated)
			fmt.Fprintln(w, `{
				"data": {
					"message": "role_id test-role-id created successfully."
				}
			}`)

		case path == "/platform/iam/v1/role" && r.Method == http.MethodGet:
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, `{
				"data": [
					{
						"role_id": "test-role-id",
						"pretty_name": "test-role",
						"description": "test role description",
						"is_custom": true,
						"created_by": "test-user",
						"created_ts": 1678886400000,
						"updated_ts": 1678886400000
					}
				],
				"metadata": { "total_count": 1 }
			}`)

		// Delete：/platform/iam/v1/role/{role_id}
		case path == "/platform/iam/v1/role/test-role-id" && r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusOK)

		default:
			http.Error(w, "not found: "+r.URL.Path, http.StatusNotFound)
		}
	}))
	defer server.Close()

	resource.Test(t, resource.TestCase{
		IsUnitTest: true,
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"cortexcloud": providerserver.NewProtocol6WithError(provider.New("test")()),
		},
		Steps: []resource.TestStep{
			// Step 1: Create
			{
				Config: fmt.Sprintf(`
					provider "cortexcloud" {
						api_url    = "%s"
						api_key    = "test"
						api_key_id = 123
					}
					resource "cortexcloud_iam_role" "test" {
						pretty_name           = "test-role"
						description           = "test role description"
						component_permissions = ["perm1", "perm2"]
					}
				`, server.URL),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("cortexcloud_iam_role.test", "id", "test-role-id"),
					resource.TestCheckResourceAttr("cortexcloud_iam_role.test", "pretty_name", "test-role"),
					resource.TestCheckResourceAttr("cortexcloud_iam_role.test", "description", "test role description"),
				),
			},
			// Step 2: Refresh
			{
				ResourceName: "cortexcloud_iam_role.test",
				RefreshState: true,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("cortexcloud_iam_role.test", "id", "test-role-id"), // ID 保持不变
					resource.TestCheckResourceAttr("cortexcloud_iam_role.test", "is_custom", "true"),
					resource.TestCheckResourceAttr("cortexcloud_iam_role.test", "created_by", "test-user"),
					resource.TestCheckResourceAttr("cortexcloud_iam_role.test", "created_ts", "1678886400000"),
					resource.TestCheckResourceAttr("cortexcloud_iam_role.test", "updated_ts", "1678886400000"),
				),
			},
		},
	})
}
