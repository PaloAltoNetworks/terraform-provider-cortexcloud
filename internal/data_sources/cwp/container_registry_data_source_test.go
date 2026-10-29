// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package cwp_test

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

const registryDSPath = "/public_api/v1/cwp/registry_onboarding/instances"

func TestUnitContainerRegistryDataSource(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.TrimSuffix(r.URL.Path, "/") != registryDSPath+"/conn-1" || r.Method != http.MethodGet {
			http.Error(w, "not found: "+r.URL.Path, http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{
			"connector_id": "conn-1",
			"vendor": "DOCKER_HUB",
			"name": "dockerhub",
			"enabled": true,
			"url": "https://registry-1.docker.io",
			"username": "svc",
			"password": "********",
			"auth_token": "",
			"scanning_mode": "CLOUD",
			"cloud_provider": "AWS",
			"region": "us-east-1",
			"insecure_pull": false,
			"initial_scan_configuration": {"mode": "ALL"},
			"filter_type": "INCLUDE",
			"vendor_specific_configuration": {"repository": "my-repo"},
			"tenant_id": "tenant-1"
		}`)
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
  api_url    = %q
  api_key    = "test"
  api_key_id = 123
}

data "cortexcloud_container_registry" "test" {
  id = "conn-1"
}
`, server.URL),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("data.cortexcloud_container_registry.test", "vendor", "DOCKER_HUB"),
					resource.TestCheckResourceAttr("data.cortexcloud_container_registry.test", "name", "dockerhub"),
					resource.TestCheckResourceAttr("data.cortexcloud_container_registry.test", "tenant_id", "tenant-1"),
					// The API never returns real secrets; the data source must not expose the mask.
					resource.TestCheckNoResourceAttr("data.cortexcloud_container_registry.test", "password"),
					resource.TestCheckNoResourceAttr("data.cortexcloud_container_registry.test", "auth_token"),
					resource.TestCheckResourceAttr("data.cortexcloud_container_registry.test", "docker_hub.repository", "my-repo"),
					resource.TestCheckResourceAttr("data.cortexcloud_container_registry.test", "initial_scan_configuration.mode", "ALL"),
				),
			},
		},
	})
}
