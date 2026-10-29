// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package cwp_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/provider"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

const registryPath = "/public_api/v1/cwp/registry_onboarding/instances"

var protoV6Factories = map[string]func() (tfprotov6.ProviderServer, error){
	"cortexcloud": providerserver.NewProtocol6WithError(provider.New("test", "test")()),
}

// fakeRegistryAPI is an in-memory registry onboarding API. It stores the last
// body written for each connector and echoes it back on GET with the secrets
// masked, the way a real API that does not return credentials would.
type fakeRegistryAPI struct {
	mu         sync.Mutex
	connectors map[string]map[string]any
	nextID     int
	requests   []recordedRequest

	// assignedOutpostID, when set, is stored on create for connectors that did
	// not send an outpost_id, the way the real API assigns one for CLOUD scanning.
	assignedOutpostID string
}

type recordedRequest struct {
	method string
	path   string
	body   map[string]any
}

func newFakeRegistryAPI() *fakeRegistryAPI {
	return &fakeRegistryAPI{connectors: map[string]map[string]any{}}
}

func (f *fakeRegistryAPI) handler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()

		path := strings.TrimSuffix(strings.ReplaceAll(r.URL.Path, "//", "/"), "/")
		var body map[string]any
		if raw, _ := io.ReadAll(r.Body); len(raw) > 0 {
			if err := json.Unmarshal(raw, &body); err != nil {
				t.Errorf("request body is not JSON: %v", err)
			}
		}
		f.requests = append(f.requests, recordedRequest{method: r.Method, path: path, body: body})

		w.Header().Set("Content-Type", "application/json")
		notFound := func() {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"err_msg":"Connector ID not found","metadata":{"code":"NOT_FOUND"}}`))
		}

		switch {
		case path == registryPath && r.Method == http.MethodPost:
			f.nextID++
			id := fmt.Sprintf("conn-%d", f.nextID)
			body["connector_id"] = id
			body["tenant_id"] = "tenant-1"
			if existing, _ := body["outpost_id"].(string); existing == "" && f.assignedOutpostID != "" {
				body["outpost_id"] = f.assignedOutpostID
			}
			f.connectors[id] = body
			w.WriteHeader(http.StatusCreated)
			_, _ = fmt.Fprintf(w, `{"connector_id":%q}`, id)

		case strings.HasPrefix(path, registryPath+"/"):
			id := strings.TrimPrefix(path, registryPath+"/")
			stored, ok := f.connectors[id]
			if !ok {
				notFound()
				return
			}
			switch r.Method {
			case http.MethodGet:
				out := map[string]any{}
				for k, v := range stored {
					out[k] = v
				}
				out["password"] = "********"
				out["auth_token"] = ""
				_ = json.NewEncoder(w).Encode(out)
			case http.MethodPut:
				body["connector_id"] = id
				body["tenant_id"] = stored["tenant_id"]
				f.connectors[id] = body
				w.WriteHeader(http.StatusNoContent)
			case http.MethodDelete:
				delete(f.connectors, id)
				w.WriteHeader(http.StatusNoContent)
			default:
				w.WriteHeader(http.StatusMethodNotAllowed)
			}

		default:
			notFound()
		}
	}
}

func (f *fakeRegistryAPI) lastBody(method string) map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := len(f.requests) - 1; i >= 0; i-- {
		if f.requests[i].method == method {
			return f.requests[i].body
		}
	}
	return nil
}

func (f *fakeRegistryAPI) deleteOutOfBand(id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.connectors, id)
}

func providerBlock(url string) string {
	return fmt.Sprintf(`
provider "cortexcloud" {
  api_url    = %q
  api_key    = "test"
  api_key_id = 123
}
`, url)
}

func TestUnitContainerRegistryResource_Lifecycle(t *testing.T) {
	api := newFakeRegistryAPI()
	server := httptest.NewServer(api.handler(t))
	defer server.Close()

	create := providerBlock(server.URL) + `
resource "cortexcloud_container_registry" "test" {
  vendor        = "DOCKER_HUB"
  name          = "dockerhub"
  url           = "https://registry-1.docker.io"
  username      = "svc"
  password      = "s3cret"
  scanning_mode = "CLOUD"
  cloud_provider = "AWS"
  region        = "us-east-1"

  initial_scan_configuration = {
    mode     = "TAGS_MODIFIED_DAYS"
    num_days = 7
  }

  docker_hub = {
    repository = "my-repo"
  }
}
`
	update := strings.Replace(create, `name          = "dockerhub"`, `name          = "dockerhub-renamed"`, 1)
	replace := strings.Replace(strings.Replace(update, `"DOCKER_HUB"`, `"HARBOR"`, 1),
		"docker_hub = {\n    repository = \"my-repo\"\n  }", "", 1)

	resource.Test(t, resource.TestCase{
		IsUnitTest:               true,
		ProtoV6ProviderFactories: protoV6Factories,
		Steps: []resource.TestStep{
			{
				Config: create,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("cortexcloud_container_registry.test", "id", "conn-1"),
					resource.TestCheckResourceAttr("cortexcloud_container_registry.test", "tenant_id", "tenant-1"),
					resource.TestCheckResourceAttr("cortexcloud_container_registry.test", "enabled", "true"),
					resource.TestCheckResourceAttr("cortexcloud_container_registry.test", "insecure_pull", "false"),
					resource.TestCheckResourceAttr("cortexcloud_container_registry.test", "filter_type", "INCLUDE"),
					// The masked value returned by GET must not replace the configured secret.
					resource.TestCheckResourceAttr("cortexcloud_container_registry.test", "password", "s3cret"),
					resource.TestCheckResourceAttr("cortexcloud_container_registry.test", "initial_scan_configuration.num_days", "7"),
					resource.TestCheckResourceAttr("cortexcloud_container_registry.test", "docker_hub.repository", "my-repo"),
				),
			},
			{
				// Re-applying the same config must be a no-op: no permanent diff from
				// secrets, defaults or empty optional strings.
				Config: create,
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
			},
			{
				Config: update,
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction("cortexcloud_container_registry.test", plancheck.ResourceActionUpdate),
					},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("cortexcloud_container_registry.test", "id", "conn-1"),
					resource.TestCheckResourceAttr("cortexcloud_container_registry.test", "name", "dockerhub-renamed"),
					func(_ *terraform.State) error {
						// PUT is a full replacement: credentials and the vendor block must be sent.
						body := api.lastBody(http.MethodPut)
						if body == nil {
							return fmt.Errorf("no PUT request was sent")
						}
						if body["password"] != "s3cret" {
							return fmt.Errorf("PUT password = %v, want the configured secret", body["password"])
						}
						if body["name"] != "dockerhub-renamed" {
							return fmt.Errorf("PUT name = %v", body["name"])
						}
						vsc, _ := body["vendor_specific_configuration"].(map[string]any)
						if vsc["repository"] != "my-repo" {
							return fmt.Errorf("PUT vendor_specific_configuration = %v", body["vendor_specific_configuration"])
						}
						isc, _ := body["initial_scan_configuration"].(map[string]any)
						if isc["numDays"] != float64(7) {
							return fmt.Errorf("PUT initial_scan_configuration = %v", isc)
						}
						return nil
					},
				),
			},
			{
				// Changing vendor replaces the connector.
				Config: replace,
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction("cortexcloud_container_registry.test", plancheck.ResourceActionDestroyBeforeCreate),
					},
				},
				Check: resource.TestCheckResourceAttr("cortexcloud_container_registry.test", "id", "conn-2"),
			},
			{
				ResourceName:            "cortexcloud_container_registry.test",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"password", "auth_token"},
			},
		},
	})
}

// Regression: the API assigns an outpost_id for CLOUD scanning even though the
// user never configured one. outpost_id must therefore be Computed, otherwise
// Terraform fails with "Provider produced inconsistent result after apply:
// .outpost_id: was null, but now cty.StringVal(...)".
func TestUnitContainerRegistryResource_ServerAssignedOutpostID(t *testing.T) {
	api := newFakeRegistryAPI()
	api.assignedOutpostID = "f91ea8cef6f845439fce6adc0c52bfe2"
	server := httptest.NewServer(api.handler(t))
	defer server.Close()

	config := providerBlock(server.URL) + `
resource "cortexcloud_container_registry" "test" {
  vendor         = "DOCKER"
  name           = "ecr"
  url            = "https://789934945814.dkr.ecr.us-east-2.amazonaws.com"
  username       = "AWS"
  password       = "s3cret"
  scanning_mode  = "CLOUD"
  cloud_provider = "AWS"
  region         = "us-east-2"

  initial_scan_configuration = {
    mode     = "TAGS_MODIFIED_DAYS"
    num_days = 7
  }
}
`

	resource.Test(t, resource.TestCase{
		IsUnitTest:               true,
		ProtoV6ProviderFactories: protoV6Factories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.TestCheckResourceAttr(
					"cortexcloud_container_registry.test", "outpost_id", "f91ea8cef6f845439fce6adc0c52bfe2"),
			},
			{
				// The server-assigned value must not cause a permanent diff.
				Config: config,
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
			},
			{
				// An update that keeps scanning_mode must keep sending the
				// server-assigned outpost_id in the full-replacement PUT.
				Config: strings.Replace(config, `name           = "ecr"`, `name           = "ecr-renamed"`, 1),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(
						"cortexcloud_container_registry.test", "outpost_id", "f91ea8cef6f845439fce6adc0c52bfe2"),
					func(_ *terraform.State) error {
						body := api.lastBody(http.MethodPut)
						if body == nil {
							return fmt.Errorf("no PUT request was sent")
						}
						if body["outpost_id"] != "f91ea8cef6f845439fce6adc0c52bfe2" {
							return fmt.Errorf("PUT outpost_id = %v, want the server-assigned value", body["outpost_id"])
						}
						return nil
					},
				),
			},
		},
	})
}

// Regression (MR !201 review): registry_type was Optional+Computed with
// UseStateForUnknown, so removing it from config kept planning the old value
// and the user had no way to clear it. It is now plain Optional.
func TestUnitContainerRegistryResource_RegistryTypeCanBeCleared(t *testing.T) {
	api := newFakeRegistryAPI()
	server := httptest.NewServer(api.handler(t))
	defer server.Close()

	cfg := func(extra string) string {
		return providerBlock(server.URL) + fmt.Sprintf(`
resource "cortexcloud_container_registry" "test" {
  vendor        = "HARBOR"
  name          = "harbor"
  url           = "https://harbor.example.com"
  auth_token    = "tok"
  scanning_mode = "OUTPOST"
  outpost_id    = "op-1"
%s

  initial_scan_configuration = {
    mode = "ALL"
  }
}
`, extra)
	}
	withType := cfg(`  registry_type = "SELF_HOSTED"`)
	withoutType := cfg("")

	resource.Test(t, resource.TestCase{
		IsUnitTest:               true,
		ProtoV6ProviderFactories: protoV6Factories,
		Steps: []resource.TestStep{
			{
				Config: withType,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("cortexcloud_container_registry.test", "registry_type", "SELF_HOSTED"),
					func(_ *terraform.State) error {
						if got := api.lastBody(http.MethodPost)["registry_type"]; got != "SELF_HOSTED" {
							return fmt.Errorf("POST registry_type = %v, want SELF_HOSTED", got)
						}
						return nil
					},
				),
			},
			{
				Config: withoutType,
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction("cortexcloud_container_registry.test", plancheck.ResourceActionUpdate),
						plancheck.ExpectKnownValue("cortexcloud_container_registry.test",
							tfjsonpath.New("registry_type"), knownvalue.Null()),
					},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckNoResourceAttr("cortexcloud_container_registry.test", "registry_type"),
					func(_ *terraform.State) error {
						body := api.lastBody(http.MethodPut)
						if body == nil {
							return fmt.Errorf("no PUT request was sent")
						}
						if v, ok := body["registry_type"]; ok {
							return fmt.Errorf("PUT registry_type = %v, want it omitted after removal from config", v)
						}
						return nil
					},
				),
			},
			{
				Config: withoutType,
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
			},
		},
	})
}

// Regression (MR !201 review): outpost_id was planned with UseStateForUnknown,
// so after switching OUTPOST -> BROKER and removing outpost_id from config the
// old outpost ID was still sent in the full-replacement PUT.
func TestUnitContainerRegistryResource_ScanningModeChangeDropsOutpostID(t *testing.T) {
	api := newFakeRegistryAPI()
	server := httptest.NewServer(api.handler(t))
	defer server.Close()

	// Build both configs from one template rather than string-replacing, so the
	// test does not depend on whitespace in the HCL.
	cfg := func(scanning string) string {
		return providerBlock(server.URL) + fmt.Sprintf(`
resource "cortexcloud_container_registry" "test" {
	 vendor     = "HARBOR"
	 name       = "harbor"
	 url        = "https://harbor.example.com"
	 auth_token = "tok"
%s

	 initial_scan_configuration = {
	   mode = "ALL"
	 }
}
`, scanning)
	}
	outpost := cfg(`
	 scanning_mode = "OUTPOST"
	 outpost_id    = "op-1"`)
	broker := cfg(`
	 scanning_mode = "BROKER"
	 broker_type   = "BROKER_VM"
	 broker_id     = "br-1"`)

	resource.Test(t, resource.TestCase{
		IsUnitTest:               true,
		ProtoV6ProviderFactories: protoV6Factories,
		Steps: []resource.TestStep{
			{
				Config: outpost,
				Check:  resource.TestCheckResourceAttr("cortexcloud_container_registry.test", "outpost_id", "op-1"),
			},
			{
				Config: broker,
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction("cortexcloud_container_registry.test", plancheck.ResourceActionUpdate),
						plancheck.ExpectUnknownValue("cortexcloud_container_registry.test", tfjsonpath.New("outpost_id")),
					},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("cortexcloud_container_registry.test", "scanning_mode", "BROKER"),
					resource.TestCheckNoResourceAttr("cortexcloud_container_registry.test", "outpost_id"),
					func(_ *terraform.State) error {
						body := api.lastBody(http.MethodPut)
						if body == nil {
							return fmt.Errorf("no PUT request was sent")
						}
						if v, ok := body["outpost_id"]; ok {
							return fmt.Errorf("PUT outpost_id = %v, want it omitted after leaving OUTPOST mode", v)
						}
						if body["scanning_mode"] != "BROKER" {
							return fmt.Errorf("PUT scanning_mode = %v", body["scanning_mode"])
						}
						return nil
					},
				),
			},
			{
				// The new state must be stable.
				Config: broker,
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
			},
		},
	})
}

func TestUnitContainerRegistryResource_RemovedOutOfBand(t *testing.T) {
	api := newFakeRegistryAPI()
	server := httptest.NewServer(api.handler(t))
	defer server.Close()

	config := providerBlock(server.URL) + `
resource "cortexcloud_container_registry" "test" {
  vendor        = "HARBOR"
  name          = "harbor"
  url           = "https://harbor.example.com"
  auth_token    = "tok"
  scanning_mode = "OUTPOST"
  outpost_id    = "op-1"

  initial_scan_configuration = {
    mode = "ALL"
  }
}
`
	resource.Test(t, resource.TestCase{
		IsUnitTest:               true,
		ProtoV6ProviderFactories: protoV6Factories,
		Steps: []resource.TestStep{
			{Config: config},
			{
				// A connector deleted outside Terraform must be planned for re-creation,
				// not fail the refresh.
				PreConfig: func() { api.deleteOutOfBand("conn-1") },
				Config:    config,
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction("cortexcloud_container_registry.test", plancheck.ResourceActionCreate),
					},
				},
				Check: resource.TestCheckResourceAttr("cortexcloud_container_registry.test", "id", "conn-2"),
			},
		},
	})
}

func TestUnitContainerRegistryResource_Validation(t *testing.T) {
	base := func(body string) string {
		return providerBlock("http://127.0.0.1:1") + `
resource "cortexcloud_container_registry" "test" {
  name = "r"
  url  = "https://r.example.com"
` + body + `
}
`
	}

	tests := []struct {
		name   string
		config string
		want   string
	}{
		{
			name: "cloud mode requires cloud_provider and region",
			config: base(`
  vendor        = "HARBOR"
  scanning_mode = "CLOUD"
  initial_scan_configuration = { mode = "ALL" }
`),
			want: `"cloud_provider" is required when scanning_mode is "CLOUD"`,
		},
		{
			name: "outpost mode requires outpost_id",
			config: base(`
  vendor        = "HARBOR"
  scanning_mode = "OUTPOST"
  initial_scan_configuration = { mode = "ALL" }
`),
			want: `"outpost_id" is required when scanning_mode is "OUTPOST"`,
		},
		{
			name: "broker mode requires broker_type and broker_id",
			config: base(`
  vendor        = "HARBOR"
  scanning_mode = "BROKER"
  broker_type   = "BROKER_VM"
  initial_scan_configuration = { mode = "ALL" }
`),
			want: `"broker_id" is required when scanning_mode is "BROKER"`,
		},
		{
			name: "TAGS_MODIFIED_DAYS requires num_days",
			config: base(`
  vendor        = "HARBOR"
  scanning_mode = "KAPI"
  initial_scan_configuration = { mode = "TAGS_MODIFIED_DAYS" }
`),
			want: `num_days is required when initial_scan_configuration.mode is\s+TAGS_MODIFIED_DAYS`,
		},
		{
			name: "num_days only with TAGS_MODIFIED_DAYS",
			config: base(`
  vendor        = "HARBOR"
  scanning_mode = "KAPI"
  initial_scan_configuration = {
    mode     = "ALL"
    num_days = 5
  }
`),
			want: `num_days is only allowed when initial_scan_configuration.mode is`,
		},
		{
			name: "num_days range",
			config: base(`
  vendor        = "HARBOR"
  scanning_mode = "KAPI"
  initial_scan_configuration = {
    mode     = "TAGS_MODIFIED_DAYS"
    num_days = 91
  }
`),
			want: `value must be between 1 and 90`,
		},
		{
			name: "username without password",
			config: base(`
  vendor        = "HARBOR"
  scanning_mode = "KAPI"
  username      = "u"
  initial_scan_configuration = { mode = "ALL" }
`),
			want: `username and password must be set together`,
		},
		{
			name: "vendor block must match vendor",
			config: base(`
  vendor        = "HARBOR"
  scanning_mode = "KAPI"
  initial_scan_configuration = { mode = "ALL" }
  gitlab = { group_ids = "1" }
`),
			want: `"gitlab" is only valid when vendor is\s+"GITLAB_CONTAINER_REGISTRY"`,
		},
		{
			name: "unknown vendor rejected",
			config: base(`
  vendor        = "QUAY"
  scanning_mode = "KAPI"
  initial_scan_configuration = { mode = "ALL" }
`),
			want: `value must be one of`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resource.UnitTest(t, resource.TestCase{
				ProtoV6ProviderFactories: protoV6Factories,
				Steps: []resource.TestStep{{
					Config:      tc.config,
					PlanOnly:    true,
					ExpectError: regexp.MustCompile(tc.want),
				}},
			})
		})
	}
}
