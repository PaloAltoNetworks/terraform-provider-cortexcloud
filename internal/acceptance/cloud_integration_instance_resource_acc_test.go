// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package acceptance

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"testing"

	"github.com/PaloAltoNetworks/cortex-cloud-go/cloudonboarding"
	cloudOnboardingTypes "github.com/PaloAltoNetworks/cortex-cloud-go/types/cloudonboarding"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

// cloudIntegrationInstanceResourceType is the Terraform resource type under test.
const cloudIntegrationInstanceResourceType = "cortexcloud_cloud_integration_instance"

// cloudIntegrationInstanceInstanceIDEnvVar names the environment variable that
// supplies the ID of an existing, CONNECTED cloud integration instance to adopt
// into Terraform state via import. The value is never hard-coded: the test is
// skipped when it is unset (see TestAccCloudIntegrationInstance_inPlaceUpdate).
const cloudIntegrationInstanceInstanceIDEnvVar = "TEST_CLOUD_INTEGRATION_INSTANCE_ID"

// cloudIntegrationInstanceCloudProviderEnvVar names the optional environment
// variable that supplies the cloud_provider value matching the instance under
// test ("AWS", "AZURE", or "GCP"). When unset it defaults to "AWS".
const cloudIntegrationInstanceCloudProviderEnvVar = "TEST_CLOUD_INTEGRATION_INSTANCE_CLOUD_PROVIDER"

// cloudIntegrationInstanceEditReadBackEnvVar gates the live edit read-back
// assertion, which applies a real edit_instance call against the instance named
// by TEST_CLOUD_INTEGRATION_INSTANCE_ID and asserts the toggled value round
// trips. It is opt-in because it mutates a live tenant.
//
// One backend precondition applies. edit_instance rejects a null or omitted
// custom_resources_tags with HTTP 422, but crashes with HTTP 500 when the field
// is an empty list; only a non-empty list is accepted. The provider merges the
// live tags into the request, so the edit succeeds whenever the target instance
// carries at least one tag (instances carry managed_by by default). Against an
// instance with zero tags the request necessarily contains an empty list and the
// backend returns 500 — a server-side defect for which no client-side payload is
// valid. Point this test at a tagged instance.
const cloudIntegrationInstanceEditReadBackEnvVar = "TEST_CLOUD_INTEGRATION_INSTANCE_EDIT_READBACK"

// cloudIntegrationInstanceConfigTmpl renders a minimal resource configuration.
//
// The config declares only id, cloud_provider, and the additional_capabilities
// block that the test toggles. Write-only attributes (cloud_partition,
// scope_modifications) are intentionally omitted: they are not returned by the
// platform, are not refreshed into state, and are not needed to prove the
// in-place update behavior.
const cloudIntegrationInstanceConfigTmpl = `
resource "%s" "test" {
  id             = %q
  cloud_provider = %q

  additional_capabilities = {
    serverless_scanning = %t
  }
}
`

// TestAccCloudIntegrationInstance_inPlaceUpdate is the regression guard for
// in-place edits: toggling additional_capabilities on a connected cloud
// integration instance must be applied as an IN-PLACE update (via the
// platform's edit_instance API) and must NEVER force a destroy-and-recreate.
//
// Import-only lifecycle
// ---------------------
// This resource does not provision new instances. Its Create implementation
// returns an actionable "import required" error, so a create-driven acceptance
// test is impossible. Instead the test adopts a pre-existing, CONNECTED instance
// into state with `terraform import` (import-first via ImportStateId +
// ImportStatePersist), and then exercises an in-place edit against it.
//
// Because a real, connected instance is required, the test reads its ID from the
// TEST_CLOUD_INTEGRATION_INSTANCE_ID environment variable and SKIPS when that is
// unset (mirroring how other acceptance tests skip when their required inputs
// are absent). No instance ID is ever hard-coded.
//
// V0 unknown (documented, not yet verified live): it is not yet confirmed
// whether the platform's edit_instance API operates on PENDING instances or only
// on CONNECTED ones. This test therefore requires a CONNECTED instance ID; if a
// PENDING instance is supplied the edit step's behavior is undefined.
//
// The KEY assertion is the PreApply plan check
// plancheck.ExpectResourceAction(..., plancheck.ResourceActionUpdate): it fails
// the test if the plan is a replacement (DestroyBeforeCreate / CreateBeforeDestroy)
// instead of an in-place update. That is precisely what the fix must guarantee.
func TestAccCloudIntegrationInstance_inPlaceUpdate(t *testing.T) {
	instanceID := os.Getenv(cloudIntegrationInstanceInstanceIDEnvVar)
	if instanceID == "" {
		t.Skipf(
			"Skipping: %s must be set to the ID of an existing CONNECTED cloud "+
				"integration instance. This resource has an import-only "+
				"lifecycle (Create returns an import-required error), so a real "+
				"connected instance is required to exercise the in-place edit.",
			cloudIntegrationInstanceInstanceIDEnvVar,
		)
	}

	cloudProvider := os.Getenv(cloudIntegrationInstanceCloudProviderEnvVar)
	if cloudProvider == "" {
		cloudProvider = "AWS"
	}

	providerConfig := getProviderConfig(t, dotEnvPath, true)

	resourceName := fmt.Sprintf("%s.test", cloudIntegrationInstanceResourceType)

	// The toggle direction is derived from the instance's live state rather than
	// hard-coded, so the test does not silently degrade to a no-op plan when a
	// previous run left serverless_scanning already enabled.
	live := readLiveInstance(t, instanceID)
	currentServerless := live.AdditionalCapabilities.ServerlessScanning != nil &&
		*live.AdditionalCapabilities.ServerlessScanning
	targetServerless := !currentServerless

	configCurrent := fmt.Sprintf(
		cloudIntegrationInstanceConfigTmpl,
		cloudIntegrationInstanceResourceType,
		instanceID,
		cloudProvider,
		currentServerless,
	)
	configToggled := fmt.Sprintf(
		cloudIntegrationInstanceConfigTmpl,
		cloudIntegrationInstanceResourceType,
		instanceID,
		cloudProvider,
		targetServerless,
	)

	// Capabilities the config never declares. Under edit_instance's full-replace
	// semantics these must survive the edit; if the provider stops merging live
	// state they are silently disabled, which is the data-loss regression this
	// guards against.
	undeclaredBefore := map[string]*bool{
		"xsiam_analytics":                  live.AdditionalCapabilities.XSIAMAnalytics,
		"data_security_posture_management": live.AdditionalCapabilities.DataSecurityPostureManagement,
		"registry_scanning":                live.AdditionalCapabilities.RegistryScanning,
		"agentless_disk_scanning":          live.AdditionalCapabilities.AgentlessDiskScanning,
	}

	// The live edit read-back (apply + confirm the toggled value persisted) is
	// opt-in because it mutates a live tenant. When it is off, the plan-only
	// step still proves the regression guard (Update, not replace) without
	// issuing edit_instance. See the env-var doc above for the one backend
	// precondition: the target instance must carry at least one custom resource
	// tag.
	editReadBack := os.Getenv(cloudIntegrationInstanceEditReadBackEnvVar) == "1"

	steps := []resource.TestStep{
		// Step 1 — Import.
		//
		// Adopt the existing CONNECTED instance into state. ImportStateId
		// supplies the real instance ID from the environment, and
		// ImportStatePersist keeps the imported state so the subsequent step
		// edits that same instance instead of trying to create one.
		{
			Config:             providerConfig + configCurrent,
			ResourceName:       resourceName,
			ImportState:        true,
			ImportStateId:      instanceID,
			ImportStatePersist: true,
			// ImportStateVerify is disabled: the config declares only a
			// minimal attribute subset, so a full round-trip comparison
			// against the imported remote object would report spurious diffs
			// on unmanaged computed attributes.
			ImportStateVerify: false,
		},
	}

	if editReadBack {
		// Step 2 (full end-to-end) — In-place edit (the regression guard).
		//
		// Toggle additional_capabilities.serverless_scanning and assert, via a
		// PreApply plan check, that the planned action is Update and NOT a
		// replacement, then APPLY the edit and confirm the toggled value took
		// effect via read-back. This exercises the real edit_instance call and
		// its read-back, and only runs when the backend managed-edit defect is
		// resolved (gated by TEST_CLOUD_INTEGRATION_INSTANCE_EDIT_READBACK=1).
		steps = append(steps, resource.TestStep{
			Config: providerConfig + configToggled,
			ConfigPlanChecks: resource.ConfigPlanChecks{
				PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction(
						resourceName,
						plancheck.ResourceActionUpdate,
					),
				},
			},
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttr(
					resourceName,
					"additional_capabilities.serverless_scanning",
					strconv.FormatBool(targetServerless),
				),
				testAccCheckUndeclaredCapabilitiesPreserved(t, instanceID, undeclaredBefore),
			),
		})
	} else {
		// Step 2 (default, plan-only) — In-place edit plan check WITHOUT apply.
		//
		// PlanOnly proves the toggled capability plans as an in-place Update and
		// NOT a destroy-and-recreate (the regression guard for the original bug)
		// without issuing the edit_instance call that currently 500s on the
		// backend. ExpectNonEmptyPlan is required because the config differs from
		// the imported state (serverless_scanning true vs false). If the resource
		// ever regresses to forcing a replacement, ExpectResourceAction(...,
		// ResourceActionUpdate) fails here.
		//
		// The check uses PostApplyPreRefresh because the framework rejects
		// PreApply together with PlanOnly.
		steps = append(steps, resource.TestStep{
			Config:             providerConfig + configToggled,
			PlanOnly:           true,
			ExpectNonEmptyPlan: true,
			ConfigPlanChecks: resource.ConfigPlanChecks{
				PostApplyPreRefresh: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction(
						resourceName,
						plancheck.ResourceActionUpdate,
					),
				},
			},
		})
	}

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps:                    steps,
	})
}

// newCloudOnboardingTestClient builds an SDK client for out-of-band reads of the
// instance under test.
func newCloudOnboardingTestClient(t *testing.T) *cloudonboarding.Client {
	t.Helper()

	client, err := cloudonboarding.NewClient(
		cloudonboarding.WithCortexAPIURL(testAPIURL),
		cloudonboarding.WithCortexAPIKey(testAPIKey),
		cloudonboarding.WithCortexAPIKeyID(testAPIKeyID),
		cloudonboarding.WithCortexAPIKeyType(testAPIKeyType),
	)
	if err != nil {
		t.Fatalf("failed to create cloud onboarding SDK client: %s", err)
	}
	return client
}

// readLiveInstance fetches the instance under test so the test can derive its
// toggle direction and baseline from real state instead of assuming one.
func readLiveInstance(t *testing.T, instanceID string) cloudOnboardingTypes.IntegrationInstance {
	t.Helper()

	loadEnvErr := loadDotEnv(t, dotEnvPath)
	if loadEnvErr != nil {
		t.Logf("Failed to load env file at %q: %v", dotEnvPath, loadEnvErr)
	}

	instance, err := newCloudOnboardingTestClient(t).GetIntegrationInstanceDetails(context.Background(), instanceID)
	if err != nil {
		t.Fatalf("failed to read instance %q to derive test baseline: %s", instanceID, err)
	}
	if instance.ID == "" {
		t.Fatalf("instance %q was not found; %s must reference an existing CONNECTED instance",
			instanceID, cloudIntegrationInstanceInstanceIDEnvVar)
	}
	return instance
}

// testAccCheckUndeclaredCapabilitiesPreserved asserts that capabilities absent
// from the Terraform configuration retain their pre-edit values. edit_instance
// replaces the whole capability set, so a provider that fails to merge live
// state silently disables them.
func testAccCheckUndeclaredCapabilitiesPreserved(t *testing.T, instanceID string, before map[string]*bool) resource.TestCheckFunc {
	return func(*terraform.State) error {
		after := readLiveInstance(t, instanceID).AdditionalCapabilities
		afterByName := map[string]*bool{
			"xsiam_analytics":                  after.XSIAMAnalytics,
			"data_security_posture_management": after.DataSecurityPostureManagement,
			"registry_scanning":                after.RegistryScanning,
			"agentless_disk_scanning":          after.AgentlessDiskScanning,
		}

		for name, beforeValue := range before {
			if beforeValue == nil || !*beforeValue {
				continue
			}
			afterValue := afterByName[name]
			if afterValue == nil || !*afterValue {
				return fmt.Errorf(
					"additional_capabilities.%s was enabled before the edit and is "+
						"not enabled after it: an undeclared capability was wiped by "+
						"the full-replace edit",
					name,
				)
			}
		}
		return nil
	}
}
