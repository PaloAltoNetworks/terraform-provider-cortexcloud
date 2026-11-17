// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package acceptance

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/util"
	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/compliance"
	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/log"
	complianceTypes "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/types/compliance"
	"github.com/hashicorp/terraform-plugin-log/tfsdklog"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

var (
	complianceControlName        = fmt.Sprintf("tf-provider-compliance-control-%d", time.Now().Unix())
	complianceControlDescription = "Terraform provider acceptance test control"
	complianceControlCategory    = "Access Control"
	complianceControlSubcategory = "5.1"

	complianceControlNameUpdated        = fmt.Sprintf("tf-provider-compliance-control-%d-updated", time.Now().Unix())
	complianceControlDescriptionUpdated = "Terraform provider acceptance test control updated"

	complianceControlResourceType       = "cortexcloud_compliance_control"
	complianceControlResourceName       = "test"
	complianceControlResourceConfigTmpl = `
resource "%s" "%s" {
	name        = "%s"
	description = "%s"
	category    = "%s"
	subcategory = "%s"
}`
)

var (
	complianceControlResourceNameFull = fmt.Sprintf("%s.%s", complianceControlResourceType, complianceControlResourceName)
	complianceControlResourceConfig   = fmt.Sprintf(
		complianceControlResourceConfigTmpl,
		complianceControlResourceType,
		complianceControlResourceName,
		complianceControlName,
		complianceControlDescription,
		complianceControlCategory,
		complianceControlSubcategory,
	)
	complianceControlResourceUpdatedConfig = fmt.Sprintf(
		complianceControlResourceConfigTmpl,
		complianceControlResourceType,
		complianceControlResourceName,
		complianceControlNameUpdated,
		complianceControlDescriptionUpdated,
		complianceControlCategory,
		complianceControlSubcategory,
	)
)

func TestAccComplianceControlResourceLifecycle(t *testing.T) {
	providerConfig := getProviderConfig(t, dotEnvPath, true)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				PreConfig: func() {
					t.Log("Executing Create test step")
				},
				Config: providerConfig + complianceControlResourceConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(complianceControlResourceNameFull, "name", complianceControlName),
					resource.TestCheckResourceAttr(complianceControlResourceNameFull, "description", complianceControlDescription),
					resource.TestCheckResourceAttr(complianceControlResourceNameFull, "category", complianceControlCategory),
					resource.TestCheckResourceAttr(complianceControlResourceNameFull, "subcategory", complianceControlSubcategory),
					resource.TestCheckResourceAttrSet(complianceControlResourceNameFull, "id"),
					resource.TestCheckResourceAttr(complianceControlResourceNameFull, "is_custom", "true"),
				),
			},
			// Update and Read testing
			{
				PreConfig: func() {
					t.Log("Executing Update test step")
				},
				Config: providerConfig + complianceControlResourceUpdatedConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(complianceControlResourceNameFull, "name", complianceControlNameUpdated),
					resource.TestCheckResourceAttr(complianceControlResourceNameFull, "description", complianceControlDescriptionUpdated),
					resource.TestCheckResourceAttrSet(complianceControlResourceNameFull, "id"),
				),
			},
			// Import State testing
			{
				PreConfig: func() {
					t.Log("Executing Import test step")
				},
				ResourceName:      complianceControlResourceNameFull,
				ImportState:       true,
				ImportStateVerify: true,
			},
			// Delete testing
			{
				PreConfig: func() {
					t.Log("Executing Delete test step")
				},
				Config: providerConfig,
			},
		},
		CheckDestroy: testAccCheckComplianceControlDestroy,
	})
}

// complianceControlNoDescriptionConfigTmpl omits description entirely, so the
// Optional-only attribute is null in configuration.
const complianceControlNoDescriptionConfigTmpl = `
resource "%s" "%s" {
	name        = "%s"
	category    = "%s"
	subcategory = "%s"
}`

// complianceControlNoSubcategoryConfigTmpl omits subcategory entirely, so the
// Optional-only attribute is null in configuration (as opposed to "").
const complianceControlNoSubcategoryConfigTmpl = `
resource "%s" "%s" {
	name        = "%s"
	description = "%s"
	category    = "%s"
}`

// complianceControlOutOfBandDescription is written directly through the API to
// simulate drift on an attribute that the configuration omits.
const complianceControlOutOfBandDescription = "Set outside Terraform"

// TestAccComplianceControlResourceSubcategoryClear covers clearing the
// Optional-only description and subcategory attributes:
//   - an explicit subcategory = "" clears it remotely and stores "" in state.
//     Previously the empty value was dropped by omitempty, the backend kept
//     the old subcategory, and apply failed with "Provider produced
//     inconsistent result after apply".
//   - removing subcategory or description from configuration clears it
//     remotely and leaves it null in state, with no perpetual diff.
//   - a value set out-of-band on an omitted attribute surfaces as drift and
//     the next apply clears it.
func TestAccComplianceControlResourceSubcategoryClear(t *testing.T) {
	providerConfig := getProviderConfig(t, dotEnvPath, true)

	name := fmt.Sprintf("tf-provider-compliance-control-subcat-%d", time.Now().Unix())

	// controlID is captured after create so PreConfig hooks, which have no
	// access to state, can modify the control out-of-band.
	var controlID string

	withSubcategory := fmt.Sprintf(
		complianceControlResourceConfigTmpl,
		complianceControlResourceType,
		complianceControlResourceName,
		name,
		complianceControlDescription,
		complianceControlCategory,
		complianceControlSubcategory,
	)
	emptySubcategory := fmt.Sprintf(
		complianceControlResourceConfigTmpl,
		complianceControlResourceType,
		complianceControlResourceName,
		name,
		complianceControlDescription,
		complianceControlCategory,
		"",
	)
	omittedSubcategory := fmt.Sprintf(
		complianceControlNoSubcategoryConfigTmpl,
		complianceControlResourceType,
		complianceControlResourceName,
		name,
		complianceControlDescription,
		complianceControlCategory,
	)
	withoutDescription := fmt.Sprintf(
		complianceControlNoDescriptionConfigTmpl,
		complianceControlResourceType,
		complianceControlResourceName,
		name,
		complianceControlCategory,
		complianceControlSubcategory,
	)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create with a subcategory.
			{
				PreConfig: func() { t.Log("Creating control with subcategory") },
				Config:    providerConfig + withSubcategory,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(complianceControlResourceNameFull, "id"),
					resource.TestCheckResourceAttr(complianceControlResourceNameFull, "subcategory", complianceControlSubcategory),
					testAccCaptureResourceID(complianceControlResourceNameFull, &controlID),
				),
			},
			// Explicit subcategory = "": must be an in-place update, persist
			// remotely, and store "" (not null) in state.
			{
				PreConfig: func() { t.Log("Setting subcategory to empty string") },
				Config:    providerConfig + emptySubcategory,
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(complianceControlResourceNameFull, plancheck.ResourceActionUpdate),
					},
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(complianceControlResourceNameFull, "subcategory", ""),
					resource.TestCheckResourceAttr(complianceControlResourceNameFull, "description", complianceControlDescription),
					testAccCheckComplianceControlRemote(complianceControlResourceNameFull, func(c *complianceTypes.Control) error {
						if c.Subcategory != "" {
							return fmt.Errorf("expected remote subcategory to be cleared, got %q", c.Subcategory)
						}
						return nil
					}),
				),
			},
			// Restore subcategory.
			{
				PreConfig: func() { t.Log("Restoring subcategory") },
				Config:    providerConfig + withSubcategory,
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(complianceControlResourceNameFull, "subcategory", complianceControlSubcategory),
					testAccCheckComplianceControlRemote(complianceControlResourceNameFull, func(c *complianceTypes.Control) error {
						if c.Subcategory != complianceControlSubcategory {
							return fmt.Errorf("expected remote subcategory %q, got %q", complianceControlSubcategory, c.Subcategory)
						}
						return nil
					}),
				),
			},
			// Omitting subcategory (Optional only) must clear it remotely via an
			// in-place update, leave it null (not "") in state, and not produce a
			// perpetual diff.
			{
				PreConfig: func() { t.Log("Omitting subcategory") },
				Config:    providerConfig + omittedSubcategory,
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(complianceControlResourceNameFull, plancheck.ResourceActionUpdate),
					},
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckNoResourceAttr(complianceControlResourceNameFull, "subcategory"),
					resource.TestCheckResourceAttr(complianceControlResourceNameFull, "description", complianceControlDescription),
					testAccCheckComplianceControlRemote(complianceControlResourceNameFull, func(c *complianceTypes.Control) error {
						if c.Subcategory != "" {
							return fmt.Errorf("expected remote subcategory to be cleared, got %q", c.Subcategory)
						}
						if c.Description != complianceControlDescription {
							return fmt.Errorf("expected remote description %q to be untouched, got %q", complianceControlDescription, c.Description)
						}
						return nil
					}),
				),
			},
			// Omitting description (Optional only) must clear it remotely via an
			// in-place update, leave it null in state, and not produce a perpetual
			// diff. subcategory goes from null back to a value in the same step.
			{
				PreConfig: func() { t.Log("Omitting description") },
				Config:    providerConfig + withoutDescription,
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(complianceControlResourceNameFull, plancheck.ResourceActionUpdate),
					},
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckNoResourceAttr(complianceControlResourceNameFull, "description"),
					resource.TestCheckResourceAttr(complianceControlResourceNameFull, "subcategory", complianceControlSubcategory),
					testAccCheckComplianceControlRemote(complianceControlResourceNameFull, func(c *complianceTypes.Control) error {
						if c.Description != "" {
							return fmt.Errorf("expected remote description to be cleared, got %q", c.Description)
						}
						if c.Subcategory != complianceControlSubcategory {
							return fmt.Errorf("expected remote subcategory %q, got %q", complianceControlSubcategory, c.Subcategory)
						}
						return nil
					}),
				),
			},
			// Drift: a description set out-of-band while the configuration omits
			// it must surface in the plan (refresh records the remote value) and
			// the apply must clear it again.
			{
				PreConfig: func() {
					t.Log("Setting description out-of-band")
					testAccSetComplianceControlDescription(t, controlID, complianceControlOutOfBandDescription)
				},
				Config: providerConfig + withoutDescription,
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(complianceControlResourceNameFull, plancheck.ResourceActionUpdate),
					},
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckNoResourceAttr(complianceControlResourceNameFull, "description"),
					resource.TestCheckResourceAttr(complianceControlResourceNameFull, "subcategory", complianceControlSubcategory),
					testAccCheckComplianceControlRemote(complianceControlResourceNameFull, func(c *complianceTypes.Control) error {
						if c.Description != "" {
							return fmt.Errorf("expected out-of-band description to be cleared, got %q", c.Description)
						}
						return nil
					}),
				),
			},
			// Import must round-trip, including subcategory/description.
			{
				ResourceName:      complianceControlResourceNameFull,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
		CheckDestroy: testAccCheckComplianceControlDestroy,
	})
}

// TestAccComplianceControlResourceNormalizedLabels covers the API's Title Case
// normalization of free-text category and subcategory values:
//   - a lowercase configuration is stored remotely in Title Case, while state
//     keeps the configured casing (no "inconsistent result after apply") and
//     the follow-up plan is empty.
//   - a casing-only configuration change is an in-place update that also
//     converges to an empty plan.
//   - import has no configuration to compare with, so it reads the normalized
//     remote value; category and subcategory are excluded from the import
//     comparison for that reason.
func TestAccComplianceControlResourceNormalizedLabels(t *testing.T) {
	providerConfig := getProviderConfig(t, dotEnvPath, true)

	suffix := time.Now().Unix()
	name := fmt.Sprintf("tf-provider-compliance-control-labels-%d", suffix)
	lowerCategory := fmt.Sprintf("tf acc custom category %d", suffix)
	lowerSubcategory := fmt.Sprintf("tf acc custom subcategory %d", suffix)
	upperCategory := fmt.Sprintf("TF ACC CUSTOM CATEGORY %d", suffix)
	upperSubcategory := fmt.Sprintf("TF ACC CUSTOM SUBCATEGORY %d", suffix)
	// The API stores the normalized form regardless of the configured casing.
	storedCategory := util.NormalizeControlLabel(lowerCategory)
	storedSubcategory := util.NormalizeControlLabel(lowerSubcategory)

	config := func(category, subcategory string) string {
		return fmt.Sprintf(
			complianceControlResourceConfigTmpl,
			complianceControlResourceType,
			complianceControlResourceName,
			name,
			complianceControlDescription,
			category,
			subcategory,
		)
	}

	checkRemoteStoresNormalized := testAccCheckComplianceControlRemote(complianceControlResourceNameFull, func(c *complianceTypes.Control) error {
		if c.Category != storedCategory {
			return fmt.Errorf("expected remote category %q, got %q", storedCategory, c.Category)
		}
		if c.Subcategory != storedSubcategory {
			return fmt.Errorf("expected remote subcategory %q, got %q", storedSubcategory, c.Subcategory)
		}
		return nil
	})

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create with lowercase values: state keeps the configured casing,
			// the backend holds the Title Case form, and the plan stays empty.
			{
				PreConfig: func() { t.Log("Creating control with lowercase category and subcategory") },
				Config:    providerConfig + config(lowerCategory, lowerSubcategory),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(complianceControlResourceNameFull, "category", lowerCategory),
					resource.TestCheckResourceAttr(complianceControlResourceNameFull, "subcategory", lowerSubcategory),
					checkRemoteStoresNormalized,
				),
			},
			// Casing-only change: in-place update, state follows the new
			// configured casing, the backend value is unchanged, and the plan
			// converges.
			{
				PreConfig: func() { t.Log("Changing only the casing of category and subcategory") },
				Config:    providerConfig + config(upperCategory, upperSubcategory),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(complianceControlResourceNameFull, plancheck.ResourceActionUpdate),
					},
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(complianceControlResourceNameFull, "category", upperCategory),
					resource.TestCheckResourceAttr(complianceControlResourceNameFull, "subcategory", upperSubcategory),
					checkRemoteStoresNormalized,
				),
			},
			// Import reads the normalized remote values. They differ in
			// casing from the configured ones, so exclude them from the
			// comparison.
			{
				ResourceName:            complianceControlResourceNameFull,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"category", "subcategory"},
			},
		},
		CheckDestroy: testAccCheckComplianceControlDestroy,
	})
}

// testAccCheckComplianceControlRemote fetches the control directly from the API
// and runs check against it, verifying the backend (not just state) changed.
func testAccCheckComplianceControlRemote(resourceName string, check func(*complianceTypes.Control) error) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return fmt.Errorf("resource %s not found in state", resourceName)
		}

		client, err := newComplianceTestClient()
		if err != nil {
			return err
		}

		control, err := client.GetControl(context.Background(), complianceTypes.GetControlRequest{ID: rs.Primary.ID})
		if err != nil {
			return fmt.Errorf("error fetching compliance control %s: %s", rs.Primary.ID, err.Error())
		}
		if control == nil {
			return fmt.Errorf("compliance control %s not found", rs.Primary.ID)
		}

		return check(control)
	}
}

// complianceControlUpgradeFromProviderVersion is the released provider
// version the upgrade test starts from. It is the most recent release that
// users upgrade from (v1.0.15, before this change). That release stored an
// omitted subcategory as "" in state (Optional+Computed with Default: "");
// step 1 of the upgrade test asserts this. Bump it when a newer release ships.
const complianceControlUpgradeFromProviderVersion = "1.0.15"

// TestAccComplianceControlResourceUpgradeFromPreviousRelease documents the
// one-time diff users see after upgrading: v1.0.15 stored an omitted
// subcategory as "" in state, while subcategory is now Optional only, so the
// first plan with the current provider is an in-place "" -> null update. The
// apply sends "" (the value the backend already has) and later plans are
// empty. This is the behaviour described under Known Issues in
// RELEASE_NOTES.md; if this test starts failing, update that note.
//
// Step 1 downloads v1.0.15 from the public Terraform registry.
func TestAccComplianceControlResourceUpgradeFromPreviousRelease(t *testing.T) {
	providerConfig := getProviderConfig(t, dotEnvPath, true)

	name := fmt.Sprintf("tf-provider-compliance-control-upgrade-%d", time.Now().Unix())
	omittedSubcategory := fmt.Sprintf(
		complianceControlNoSubcategoryConfigTmpl,
		complianceControlResourceType,
		complianceControlResourceName,
		name,
		complianceControlDescription,
		complianceControlCategory,
	)

	resource.Test(t, resource.TestCase{
		PreCheck: func() { testAccPreCheck(t) },
		Steps: []resource.TestStep{
			// Create with the previous release, subcategory omitted. Its
			// Default: "" stores "" (not null) in state.
			{
				PreConfig: func() { t.Logf("Creating control with provider v%s", complianceControlUpgradeFromProviderVersion) },
				ExternalProviders: map[string]resource.ExternalProvider{
					providerName: {
						Source:            "PaloAltoNetworks/cortexcloud",
						VersionConstraint: complianceControlUpgradeFromProviderVersion,
					},
				},
				Config: providerConfig + omittedSubcategory,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(complianceControlResourceNameFull, "id"),
					resource.TestCheckResourceAttr(complianceControlResourceNameFull, "subcategory", ""),
				),
			},
			// Same configuration with the current provider: exactly one
			// in-place update planning subcategory as null, leaving the
			// control's configured values unchanged, then an empty plan.
			{
				PreConfig:                func() { t.Log("Upgrading to the current provider") },
				ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
				Config:                   providerConfig + omittedSubcategory,
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(complianceControlResourceNameFull, plancheck.ResourceActionUpdate),
						plancheck.ExpectKnownValue(complianceControlResourceNameFull, tfjsonpath.New("subcategory"), knownvalue.Null()),
						plancheck.ExpectKnownValue(complianceControlResourceNameFull, tfjsonpath.New("name"), knownvalue.StringExact(name)),
						plancheck.ExpectKnownValue(complianceControlResourceNameFull, tfjsonpath.New("description"), knownvalue.StringExact(complianceControlDescription)),
						plancheck.ExpectKnownValue(complianceControlResourceNameFull, tfjsonpath.New("category"), knownvalue.StringExact(complianceControlCategory)),
					},
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckNoResourceAttr(complianceControlResourceNameFull, "subcategory"),
					testAccCheckComplianceControlRemote(complianceControlResourceNameFull, func(c *complianceTypes.Control) error {
						if c.Subcategory != "" {
							return fmt.Errorf("expected remote subcategory to stay empty, got %q", c.Subcategory)
						}
						if c.Name != name || c.Description != complianceControlDescription || c.Category != complianceControlCategory {
							return fmt.Errorf("expected configured values to be unchanged, got name=%q description=%q category=%q",
								c.Name, c.Description, c.Category)
						}
						return nil
					}),
				),
			},
		},
		CheckDestroy: testAccCheckComplianceControlDestroy,
	})
}

// testAccCaptureResourceID stores the resource's ID in dst so later PreConfig
// hooks, which cannot read state, can address the remote object.
func testAccCaptureResourceID(resourceName string, dst *string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return fmt.Errorf("resource %s not found in state", resourceName)
		}
		if rs.Primary.ID == "" {
			return fmt.Errorf("resource %s has no ID in state", resourceName)
		}
		*dst = rs.Primary.ID
		return nil
	}
}

// testAccSetComplianceControlDescription changes a control's description
// directly through the API to simulate out-of-band drift. The edit API has no
// omitempty on description/subcategory, so the current values of every other
// field are read first and sent back unchanged.
func testAccSetComplianceControlDescription(t *testing.T, id, description string) {
	t.Helper()
	if id == "" {
		t.Fatal("control ID was not captured before the out-of-band update")
	}

	client, err := newComplianceTestClient()
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	current, err := client.GetControl(ctx, complianceTypes.GetControlRequest{ID: id})
	if err != nil {
		t.Fatalf("error fetching compliance control %s: %s", id, err.Error())
	}
	if current == nil {
		t.Fatalf("compliance control %s not found", id)
	}

	ok, err := client.UpdateControl(ctx, complianceTypes.UpdateControlRequest{
		ID:          id,
		ControlName: current.Name,
		Description: description,
		Category:    current.Category,
		Subcategory: current.Subcategory,
	})
	if err != nil {
		t.Fatalf("error updating compliance control %s out-of-band: %s", id, err.Error())
	}
	if !ok {
		t.Fatalf("out-of-band update of compliance control %s was not successful", id)
	}
}

func newComplianceTestClient() (*compliance.Client, error) {
	client, err := compliance.NewClient(
		compliance.WithCortexAPIURL(testAPIURL),
		compliance.WithCortexAPIKey(testAPIKey),
		compliance.WithCortexAPIKeyID(testAPIKeyID),
		compliance.WithCortexAPIKeyType("standard"),
		compliance.WithLogger(log.TflogAdapter{}),
		compliance.WithLogLevel("debug"),
	)
	if err != nil {
		return nil, fmt.Errorf("error creating SDK client: %s", err.Error())
	}
	return client, nil
}

func testAccCheckComplianceControlDestroy(s *terraform.State) error {
	ctx := context.Background()
	tfsdklog.Debug(ctx, "Confirming compliance control resource destruction")

	complianceClient, err := compliance.NewClient(
		compliance.WithCortexAPIURL(testAPIURL),
		compliance.WithCortexAPIKey(testAPIKey),
		compliance.WithCortexAPIKeyID(testAPIKeyID),
		compliance.WithCortexAPIKeyType("standard"),
		compliance.WithLogger(log.TflogAdapter{}),
		compliance.WithLogLevel("debug"),
	)

	if err != nil {
		return fmt.Errorf("error creating SDK client for destruction check: %s", err.Error())
	}

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "cortexcloud_compliance_control" {
			continue
		}

		// Try to get the control - it should not exist
		_, err := complianceClient.GetControl(ctx, complianceTypes.GetControlRequest{
			ID: rs.Primary.ID,
		})
		if err == nil {
			return fmt.Errorf("Compliance control %s still exists", rs.Primary.ID)
		}
	}

	return nil
}
