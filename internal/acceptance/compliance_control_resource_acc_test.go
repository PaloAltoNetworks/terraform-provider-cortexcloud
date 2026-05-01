// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package acceptance

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/PaloAltoNetworks/cortex-cloud-go/compliance"
	"github.com/PaloAltoNetworks/cortex-cloud-go/log"
	complianceTypes "github.com/PaloAltoNetworks/cortex-cloud-go/types/compliance"
	"github.com/hashicorp/terraform-plugin-log/tfsdklog"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
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
