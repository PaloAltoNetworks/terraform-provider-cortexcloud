// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package acceptance

import (
	"context"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/PaloAltoNetworks/cortex-cloud-go/log"
	"github.com/PaloAltoNetworks/cortex-cloud-go/platform"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

const (
	biocResourceType    = "cortexcloud_bioc"
	biocResourceLocalID = "test"

	biocXQLResourceConfigTmpl = `
resource "%s" "%s" {
  name      = "%s"
  type      = "%s"
  severity  = "%s"
  status    = "%s"
  comment   = "%s"
  xql_query = "%s"
}
`

	biocStructuredResourceConfigTmpl = `
resource "%s" "%s" {
  name     = "%s"
  type     = "%s"
  severity = "%s"
  status   = "%s"
  comment  = "%s"
  definition = jsonencode({
    runOnCGO          = true
    investigationType = "PROCESS_EXECUTION_EVENT"
    investigation = {
      PROCESS_EXECUTION_EVENT = {
        filter = {
          AND = [{
            SEARCH_FIELD = "action_process_username"
            SEARCH_TYPE  = "EQ"
            SEARCH_VALUE = "%s"
          }]
        }
      }
    }
  })
}
`
)

func biocXQLResourceConfig(name, biocType, severity, status, comment, xql string) string {
	return fmt.Sprintf(
		biocXQLResourceConfigTmpl,
		biocResourceType, biocResourceLocalID,
		name, biocType, severity, status, comment, xql,
	)
}

func biocStructuredResourceConfig(name, biocType, severity, status, comment, searchValue string) string {
	return fmt.Sprintf(
		biocStructuredResourceConfigTmpl,
		biocResourceType, biocResourceLocalID,
		name, biocType, severity, status, comment, searchValue,
	)
}

// TestAccBIOCResourceXQLLifecycle exercises the full create → in-place
// update → rename → delete cycle of the cortexcloud_bioc resource with the
// XQL indicator form. The rename step asserts rule_id is stable across the
// in-place upsert (BIOC names are not unique per tenant, so rule_id is the
// only safe identity).
func TestAccBIOCResourceXQLLifecycle(t *testing.T) {
	providerConfig := getProviderConfig(t, dotEnvPath, true)

	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	originalName := fmt.Sprintf("tf-provider-acctest-bioc-%s", timestamp)
	renamedName := originalName + "-renamed"
	xql := fmt.Sprintf("dataset = xdr_data | filter event_type = 1 and actor_process_image_name = \\\"acctest-%s.exe\\\"", timestamp)

	fqResourceName := fmt.Sprintf("%s.%s", biocResourceType, biocResourceLocalID)

	var ruleIDAfterCreate string

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create.
			{
				PreConfig: func() { t.Log("Executing Create test step") },
				Config: providerConfig + biocXQLResourceConfig(
					originalName, "EXECUTION", "SEV_020_LOW", "enabled", "initial", xql,
				),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(fqResourceName, "name", originalName),
					resource.TestCheckResourceAttr(fqResourceName, "type", "EXECUTION"),
					resource.TestCheckResourceAttr(fqResourceName, "severity", "SEV_020_LOW"),
					resource.TestCheckResourceAttr(fqResourceName, "status", "enabled"),
					resource.TestCheckResourceAttr(fqResourceName, "comment", "initial"),
					resource.TestCheckResourceAttr(fqResourceName, "is_xql", "true"),
					resource.TestCheckResourceAttrSet(fqResourceName, "rule_id"),
					resource.TestCheckResourceAttrSet(fqResourceName, "creation_time"),
					resource.TestCheckResourceAttrWith(fqResourceName, "rule_id", func(value string) error {
						ruleIDAfterCreate = value
						return nil
					}),
				),
			},
			// In-place update — severity, comment change. rule_id stable.
			{
				PreConfig: func() { t.Log("Executing In-Place Update test step") },
				Config: providerConfig + biocXQLResourceConfig(
					originalName, "EXECUTION", "SEV_050_CRITICAL", "enabled", "updated", xql,
				),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(fqResourceName, "severity", "SEV_050_CRITICAL"),
					resource.TestCheckResourceAttr(fqResourceName, "comment", "updated"),
					resource.TestCheckResourceAttrPtr(fqResourceName, "rule_id", &ruleIDAfterCreate),
				),
			},
			// Rename — name changes, record overwritten in place via
			// rule_id-keyed upsert. rule_id remains stable.
			{
				PreConfig: func() { t.Log("Executing Rename test step") },
				Config: providerConfig + biocXQLResourceConfig(
					renamedName, "EXECUTION", "SEV_050_CRITICAL", "enabled", "updated", xql,
				),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(fqResourceName, "name", renamedName),
					resource.TestCheckResourceAttrPtr(fqResourceName, "rule_id", &ruleIDAfterCreate),
				),
			},
			// Empty step → triggers terraform destroy.
			{
				PreConfig: func() { t.Log("Executing Destroy test step") },
				Config:    providerConfig,
			},
		},
		CheckDestroy: testAccCheckBIOCDestroy,
	})
}

// TestAccBIOCResourceStructured exercises the non-XQL form: a JSON-encoded
// filter AST as the indicator. Verifies the round-trip through canonical
// JSON does not show as a plan diff on re-read.
func TestAccBIOCResourceStructured(t *testing.T) {
	providerConfig := getProviderConfig(t, dotEnvPath, false)

	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	name := fmt.Sprintf("tf-provider-acctest-bioc-structured-%s", timestamp)
	fqResourceName := fmt.Sprintf("%s.%s", biocResourceType, biocResourceLocalID)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + biocStructuredResourceConfig(
					name, "EXECUTION", "SEV_010_INFO", "disabled", "structured-probe",
					fmt.Sprintf("acctest-%s", timestamp),
				),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(fqResourceName, "is_xql", "false"),
					resource.TestCheckResourceAttrSet(fqResourceName, "definition"),
					resource.TestCheckResourceAttrSet(fqResourceName, "rule_id"),
				),
			},
			{Config: providerConfig},
		},
		CheckDestroy: testAccCheckBIOCDestroy,
	})
}

// testAccCheckBIOCDestroy walks the terraform state, picks out every
// cortexcloud_bioc, and asserts the API no longer surfaces it under the
// recorded rule_id. The ID is the stringified rule_id.
func testAccCheckBIOCDestroy(s *terraform.State) error {
	ctx := context.Background()

	client, err := platform.NewClient(
		platform.WithCortexAPIURL(testAPIURL),
		platform.WithCortexAPIKey(testAPIKey),
		platform.WithCortexAPIKeyID(testAPIKeyID),
		platform.WithCortexAPIKeyType("standard"),
		platform.WithLogger(log.TflogAdapter{}),
		platform.WithLogLevel("info"),
	)
	if err != nil {
		return fmt.Errorf("error creating SDK client for destruction check: %s", err.Error())
	}

	for _, rs := range s.RootModule().Resources {
		if rs.Type != biocResourceType {
			continue
		}
		idStr := rs.Primary.ID
		if idStr == "" {
			continue
		}
		ruleID, parseErr := strconv.Atoi(idStr)
		if parseErr != nil {
			return fmt.Errorf("BIOC id %q is not a numeric rule_id: %s", idStr, parseErr.Error())
		}
		got, err := client.FindBIOCByID(ctx, ruleID)
		if err != nil {
			return fmt.Errorf("error checking BIOC rule_id=%d for destruction: %s", ruleID, err.Error())
		}
		if got != nil {
			return fmt.Errorf("BIOC rule_id=%d still exists after destroy (name=%q)", ruleID, got.Name)
		}
	}
	return nil
}
