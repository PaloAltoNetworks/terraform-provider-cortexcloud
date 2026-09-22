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
	indicatorResourceType    = "cortexcloud_indicator"
	indicatorResourceLocalID = "test"

	indicatorResourceConfigTmpl = `
resource "%s" "%s" {
  indicator                  = "%s"
  type                       = "%s"
  severity                   = "%s"
  expiration_date            = -1
  default_expiration_enabled = true
  reputation                 = "%s"
  reliability                = "%s"
  comment                    = "%s"
}
`
)

func indicatorResourceConfig(indicator, indicatorType, severity, reputation, reliability, comment string) string {
	return fmt.Sprintf(
		indicatorResourceConfigTmpl,
		indicatorResourceType,
		indicatorResourceLocalID,
		indicator,
		indicatorType,
		severity,
		reputation,
		reliability,
		comment,
	)
}

// TestAccIndicatorResourceLifecycle exercises the full create → in-place
// update → rename → delete cycle of the cortexcloud_indicator resource
// against a live tenant. Both the steady-state update and the rename go
// through the rule_id-keyed upsert, which overwrites the record in place
// and preserves `rule_id`; the rename step asserts that stability directly.
func TestAccIndicatorResourceLifecycle(t *testing.T) {
	providerConfig := getProviderConfig(t, dotEnvPath, true)

	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	originalName := fmt.Sprintf("tf-provider-acctest-%s.example.test", timestamp)
	renamedName := originalName + "-renamed"

	fqResourceName := fmt.Sprintf("%s.%s", indicatorResourceType, indicatorResourceLocalID)

	// Captured after Create so the rename step can assert rule_id is
	// preserved across the in-place upsert (not regenerated).
	var ruleIDAfterCreate string

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create
			{
				PreConfig: func() { t.Log("Executing Create test step") },
				Config: providerConfig + indicatorResourceConfig(
					originalName, "DOMAIN_NAME", "SEV_020_LOW",
					"UNKNOWN", "F", "initial",
				),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(fqResourceName, "indicator", originalName),
					resource.TestCheckResourceAttr(fqResourceName, "type", "DOMAIN_NAME"),
					resource.TestCheckResourceAttr(fqResourceName, "severity", "SEV_020_LOW"),
					resource.TestCheckResourceAttr(fqResourceName, "reputation", "UNKNOWN"),
					resource.TestCheckResourceAttr(fqResourceName, "reliability", "F"),
					resource.TestCheckResourceAttr(fqResourceName, "comment", "initial"),
					resource.TestCheckResourceAttr(fqResourceName, "status", "ENABLED"),
					resource.TestCheckResourceAttrSet(fqResourceName, "rule_id"),
					resource.TestCheckResourceAttrSet(fqResourceName, "creation_time"),
					resource.TestCheckResourceAttrWith(fqResourceName, "rule_id", func(value string) error {
						ruleIDAfterCreate = value
						return nil
					}),
				),
			},
			// In-place update (rule_id-keyed upsert): severity, reputation,
			// reliability, comment all change. rule_id must be stable.
			{
				PreConfig: func() { t.Log("Executing In-Place Update test step") },
				Config: providerConfig + indicatorResourceConfig(
					originalName, "DOMAIN_NAME", "SEV_050_CRITICAL",
					"BAD", "A", "updated",
				),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(fqResourceName, "severity", "SEV_050_CRITICAL"),
					resource.TestCheckResourceAttr(fqResourceName, "reputation", "BAD"),
					resource.TestCheckResourceAttr(fqResourceName, "reliability", "A"),
					resource.TestCheckResourceAttr(fqResourceName, "comment", "updated"),
				),
			},
			// Rename (rule_id-keyed upsert). The indicator value moves and
			// rule_id stays put — the record is overwritten in place, not
			// recreated.
			{
				PreConfig: func() { t.Log("Executing Rename test step") },
				Config: providerConfig + indicatorResourceConfig(
					renamedName, "DOMAIN_NAME", "SEV_050_CRITICAL",
					"BAD", "A", "updated",
				),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(fqResourceName, "indicator", renamedName),
					resource.TestCheckResourceAttrPtr(fqResourceName, "rule_id", &ruleIDAfterCreate),
				),
			},
			// Empty step → triggers terraform destroy.
			{
				PreConfig: func() { t.Log("Executing Destroy test step") },
				Config:    providerConfig,
			},
		},
		CheckDestroy: testAccCheckIndicatorDestroy,
	})
}

// TestAccIndicatorResourceURLType verifies B1 — `type=URL` and
// `severity=SEV_050_CRITICAL` are accepted by the live API and survive
// the Terraform plan/apply round-trip even though they're absent from the
// OpenAPI insert enum.
func TestAccIndicatorResourceURLType(t *testing.T) {
	providerConfig := getProviderConfig(t, dotEnvPath, false)

	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	urlValue := fmt.Sprintf("https://tf-provider-acctest-%s.example.test/probe", timestamp)

	fqResourceName := fmt.Sprintf("%s.%s", indicatorResourceType, indicatorResourceLocalID)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + indicatorResourceConfig(
					urlValue, "URL", "SEV_050_CRITICAL", "BAD", "A", "URL+critical probe",
				),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(fqResourceName, "type", "URL"),
					resource.TestCheckResourceAttr(fqResourceName, "severity", "SEV_050_CRITICAL"),
					resource.TestCheckResourceAttrSet(fqResourceName, "rule_id"),
				),
			},
			{Config: providerConfig},
		},
		CheckDestroy: testAccCheckIndicatorDestroy,
	})
}

// testAccCheckIndicatorDestroy walks the terraform state, picks out every
// cortexcloud_indicator, and asserts the API no longer surfaces it.
func testAccCheckIndicatorDestroy(s *terraform.State) error {
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
		if rs.Type != indicatorResourceType {
			continue
		}
		indicator := rs.Primary.ID
		if indicator == "" {
			continue
		}
		got, err := client.FindIndicatorByName(ctx, indicator)
		if err != nil {
			return fmt.Errorf("error checking indicator %q for destruction: %s", indicator, err.Error())
		}
		if got != nil {
			return fmt.Errorf("indicator %q still exists after destroy (rule_id=%d)", indicator, got.RuleID)
		}
	}
	return nil
}
