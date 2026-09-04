// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package acceptance

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/appsec"
	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/log"
	"github.com/hashicorp/terraform-plugin-log/tfsdklog"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

const (
	appsecRuleName        = "tf-provider-appsec-rule"
	appsecRuleDescription = "Terraform provider acceptance test rule"
	appsecRuleSeverity    = "HIGH"
	appsecRuleScanner     = "IAC"
	appsecRuleCategory    = "NETWORKING"
	appsecRuleSubCategory = "INGRESS_CONTROLS"

	appsecRuleResourceType       = "cortexcloud_appsec_rule"
	appsecRuleResourceName       = "test"
	appsecRuleResourceConfigTmpl = `
resource "%s" "%s" {
	name        = "%s"
	description = "%s"
	severity    = "%s"
	scanner     = "%s"
	category    = "%s"
	sub_category = "%s"
	
	frameworks {
		name       = "TERRAFORM"
		definition = "scope:\n  provider: aws\ndefinition:\n  cond_type: attribute\n  resource_types:\n    - aws_security_group\n  attribute: ingress.cidr_blocks\n  operator: not_contains\n  value: 0.0.0.0/0"
	}
	
	labels = ["test", "terraform"]
}`
)

var (
	appsecRuleResourceNameFull = fmt.Sprintf("%s.%s", appsecRuleResourceType, appsecRuleResourceName)
	appsecRuleResourceConfig   = fmt.Sprintf(
		appsecRuleResourceConfigTmpl,
		appsecRuleResourceType,
		appsecRuleResourceName,
		appsecRuleName,
		appsecRuleDescription,
		appsecRuleSeverity,
		appsecRuleScanner,
		appsecRuleCategory,
		appsecRuleSubCategory,
	)
)

func TestAccAppSecRuleResourceLifecycle(t *testing.T) {
	providerConfig := getProviderConfig(t, dotEnvPath, true)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + appsecRuleResourceConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(appsecRuleResourceNameFull, "name", appsecRuleName),
					resource.TestCheckResourceAttr(appsecRuleResourceNameFull, "severity", appsecRuleSeverity),
					resource.TestCheckResourceAttrSet(appsecRuleResourceNameFull, "id"),
				),
			},
			{
				Config: providerConfig,
			},
		},
		CheckDestroy: testAccCheckAppSecRuleDestroy,
	})
}

// appsecRuleCspmConfigTmpl builds an AppSec rule that maps to a Cloud Security
// (CSPM) rule via the top-level, write-only cspm_rule_id attribute.
const appsecRuleCspmConfigTmpl = `
resource "%s" "%s" {
	name         = "%s-cspm"
	description  = "%s"
	severity     = "%s"
	scanner      = "%s"
	category     = "%s"
	sub_category = "%s"
	cspm_rule_id = "%s"

	frameworks {
		name       = "TERRAFORM"
		definition = "resource \"aws_security_group\" \"example\" { ingress { cidr_blocks = [\"0.0.0.0/0\"] } }"
	}

	labels = ["test", "terraform", "cspm-mapped"]
}`

// TestAccAppSecRuleResourceCspmRuleId verifies that a custom AppSec rule can be
// created with a cspm_rule_id mapping and that the value round-trips.
//
// Requires a real CSPM rule ID for the target tenant, supplied via the
// CORTEX_TEST_CSPM_RULE_ID environment variable. The test is skipped when the
// variable is unset so it does not fail in environments without a known
// CSPM rule.
func TestAccAppSecRuleResourceCspmRuleId(t *testing.T) {
	cspmRuleId := os.Getenv("CORTEX_TEST_CSPM_RULE_ID")
	if cspmRuleId == "" {
		t.Skip("CORTEX_TEST_CSPM_RULE_ID not set; skipping cspm_rule_id acceptance test")
	}

	providerConfig := getProviderConfig(t, dotEnvPath, true)
	config := providerConfig + fmt.Sprintf(
		appsecRuleCspmConfigTmpl,
		appsecRuleResourceType,
		appsecRuleResourceName,
		appsecRuleName,
		appsecRuleDescription,
		appsecRuleSeverity,
		appsecRuleScanner,
		appsecRuleCategory,
		appsecRuleSubCategory,
		cspmRuleId,
	)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(appsecRuleResourceNameFull, "id"),
					resource.TestCheckResourceAttr(appsecRuleResourceNameFull, "cspm_rule_id", cspmRuleId),
				),
			},
			// Verify no perpetual diff: re-applying the same config produces an
			// empty plan (confirms cspm_rule_id round-trips cleanly).
			{
				Config:   config,
				PlanOnly: true,
			},
			{
				Config: providerConfig,
			},
		},
		CheckDestroy: testAccCheckAppSecRuleDestroy,
	})
}

func testAccCheckAppSecRuleDestroy(s *terraform.State) error {
	ctx := context.Background()
	tfsdklog.Debug(ctx, "Confirming appsec rule resource destruction")

	appsecClient, err := appsec.NewClient(
		appsec.WithCortexAPIURL(testAPIURL),
		appsec.WithCortexAPIKey(testAPIKey),
		appsec.WithCortexAPIKeyID(testAPIKeyID),
		appsec.WithCortexAPIKeyType("standard"),
		appsec.WithLogger(log.TflogAdapter{}),
		appsec.WithLogLevel("debug"),
	)

	if err != nil {
		return fmt.Errorf("error creating SDK client for destruction check: %s", err.Error())
	}

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "cortexcloud_appsec_rule" {
			continue
		}

		_, err := appsecClient.Get(ctx, rs.Primary.ID)
		if err == nil {
			return fmt.Errorf("AppSec rule %s still exists", rs.Primary.ID)
		}
	}

	return nil
}
