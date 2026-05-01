// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package acceptance

import (
	"context"
	"fmt"
	"testing"

	"github.com/PaloAltoNetworks/cortex-cloud-go/appsec"
	"github.com/PaloAltoNetworks/cortex-cloud-go/log"
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
		definition = "resource \"aws_security_group\" \"example\" { ingress { cidr_blocks = [\"0.0.0.0/0\"] } }"
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
