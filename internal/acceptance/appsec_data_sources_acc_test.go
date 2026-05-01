// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package acceptance

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// TestAccAppSecRuleLabelsDataSource tests the rule labels data source
func TestAccAppSecRuleLabelsDataSource(t *testing.T) {
	providerConfig := getProviderConfig(t, dotEnvPath, true)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
data "cortexcloud_appsec_rule_labels" "test" {}
`,
				Check: resource.ComposeTestCheckFunc(
					// Just verify the data source can be read successfully
					// Labels may be empty on this environment
					resource.TestCheckResourceAttrSet("data.cortexcloud_appsec_rule_labels.test", "id"),
				),
			},
		},
	})
}

// TestAccAppSecRulesDataSource tests the rules list data source
func TestAccAppSecRulesDataSource(t *testing.T) {
	providerConfig := getProviderConfig(t, dotEnvPath, true)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
data "cortexcloud_appsec_rules" "test" {
  limit = 5
}
`,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.cortexcloud_appsec_rules.test", "rules.#"),
				),
			},
		},
	})
}

// TestAccAppSecRuleDataSource tests the single rule data source
func TestAccAppSecRuleDataSource(t *testing.T) {
	providerConfig := getProviderConfig(t, dotEnvPath, true)

	// Use a known existing rule ID from the environment
	ruleID := "APPSEC_CICD_125"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
data "cortexcloud_appsec_rule" "test" {
  id = "` + ruleID + `"
}
`,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("data.cortexcloud_appsec_rule.test", "id", ruleID),
					resource.TestCheckResourceAttrSet("data.cortexcloud_appsec_rule.test", "name"),
					resource.TestCheckResourceAttrSet("data.cortexcloud_appsec_rule.test", "severity"),
					resource.TestCheckResourceAttrSet("data.cortexcloud_appsec_rule.test", "scanner"),
				),
			},
		},
	})
}
