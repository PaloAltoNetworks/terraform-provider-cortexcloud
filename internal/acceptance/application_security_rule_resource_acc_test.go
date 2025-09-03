// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package acceptance

import (
	"fmt"
	"strconv"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccApplicationSecurityRuleResource(t *testing.T) {
	t.Log("Creating test configurations")

	resourceName := "cortexcloud_application_security_rule.test"
	resourceConfigCreate := fmt.Sprintf(
		AccTestAppSecRule1ConfigTmpl,
		strconv.Quote(AccTestAppSecRule1Name),
		strconv.Quote(AccTestAppSecRule1Category),
		strconv.Quote(AccTestAppSecRule1SubCategory),
		strconv.Quote(AccTestAppSecRule1Scanner),
		strconv.Quote(AccTestAppSecRule1Severity),
		strconv.Quote(AccTestAppSecRule1Description),
		AppSecRuleLabelsHCL(AccTestAppSecRule1Labels),
		strconv.Quote(AccTestAppSecRule1Framework1Name),
		strconv.Quote(AccTestAppSecRule1Framework1Definition),
		strconv.Quote(AccTestAppSecRule1Framework1DefinitionLink),
		strconv.Quote(AccTestAppSecRule1Framework1RemediationDescription),
	)
	resourceConfigUpdate := fmt.Sprintf(
		AccTestAppSecRule1ConfigTmpl,
		strconv.Quote(AccTestAppSecRule1Name),
		strconv.Quote(AccTestAppSecRule1Category),
		strconv.Quote(AccTestAppSecRule1SubCategory),
		strconv.Quote(AccTestAppSecRule1Scanner),
		strconv.Quote(AccTestAppSecRule1Severity),
		strconv.Quote(AccTestAppSecRule1DescriptionUpdated),
		AppSecRuleLabelsHCL(AccTestAppSecRule1LabelsUpdated),
		strconv.Quote(AccTestAppSecRule1Framework1Name),
		strconv.Quote(AccTestAppSecRule1Framework1Definition),
		strconv.Quote(AccTestAppSecRule1Framework1DefinitionLink),
		strconv.Quote(AccTestAppSecRule1Framework1RemediationDescription),
	)

	t.Log("Running tests")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				Config: resourceConfigCreate,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", AccTestAppSecRule1Name),
					resource.TestCheckResourceAttr(resourceName, "description", AccTestAppSecRule1Description),
					resource.TestCheckResourceAttr(resourceName, "category", AccTestAppSecRule1Category),
					resource.TestCheckResourceAttr(resourceName, "sub_category", AccTestAppSecRule1SubCategory),
					resource.TestCheckResourceAttr(resourceName, "scanner", AccTestAppSecRule1Scanner),
					resource.TestCheckResourceAttr(resourceName, "severity", AccTestAppSecRule1Severity),
					resource.TestCheckResourceAttr(resourceName, "labels.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "frameworks.0.name", AccTestAppSecRule1Framework1Name),
					resource.TestCheckResourceAttr(resourceName, "frameworks.0.definition_link", AccTestAppSecRule1Framework1DefinitionLink),
					resource.TestCheckResourceAttr(resourceName, "frameworks.0.remediation_description", AccTestAppSecRule1Framework1RemediationDescription),
				),
			},
			// Update and Read testing
			{
				Config: resourceConfigUpdate,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", AccTestAppSecRule1Name),
					resource.TestCheckResourceAttr(resourceName, "description", AccTestAppSecRule1DescriptionUpdated),
					resource.TestCheckResourceAttr(resourceName, "labels.#", "3"),
				),
			},
		},
	})
}
