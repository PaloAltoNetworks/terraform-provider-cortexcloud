// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package acceptance

//import (
//	"fmt"
//	"strconv"
//	"testing"
//
//	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
//)
//
//
//var (
//	// Unit Tests
//
//	AppSecRule1Name        = "test-rule"
//	AppSecRule1Description = "test description"
//	AppSecRule1Category    = enums.IacCategoryCompute.String()
//	AppSecRule1SubCategory = enums.IacSubCategoryComputeOverprovisioned.String()
//	AppSecRule1Scanner     = enums.ScannerIAC.String()
//	AppSecRule1Severity    = enums.SeverityInfo.String()
//	AppSecRule1Labels      = []string{
//		"label1",
//		"label2",
//	}
//	AppSecRule1Framework1Name                   = enums.FrameworkNameTerraform.String()
//	AppSecRule1Framework1Definition             = "scope:\n  provider: aws\ndefinition:\n  or:\n    - cond_type: attribute\n      resource_types:\n        - aws_instance\n      attribute: instance_type\n      operator: equals\n      value: t2.micro\n"
//	AppSecRule1Framework1DefinitionLink         = "http://docs.com/framework"
//	AppSecRule1Framework1RemediationDescription = "fix it"
//
//	AppSecUnitTestConfigTmpl = `provider "cortexcloud" {
//	cortex_cloud_api_url = %s
//	cortex_cloud_api_port = 443
//	cortex_cloud_api_key = "test"
//	cortex_cloud_api_key_id = 123
//}
//resource "cortexcloud_application_security_rule" "test" {
//	name     = %s
//	description = %s
//	severity = %s
//	scanner  = %s
//	frameworks = [
//		{
//			name = %s
//			definition = %s
//			definition_link = %s
//			remediation_description = %s
//		}
//	]
//	category = %s
//	sub_category = %s
//	labels   = %s
//}`
//
//	AppSecUnitTestCreateOrCloneResponseTmpl = `{
//	"id": "test-rule-id",
//	"name": %s,
//	"category": %s,
//	"cloudProvider": "aws",
//	"createdAt": {
//		"value": "2025-08-26T00:00:00.000Z"
//	},
//	"description": %s,
//	"detectionMethod": "some-method",
//	"docLink": "http://docs.com",
//	"domain": "test-domain",
//	"findingCategory": "test-finding-category",
//	"findingDocs": "http://docs.com/finding",
//	"findingTypeId": 123,
//	"findingTypeName": "test-finding",
//	"frameworks": [{
//		"name": %s,
//		"definition": %s,
//		"definitionLink": %s,
//		"remediationDescription": %s
//	}],
//	"isCustom": true,
//	"isEnabled": true,
//	"labels": %s,
//	"mitreTactics": ["tactic1"],
//	"mitreTechniques": ["technique1"],
//	"owner": "test-owner",
//	"scanner": %s,
//	"severity": %s,
//	"source": "custom",
//	"subCategory": %s,
//	"updatedAt": {
//		"value": "2025-08-26T00:00:00.000Z"
//	}
//}`
//
//	AppSecUnitTestGetResponseTmpl = `{
//	"id": "test-rule-id",
//	"name": %s,
//	"category": %s,
//	"cloudProvider": "aws",
//	"createdAt": {
//		"value": "2025-08-26T00:00:00.000Z"
//	},
//	"description": %s,
//	"detectionMethod": "some-method",
//	"docLink": "http://docs.com",
//	"domain": "test-domain",
//	"findingCategory": "test-finding-category",
//	"findingDocs": "http://docs.com/finding",
//	"findingTypeId": 123,
//	"findingTypeName": "test-finding",
//	"frameworks": [{
//		"name": %s,
//		"definition": %s,
//		"definitionLink": %s,
//		"remediationDescription": %s
//	}],
//	"isCustom": true,
//	"isEnabled": true,
//	"labels": %s,
//	"mitreTactics": ["tactic1"],
//	"mitreTechniques": ["technique1"],
//	"owner": "test-owner",
//	"scanner": %s,
//	"severity": %s,
//	"source": "custom",
//	"subCategory": %s,
//	"updatedAt": {
//		"value": "2025-08-26T00:00:00.000Z"
//	}
//}`
//
//	// Acceptance Tests
//
//	AccTestAppSecRule1Name        = "tf-provider-acc-test-rule"
//	AccTestAppSecRule1Description = "acc test description"
//	AccTestAppSecRule1Category    = enums.IacCategoryCompute.String()
//	AccTestAppSecRule1SubCategory = enums.IacSubCategoryComputeOverprovisioned.String()
//	AccTestAppSecRule1Scanner     = enums.ScannerIAC.String()
//	AccTestAppSecRule1Severity    = enums.SeverityInfo.String()
//	AccTestAppSecRule1Labels      = []string{
//		"accTestLabel1",
//		"accTestLabel2",
//	}
//	AccTestAppSecRule1Framework1Name       = enums.FrameworkNameTerraform.String()
//	AccTestAppSecRule1Framework1Definition = "scope:\n  provider: aws\ndefinition:\n  or:\n    - cond_type: attribute\n      resource_types:\n        - aws_instance\n      attribute: instance_type\n      operator: equals\n      value: t2.micro\n"
//	//AccTestAppSecRule1Framework1DefinitionLink = "http://docs.com/framework"
//	//AccTestAppSecRule1Framework1RemediationDescription = "fix it"
//	AccTestAppSecRule1Framework1DefinitionLink         = ""
//	AccTestAppSecRule1Framework1RemediationDescription = ""
//
//	AccTestAppSecRule1LabelsUpdated = []string{
//		"accTestLabel1",
//		"accTestLabel2",
//		"accTestLabel3",
//	}
//	AccTestAppSecRule1DescriptionUpdated = "updated acc test description"
//
//	AccTestAppSecRule1ConfigTmpl = `resource "cortexcloud_application_security_rule" "test" {
//  name         = %s
//  category     = %s
//  sub_category = %s
//  scanner      = %s
//  severity     = %s
//  description  = %s
//  labels       = %s
//  frameworks = [
//    {
//      name = %s
//      definition = %s
//      definition_link = %s
//      remediation_description = %s
//    }
//  ]
//}`
//)
//
//// AppSecRuleLabelsHCL returns the provided labels as a HCL string.
//func AppSecRuleLabelsHCL(labels []string) string {
//	return fmt.Sprintf(`["%s"]`, strings.Join(labels, "\", \""))
//}
//
//func TestAccApplicationSecurityRuleResource(t *testing.T) {
//	t.Log("Creating test configurations")
//
//	resourceName := "cortexcloud_application_security_rule.test"
//	resourceConfigCreate := fmt.Sprintf(
//		AccTestAppSecRule1ConfigTmpl,
//		strconv.Quote(AccTestAppSecRule1Name),
//		strconv.Quote(AccTestAppSecRule1Category),
//		strconv.Quote(AccTestAppSecRule1SubCategory),
//		strconv.Quote(AccTestAppSecRule1Scanner),
//		strconv.Quote(AccTestAppSecRule1Severity),
//		strconv.Quote(AccTestAppSecRule1Description),
//		AppSecRuleLabelsHCL(AccTestAppSecRule1Labels),
//		strconv.Quote(AccTestAppSecRule1Framework1Name),
//		strconv.Quote(AccTestAppSecRule1Framework1Definition),
//		strconv.Quote(AccTestAppSecRule1Framework1DefinitionLink),
//		strconv.Quote(AccTestAppSecRule1Framework1RemediationDescription),
//	)
//	resourceConfigUpdate := fmt.Sprintf(
//		AccTestAppSecRule1ConfigTmpl,
//		strconv.Quote(AccTestAppSecRule1Name),
//		strconv.Quote(AccTestAppSecRule1Category),
//		strconv.Quote(AccTestAppSecRule1SubCategory),
//		strconv.Quote(AccTestAppSecRule1Scanner),
//		strconv.Quote(AccTestAppSecRule1Severity),
//		strconv.Quote(AccTestAppSecRule1DescriptionUpdated),
//		AppSecRuleLabelsHCL(AccTestAppSecRule1LabelsUpdated),
//		strconv.Quote(AccTestAppSecRule1Framework1Name),
//		strconv.Quote(AccTestAppSecRule1Framework1Definition),
//		strconv.Quote(AccTestAppSecRule1Framework1DefinitionLink),
//		strconv.Quote(AccTestAppSecRule1Framework1RemediationDescription),
//	)
//
//	t.Log("Running tests")
//
//	resource.Test(t, resource.TestCase{
//		PreCheck:                 func() { testAccPreCheck(t) },
//		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
//		Steps: []resource.TestStep{
//			// Create and Read testing
//			{
//				Config: resourceConfigCreate,
//				Check: resource.ComposeAggregateTestCheckFunc(
//					resource.TestCheckResourceAttr(resourceName, "name", AccTestAppSecRule1Name),
//					resource.TestCheckResourceAttr(resourceName, "description", AccTestAppSecRule1Description),
//					resource.TestCheckResourceAttr(resourceName, "category", AccTestAppSecRule1Category),
//					resource.TestCheckResourceAttr(resourceName, "sub_category", AccTestAppSecRule1SubCategory),
//					resource.TestCheckResourceAttr(resourceName, "scanner", AccTestAppSecRule1Scanner),
//					resource.TestCheckResourceAttr(resourceName, "severity", AccTestAppSecRule1Severity),
//					resource.TestCheckResourceAttr(resourceName, "labels.#", "2"),
//					resource.TestCheckResourceAttr(resourceName, "frameworks.0.name", AccTestAppSecRule1Framework1Name),
//					resource.TestCheckResourceAttr(resourceName, "frameworks.0.definition_link", AccTestAppSecRule1Framework1DefinitionLink),
//					resource.TestCheckResourceAttr(resourceName, "frameworks.0.remediation_description", AccTestAppSecRule1Framework1RemediationDescription),
//				),
//			},
//			// Update and Read testing
//			{
//				Config: resourceConfigUpdate,
//				Check: resource.ComposeAggregateTestCheckFunc(
//					resource.TestCheckResourceAttr(resourceName, "name", AccTestAppSecRule1Name),
//					resource.TestCheckResourceAttr(resourceName, "description", AccTestAppSecRule1DescriptionUpdated),
//					resource.TestCheckResourceAttr(resourceName, "labels.#", "3"),
//				),
//			},
//		},
//	})
//}
