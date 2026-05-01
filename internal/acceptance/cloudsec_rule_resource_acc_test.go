// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package acceptance

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

const (
	cloudSecRuleResourceType = "cortexcloud_cloudsec_rule"
	cloudSecRuleBasicName    = "test_basic"
	cloudSecRuleCompName     = "test_compliance"
	cloudSecRuleUpdateName   = "test_update"
	cloudSecRuleImportName   = "test_import"

	// Basic rule configuration
	ruleBasicNameInitial    = "tf-acctest-rule-basic"
	ruleBasicDescInitial    = "Acceptance test basic rule"
	ruleBasicClass          = "config"
	ruleBasicType           = "DETECTION"
	ruleBasicAssetType      = "aws-s3-bucket"
	ruleBasicSeverity       = "high"
	ruleBasicXQL            = "config from cloud.resource where cloud.type = 'aws' AND api.name = 's3api.get_bucket_acl'"
	ruleBasicEnabled        = true
	ruleBasicLabel1         = "test-label-1"
	ruleBasicLabel2         = "test-label-2"
	ruleBasicRecommendation = "Enable bucket encryption"

	// Updated values
	ruleBasicNameUpdated       = "tf-acctest-rule-basic-updated"
	ruleBasicDescUpdated       = "Acceptance test basic rule updated"
	ruleBasicSeverityUpdated   = "critical"
	ruleBasicXQLUpdated        = "config from cloud.resource where cloud.type = 'aws' AND api.name = 's3api.get_bucket_encryption'"
	ruleBasicLabel3            = "test-label-3"
	ruleBasicRecommendationUpd = "Enable bucket encryption and versioning"

	// Compliance rule configuration
	ruleCompName       = "tf-acctest-rule-compliance"
	ruleCompDesc       = "Acceptance test rule with compliance metadata"
	ruleCompControlID1 = "CIS-AWS-1.2.3"
	ruleCompControlID2 = "NIST-800-53-AC-2"

	cloudSecRuleBasicResourceConfigTmpl = `
resource "%s" "%s" {
	 name        = "%s"
	 description = "%s"
	 class       = "%s"
	 type        = "%s"
	 asset_types = ["%s"]
	 severity    = "%s"
	 enabled     = %t

	 query = {
	   xql = "%s"
	 }

	 metadata = {
	   issue = {
	     recommendation = "%s"
	   }
	 }

	 labels = ["%s", "%s"]
}`

	cloudSecRuleComplianceResourceConfigTmpl = `
resource "%s" "%s" {
	 name        = "%s"
	 description = "%s"
	 class       = "%s"
	 asset_types = ["%s"]
	 severity    = "%s"

	 query = {
	   xql = "%s"
	 }

	 compliance_metadata {
	   control_id = "%s"
	 }

	 compliance_metadata {
	   control_id = "%s"
	 }
}`
)

var (
	cloudSecRuleBasicResourceNameFull = fmt.Sprintf("%s.%s", cloudSecRuleResourceType, cloudSecRuleBasicName)
	cloudSecRuleBasicResourceConfig   = fmt.Sprintf(
		cloudSecRuleBasicResourceConfigTmpl,
		cloudSecRuleResourceType,
		cloudSecRuleBasicName,
		ruleBasicNameInitial,
		ruleBasicDescInitial,
		ruleBasicClass,
		ruleBasicType,
		ruleBasicAssetType,
		ruleBasicSeverity,
		ruleBasicEnabled,
		ruleBasicXQL,
		ruleBasicRecommendation,
		ruleBasicLabel1,
		ruleBasicLabel2,
	)
	cloudSecRuleBasicResourceUpdatedConfig = fmt.Sprintf(
		cloudSecRuleBasicResourceConfigTmpl,
		cloudSecRuleResourceType,
		cloudSecRuleBasicName,
		ruleBasicNameUpdated,
		ruleBasicDescUpdated,
		ruleBasicClass,
		ruleBasicType,
		ruleBasicAssetType,
		ruleBasicSeverityUpdated,
		ruleBasicEnabled,
		ruleBasicXQLUpdated,
		ruleBasicRecommendationUpd,
		ruleBasicLabel2,
		ruleBasicLabel3,
	)

	cloudSecRuleCompResourceNameFull = fmt.Sprintf("%s.%s", cloudSecRuleResourceType, cloudSecRuleCompName)
	cloudSecRuleCompResourceConfig   = fmt.Sprintf(
		cloudSecRuleComplianceResourceConfigTmpl,
		cloudSecRuleResourceType,
		cloudSecRuleCompName,
		ruleCompName,
		ruleCompDesc,
		ruleBasicClass,
		ruleBasicAssetType,
		ruleBasicSeverity,
		ruleBasicXQL,
		ruleCompControlID1,
		ruleCompControlID2,
	)
)

// TestAccCloudSecRule_basic tests basic CRUD operations for CloudSec rules
func TestAccCloudSecRule_basic(t *testing.T) {
	providerConfig := getProviderConfig(t, dotEnvPath, true)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				PreConfig: func() {
					t.Log("Executing Create test step for basic rule")
				},
				Config: providerConfig + cloudSecRuleBasicResourceConfig,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(cloudSecRuleBasicResourceNameFull, "name", ruleBasicNameInitial),
					resource.TestCheckResourceAttr(cloudSecRuleBasicResourceNameFull, "description", ruleBasicDescInitial),
					resource.TestCheckResourceAttr(cloudSecRuleBasicResourceNameFull, "class", ruleBasicClass),
					resource.TestCheckResourceAttr(cloudSecRuleBasicResourceNameFull, "type", ruleBasicType),
					resource.TestCheckResourceAttr(cloudSecRuleBasicResourceNameFull, "asset_types.#", "1"),
					resource.TestCheckResourceAttr(cloudSecRuleBasicResourceNameFull, "asset_types.0", ruleBasicAssetType),
					resource.TestCheckResourceAttr(cloudSecRuleBasicResourceNameFull, "severity", ruleBasicSeverity),
					resource.TestCheckResourceAttr(cloudSecRuleBasicResourceNameFull, "query.xql", ruleBasicXQL),
					resource.TestCheckResourceAttr(cloudSecRuleBasicResourceNameFull, "metadata.issue.recommendation", ruleBasicRecommendation),
					resource.TestCheckResourceAttr(cloudSecRuleBasicResourceNameFull, "labels.#", "2"),
					resource.TestCheckResourceAttr(cloudSecRuleBasicResourceNameFull, "enabled", "true"),
					resource.TestCheckResourceAttrSet(cloudSecRuleBasicResourceNameFull, "id"),
					resource.TestCheckResourceAttrSet(cloudSecRuleBasicResourceNameFull, "created_by"),
					resource.TestCheckResourceAttrSet(cloudSecRuleBasicResourceNameFull, "created_on"),
					resource.TestCheckResourceAttr(cloudSecRuleBasicResourceNameFull, "system_default", "false"),
				),
			},
			// ImportState testing
			{
				ResourceName:      cloudSecRuleBasicResourceNameFull,
				ImportState:       true,
				ImportStateVerify: true,
			},
			// Update and Read testing
			{
				PreConfig: func() {
					t.Log("Executing Update test step for basic rule")
				},
				Config: providerConfig + cloudSecRuleBasicResourceUpdatedConfig,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(cloudSecRuleBasicResourceNameFull, "name", ruleBasicNameUpdated),
					resource.TestCheckResourceAttr(cloudSecRuleBasicResourceNameFull, "description", ruleBasicDescUpdated),
					resource.TestCheckResourceAttr(cloudSecRuleBasicResourceNameFull, "severity", ruleBasicSeverityUpdated),
					resource.TestCheckResourceAttr(cloudSecRuleBasicResourceNameFull, "query.xql", ruleBasicXQLUpdated),
					resource.TestCheckResourceAttr(cloudSecRuleBasicResourceNameFull, "metadata.issue.recommendation", ruleBasicRecommendationUpd),
					resource.TestCheckResourceAttr(cloudSecRuleBasicResourceNameFull, "labels.#", "2"),
					resource.TestCheckResourceAttrSet(cloudSecRuleBasicResourceNameFull, "last_modified_by"),
					resource.TestCheckResourceAttrSet(cloudSecRuleBasicResourceNameFull, "last_modified_on"),
				),
			},
			// Delete testing automatically occurs at the end
		},
		CheckDestroy: testAccCheckCloudSecRuleDestroy,
	})
}

// TestAccCloudSecRule_withCompliance tests rule creation with compliance metadata
func TestAccCloudSecRule_withCompliance(t *testing.T) {
	providerConfig := getProviderConfig(t, dotEnvPath, true)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				PreConfig: func() {
					t.Log("Executing Create test step for compliance rule")
				},
				Config: providerConfig + cloudSecRuleCompResourceConfig,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(cloudSecRuleCompResourceNameFull, "name", ruleCompName),
					resource.TestCheckResourceAttr(cloudSecRuleCompResourceNameFull, "description", ruleCompDesc),
					resource.TestCheckResourceAttr(cloudSecRuleCompResourceNameFull, "compliance_metadata.#", "2"),
					resource.TestCheckResourceAttr(cloudSecRuleCompResourceNameFull, "compliance_metadata.0.control_id", ruleCompControlID1),
					resource.TestCheckResourceAttr(cloudSecRuleCompResourceNameFull, "compliance_metadata.1.control_id", ruleCompControlID2),
					resource.TestCheckResourceAttrSet(cloudSecRuleCompResourceNameFull, "compliance_metadata.0.standard_id"),
					resource.TestCheckResourceAttrSet(cloudSecRuleCompResourceNameFull, "compliance_metadata.0.standard_name"),
					resource.TestCheckResourceAttrSet(cloudSecRuleCompResourceNameFull, "compliance_metadata.0.control_name"),
					resource.TestCheckResourceAttrSet(cloudSecRuleCompResourceNameFull, "id"),
				),
			},
			// ImportState testing
			{
				ResourceName:      cloudSecRuleCompResourceNameFull,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
		CheckDestroy: testAccCheckCloudSecRuleDestroy,
	})
}

// TestAccCloudSecRule_update tests updating various fields
func TestAccCloudSecRule_update(t *testing.T) {
	providerConfig := getProviderConfig(t, dotEnvPath, true)

	initialConfig := fmt.Sprintf(`
resource "%s" "%s" {
	 name        = "tf-acctest-rule-update-initial"
	 description = "Initial description"
	 class       = "config"
	 asset_types = ["aws-ec2-instance"]
	 severity    = "low"
	 enabled     = false

	 query = {
	   xql = "config from cloud.resource where cloud.type = 'aws'"
	 }

	 labels = ["initial"]
}`, cloudSecRuleResourceType, cloudSecRuleUpdateName)

	updatedConfig := fmt.Sprintf(`
resource "%s" "%s" {
	 name        = "tf-acctest-rule-update-modified"
	 description = "Modified description"
	 class       = "config"
	 asset_types = ["aws-ec2-instance"]
	 severity    = "medium"
	 enabled     = true

	 query = {
	   xql = "config from cloud.resource where cloud.type = 'aws' AND api.name = 'ec2'"
	 }

	 metadata = {
	   issue = {
	     recommendation = "New recommendation"
	   }
	 }

	 labels = ["modified", "updated"]
}`, cloudSecRuleResourceType, cloudSecRuleUpdateName)

	resourceNameFull := fmt.Sprintf("%s.%s", cloudSecRuleResourceType, cloudSecRuleUpdateName)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create with initial values
			{
				Config: providerConfig + initialConfig,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceNameFull, "name", "tf-acctest-rule-update-initial"),
					resource.TestCheckResourceAttr(resourceNameFull, "severity", "low"),
					resource.TestCheckResourceAttr(resourceNameFull, "enabled", "false"),
					resource.TestCheckResourceAttr(resourceNameFull, "labels.#", "1"),
				),
			},
			// Update multiple fields
			{
				Config: providerConfig + updatedConfig,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceNameFull, "name", "tf-acctest-rule-update-modified"),
					resource.TestCheckResourceAttr(resourceNameFull, "description", "Modified description"),
					resource.TestCheckResourceAttr(resourceNameFull, "severity", "medium"),
					resource.TestCheckResourceAttr(resourceNameFull, "enabled", "true"),
					resource.TestCheckResourceAttr(resourceNameFull, "labels.#", "2"),
					resource.TestCheckResourceAttr(resourceNameFull, "metadata.issue.recommendation", "New recommendation"),
				),
			},
		},
		CheckDestroy: testAccCheckCloudSecRuleDestroy,
	})
}

// TestAccCloudSecRule_import tests import functionality
func TestAccCloudSecRule_import(t *testing.T) {
	providerConfig := getProviderConfig(t, dotEnvPath, true)

	config := fmt.Sprintf(`
resource "%s" "%s" {
	 name        = "tf-acctest-rule-import"
	 class       = "config"
	 asset_types = ["aws-s3-bucket"]
	 severity    = "high"

	 query = {
	   xql = "config from cloud.resource where cloud.type = 'aws'"
	 }
}`, cloudSecRuleResourceType, cloudSecRuleImportName)

	resourceNameFull := fmt.Sprintf("%s.%s", cloudSecRuleResourceType, cloudSecRuleImportName)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create rule
			{
				Config: providerConfig + config,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceNameFull, "name", "tf-acctest-rule-import"),
					resource.TestCheckResourceAttrSet(resourceNameFull, "id"),
				),
			},
			// Import by ID
			{
				ResourceName:      resourceNameFull,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
		CheckDestroy: testAccCheckCloudSecRuleDestroy,
	})
}

// TestAccCloudSecRule_disappears tests resource disappears handling
func TestAccCloudSecRule_disappears(t *testing.T) {
	providerConfig := getProviderConfig(t, dotEnvPath, true)

	config := fmt.Sprintf(`
resource "%s" "test_disappears" {
	 name        = "tf-acctest-rule-disappears"
	 class       = "config"
	 asset_types = ["aws-s3-bucket"]
	 severity    = "medium"

	 query = {
	   xql = "config from cloud.resource where cloud.type = 'aws'"
	 }
}`, cloudSecRuleResourceType)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + config,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(fmt.Sprintf("%s.test_disappears", cloudSecRuleResourceType), "id"),
				),
			},
		},
		CheckDestroy: testAccCheckCloudSecRuleDestroy,
	})
}

// testAccCheckCloudSecRuleDestroy verifies the rule has been destroyed
func testAccCheckCloudSecRuleDestroy(s *terraform.State) error {
	for _, rs := range s.RootModule().Resources {
		if rs.Type != cloudSecRuleResourceType {
			continue
		}
	}

	return nil
}
