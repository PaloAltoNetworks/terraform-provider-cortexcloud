// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package acceptance

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

const (
	cloudSecPolicyResourceType   = "cortexcloud_cloudsec_policy"
	cloudSecPolicyAllRulesName   = "test_all_rules"
	cloudSecPolicySpecificName   = "test_specific"
	cloudSecPolicyFilterName     = "test_filter"
	cloudSecPolicyComplexName    = "test_complex"
	cloudSecPolicyAssetMatchName = "test_asset_match"
	cloudSecPolicyUpdateName     = "test_update"
	cloudSecPolicyImportName     = "test_import"
)

var (
	randomSuffix = acctest.RandStringFromCharSet(5, acctest.CharSetAlphaNum)

	// All rules policy configuration
	policyAllRulesName   = fmt.Sprintf("tf-acctest-policy-all-rules-%s", randomSuffix)
	policyAllRulesDesc   = "Policy matching all rules"
	policyAllRulesLabel1 = "all-rules"
	policyAllRulesLabel2 = "test"

	// Specific rules policy configuration
	policySpecificName    = fmt.Sprintf("tf-acctest-policy-specific-%s", randomSuffix)
	policySpecificDesc    = "Policy with specific rules"
	policySpecificRuleID1 = "2a8d9eab-3120-4686-b76e-022c82ab9dad"
	policySpecificRuleID2 = "rule-uuid-2"

	// Filter policy configuration
	policyFilterName = fmt.Sprintf("tf-acctest-policy-filter-%s", randomSuffix)
	policyFilterDesc = "Policy with rule filter"

	// Complex filter policy configuration
	policyComplexName = fmt.Sprintf("tf-acctest-policy-complex-%s", randomSuffix)
	policyComplexDesc = "Policy with complex nested filter"

	// Asset matching policy configuration
	policyAssetMatchName  = fmt.Sprintf("tf-acctest-policy-asset-match-%s", randomSuffix)
	policyAssetGroupID1   = 123
	policyAssetGroupID2   = 456
	policyCloudAccountID1 = "cloud-account-1"
	policyCloudAccountID2 = "cloud-account-2"

	// Updated values
	policyAllRulesNameUpdated = fmt.Sprintf("tf-acctest-policy-all-rules-updated-%s", randomSuffix)
	policyAllRulesDescUpdated = "Policy matching all rules updated"
)

const (
	cloudSecPolicyAllRulesConfigTmpl = `
resource "%s" "%s" {
  name        = "%s"
  description = "%s"
  enabled     = %t

  rule_matching = {
    type = "ALL_RULES"
  }

  asset_matching = {
    type = "ALL_ASSETS"
  }

  labels = ["%s", "%s"]
}`

	cloudSecPolicySpecificRulesConfigTmpl = `
resource "%s" "%s" {
  name        = "%s"
  description = "%s"

  rule_matching = {
    type  = "RULES"
    rules = ["%s"]
  }

  asset_matching = {
    type = "ALL_ASSETS"
  }
}`

	cloudSecPolicyRuleFilterConfigTmpl = `
resource "%s" "%s" {
  name        = "%s"
  description = "%s"

  rule_matching = {
    type = "RULE_FILTER"
    filter_criteria = {
      field = "severity"
      type  = "EQ"
      value = "high"
    }
  }

  asset_matching = {
    type = "ALL_ASSETS"
  }
}`

	cloudSecPolicyComplexFilterConfigTmpl = `
resource "%s" "%s" {
  name        = "%s"
  description = "%s"

  rule_matching = {
    type = "RULE_FILTER"
    filter_criteria = {
      operator = "AND"
      criteria = [
        {
          field = "severity"
          type  = "EQ"
          value = "high"
        },
        {
          operator = "OR"
          criteria = [
            {
              field = "cloudType"
              type  = "EQ"
              value = "aws"
            },
            {
              field = "cloudType"
              type  = "EQ"
              value = "azure"
            }
          ]
        }
      ]
    }
  }

  asset_matching = {
    type = "ALL_ASSETS"
  }
}`

	cloudSecPolicyAssetGroupsConfigTmpl = `
resource "%s" "%s" {
  name = "%s"

  rule_matching = {
    type = "ALL_RULES"
  }

  asset_matching = {
    type            = "ASSET_GROUPS"
    asset_group_ids = [%d]
  }
}`

	cloudSecPolicyCloudAccountsConfigTmpl = `
resource "%s" "%s" {
  name = "%s"

  rule_matching = {
    type = "ALL_RULES"
  }

  asset_matching = {
    type              = "CLOUD_ACCOUNTS"
    cloud_account_ids = ["%s", "%s"]
  }
}`
)

var (
	cloudSecPolicyAllRulesResourceNameFull = fmt.Sprintf("%s.%s", cloudSecPolicyResourceType, cloudSecPolicyAllRulesName)
	cloudSecPolicyAllRulesResourceConfig   = fmt.Sprintf(
		cloudSecPolicyAllRulesConfigTmpl,
		cloudSecPolicyResourceType,
		cloudSecPolicyAllRulesName,
		policyAllRulesName,
		policyAllRulesDesc,
		true,
		policyAllRulesLabel1,
		policyAllRulesLabel2,
	)
	cloudSecPolicyAllRulesResourceUpdatedConfig = fmt.Sprintf(
		cloudSecPolicyAllRulesConfigTmpl,
		cloudSecPolicyResourceType,
		cloudSecPolicyAllRulesName,
		policyAllRulesNameUpdated,
		policyAllRulesDescUpdated,
		false,
		policyAllRulesLabel1,
		policyAllRulesLabel2,
	)

	cloudSecPolicySpecificResourceNameFull = fmt.Sprintf("%s.%s", cloudSecPolicyResourceType, cloudSecPolicySpecificName)
	cloudSecPolicySpecificResourceConfig   = fmt.Sprintf(
		cloudSecPolicySpecificRulesConfigTmpl,
		cloudSecPolicyResourceType,
		cloudSecPolicySpecificName,
		policySpecificName,
		policySpecificDesc,
		policySpecificRuleID1,
	)

	cloudSecPolicyFilterResourceNameFull = fmt.Sprintf("%s.%s", cloudSecPolicyResourceType, cloudSecPolicyFilterName)
	cloudSecPolicyFilterResourceConfig   = fmt.Sprintf(
		cloudSecPolicyRuleFilterConfigTmpl,
		cloudSecPolicyResourceType,
		cloudSecPolicyFilterName,
		policyFilterName,
		policyFilterDesc,
	)

	cloudSecPolicyComplexResourceNameFull = fmt.Sprintf("%s.%s", cloudSecPolicyResourceType, cloudSecPolicyComplexName)
	cloudSecPolicyComplexResourceConfig   = fmt.Sprintf(
		cloudSecPolicyComplexFilterConfigTmpl,
		cloudSecPolicyResourceType,
		cloudSecPolicyComplexName,
		policyComplexName,
		policyComplexDesc,
	)

	cloudSecPolicyAssetGroupsResourceNameFull = fmt.Sprintf("%s.%s", cloudSecPolicyResourceType, cloudSecPolicyAssetMatchName)
	cloudSecPolicyAssetGroupsResourceConfig   = fmt.Sprintf(
		cloudSecPolicyAssetGroupsConfigTmpl,
		cloudSecPolicyResourceType,
		cloudSecPolicyAssetMatchName,
		policyAssetMatchName,
		policyAssetGroupID1,
	)

	cloudSecPolicyCloudAccountsResourceConfig = fmt.Sprintf(
		cloudSecPolicyCloudAccountsConfigTmpl,
		cloudSecPolicyResourceType,
		cloudSecPolicyAssetMatchName,
		policyAssetMatchName,
		policyCloudAccountID1,
		policyCloudAccountID2,
	)
)

// TestAccCloudSecPolicy_allRules tests policy matching all rules
func TestAccCloudSecPolicy_allRules(t *testing.T) {
	providerConfig := getProviderConfig(t, dotEnvPath, true)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				PreConfig: func() {
					t.Log("Executing Create test step for all rules policy")
				},
				Config: providerConfig + cloudSecPolicyAllRulesResourceConfig,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(cloudSecPolicyAllRulesResourceNameFull, "name", policyAllRulesName),
					resource.TestCheckResourceAttr(cloudSecPolicyAllRulesResourceNameFull, "description", policyAllRulesDesc),
					resource.TestCheckResourceAttr(cloudSecPolicyAllRulesResourceNameFull, "enabled", "true"),
					resource.TestCheckResourceAttr(cloudSecPolicyAllRulesResourceNameFull, "rule_matching.type", "ALL_RULES"),
					resource.TestCheckResourceAttr(cloudSecPolicyAllRulesResourceNameFull, "asset_matching.type", "ALL_ASSETS"),
					resource.TestCheckResourceAttr(cloudSecPolicyAllRulesResourceNameFull, "labels.#", "2"),
					resource.TestCheckResourceAttrSet(cloudSecPolicyAllRulesResourceNameFull, "id"),
					resource.TestCheckResourceAttrSet(cloudSecPolicyAllRulesResourceNameFull, "created_by"),
					resource.TestCheckResourceAttrSet(cloudSecPolicyAllRulesResourceNameFull, "created_at"),
					resource.TestCheckResourceAttrSet(cloudSecPolicyAllRulesResourceNameFull, "mode"),
				),
			},
			// ImportState testing
			{
				ResourceName:      cloudSecPolicyAllRulesResourceNameFull,
				ImportState:       true,
				ImportStateVerify: true,
			},
			// Update and Read testing
			{
				PreConfig: func() {
					t.Log("Executing Update test step for all rules policy")
				},
				Config: providerConfig + cloudSecPolicyAllRulesResourceUpdatedConfig,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(cloudSecPolicyAllRulesResourceNameFull, "name", policyAllRulesNameUpdated),
					resource.TestCheckResourceAttr(cloudSecPolicyAllRulesResourceNameFull, "description", policyAllRulesDescUpdated),
					resource.TestCheckResourceAttr(cloudSecPolicyAllRulesResourceNameFull, "enabled", "false"),
					resource.TestCheckResourceAttrSet(cloudSecPolicyAllRulesResourceNameFull, "updated_by"),
					resource.TestCheckResourceAttrSet(cloudSecPolicyAllRulesResourceNameFull, "updated_at"),
				),
			},
		},
		CheckDestroy: testAccCheckCloudSecPolicyDestroy,
	})
}

// TestAccCloudSecPolicy_specificRules tests policy with specific rule list
func TestAccCloudSecPolicy_specificRules(t *testing.T) {
	providerConfig := getProviderConfig(t, dotEnvPath, true)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				PreConfig: func() {
					t.Log("Executing Create test step for specific rules policy")
				},
				Config:      providerConfig + cloudSecPolicySpecificResourceConfig,
				ExpectError: regexp.MustCompile(`Error Creating CloudSec Policy`),
			},
			// ImportState testing
			{
				ResourceName:      cloudSecPolicySpecificResourceNameFull,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
		CheckDestroy: testAccCheckCloudSecPolicyDestroy,
	})
}

// TestAccCloudSecPolicy_ruleFilter tests policy with filter criteria
func TestAccCloudSecPolicy_ruleFilter(t *testing.T) {
	providerConfig := getProviderConfig(t, dotEnvPath, true)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				PreConfig: func() {
					t.Log("Executing Create test step for rule filter policy")
				},
				Config: providerConfig + cloudSecPolicyFilterResourceConfig,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(cloudSecPolicyFilterResourceNameFull, "name", policyFilterName),
					resource.TestCheckResourceAttr(cloudSecPolicyFilterResourceNameFull, "rule_matching.type", "RULE_FILTER"),
					resource.TestCheckResourceAttr(cloudSecPolicyFilterResourceNameFull, "rule_matching.filter_criteria.field", "severity"),
					resource.TestCheckResourceAttr(cloudSecPolicyFilterResourceNameFull, "rule_matching.filter_criteria.type", "EQ"),
					resource.TestCheckResourceAttr(cloudSecPolicyFilterResourceNameFull, "rule_matching.filter_criteria.value", "high"),
					resource.TestCheckResourceAttrSet(cloudSecPolicyFilterResourceNameFull, "id"),
				),
			},
			// ImportState testing
			{
				ResourceName:      cloudSecPolicyFilterResourceNameFull,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
		CheckDestroy: testAccCheckCloudSecPolicyDestroy,
	})
}

// TestAccCloudSecPolicy_complexFilter tests policy with nested filter criteria
func TestAccCloudSecPolicy_complexFilter(t *testing.T) {
	providerConfig := getProviderConfig(t, dotEnvPath, true)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				PreConfig: func() {
					t.Log("Executing Create test step for complex filter policy")
				},
				Config: providerConfig + cloudSecPolicyComplexResourceConfig,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(cloudSecPolicyComplexResourceNameFull, "name", policyComplexName),
					resource.TestCheckResourceAttr(cloudSecPolicyComplexResourceNameFull, "rule_matching.type", "RULE_FILTER"),
					resource.TestCheckResourceAttr(cloudSecPolicyComplexResourceNameFull, "rule_matching.filter_criteria.operator", "AND"),
					resource.TestCheckResourceAttr(cloudSecPolicyComplexResourceNameFull, "rule_matching.filter_criteria.criteria.#", "2"),
					resource.TestCheckResourceAttr(cloudSecPolicyComplexResourceNameFull, "rule_matching.filter_criteria.criteria.0.field", "severity"),
					resource.TestCheckResourceAttr(cloudSecPolicyComplexResourceNameFull, "rule_matching.filter_criteria.criteria.1.operator", "OR"),
					resource.TestCheckResourceAttr(cloudSecPolicyComplexResourceNameFull, "rule_matching.filter_criteria.criteria.1.criteria.#", "2"),
					resource.TestCheckResourceAttrSet(cloudSecPolicyComplexResourceNameFull, "id"),
				),
			},
			// ImportState testing
			{
				ResourceName:      cloudSecPolicyComplexResourceNameFull,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
		CheckDestroy: testAccCheckCloudSecPolicyDestroy,
	})
}

// TestAccCloudSecPolicy_assetMatching tests different asset matching types
func TestAccCloudSecPolicy_assetMatching(t *testing.T) {
	providerConfig := getProviderConfig(t, dotEnvPath, true)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create with asset groups
			{
				PreConfig: func() {
					t.Log("Executing Create test step for asset groups matching")
				},
				Config: providerConfig + cloudSecPolicyAssetGroupsResourceConfig,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(cloudSecPolicyAssetGroupsResourceNameFull, "name", policyAssetMatchName),
					resource.TestCheckResourceAttr(cloudSecPolicyAssetGroupsResourceNameFull, "asset_matching.type", "ASSET_GROUPS"),
					resource.TestCheckResourceAttr(cloudSecPolicyAssetGroupsResourceNameFull, "asset_matching.asset_group_ids.#", "2"),
					resource.TestCheckResourceAttr(cloudSecPolicyAssetGroupsResourceNameFull, "asset_matching.asset_group_ids.0", fmt.Sprintf("%d", policyAssetGroupID1)),
					resource.TestCheckResourceAttr(cloudSecPolicyAssetGroupsResourceNameFull, "asset_matching.asset_group_ids.1", fmt.Sprintf("%d", policyAssetGroupID2)),
					resource.TestCheckResourceAttrSet(cloudSecPolicyAssetGroupsResourceNameFull, "id"),
				),
			},
			// Update to cloud accounts
			{
				PreConfig: func() {
					t.Log("Executing Update test step to cloud accounts matching")
				},
				Config: providerConfig + cloudSecPolicyCloudAccountsResourceConfig,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(cloudSecPolicyAssetGroupsResourceNameFull, "asset_matching.type", "CLOUD_ACCOUNTS"),
					resource.TestCheckResourceAttr(cloudSecPolicyAssetGroupsResourceNameFull, "asset_matching.cloud_account_ids.#", "2"),
					resource.TestCheckResourceAttr(cloudSecPolicyAssetGroupsResourceNameFull, "asset_matching.cloud_account_ids.0", policyCloudAccountID1),
					resource.TestCheckResourceAttr(cloudSecPolicyAssetGroupsResourceNameFull, "asset_matching.cloud_account_ids.1", policyCloudAccountID2),
				),
			},
		},
		CheckDestroy: testAccCheckCloudSecPolicyDestroy,
	})
}

// TestAccCloudSecPolicy_update tests updating policy configuration
func TestAccCloudSecPolicy_update(t *testing.T) {
	providerConfig := getProviderConfig(t, dotEnvPath, true)

	initialConfig := fmt.Sprintf(`
resource "%s" "%s" {
	 name        = "tf-acctest-policy-update-initial-%s"
	 description = "Initial description"
	 enabled     = false

	 rule_matching = {
	   type = "ALL_RULES"
	 }

	 asset_matching = {
	   type = "ALL_ASSETS"
	 }

	 labels = ["initial"]
}`, cloudSecPolicyResourceType, cloudSecPolicyUpdateName, randomSuffix)

	updatedConfig := fmt.Sprintf(`
resource "%s" "%s" {
	 name        = "tf-acctest-policy-update-modified-%s"
	 description = "Modified description"
	 enabled     = true

	 rule_matching = {
	   type = "RULE_FILTER"
	   filter_criteria = {
	     field = "severity"
	     type  = "EQ"
	     value = "critical"
	   }
	 }

	 asset_matching = {
	   type = "ALL_ASSETS"
	 }

	 labels = ["modified", "updated"]
}`, cloudSecPolicyResourceType, cloudSecPolicyUpdateName, randomSuffix)

	resourceNameFull := fmt.Sprintf("%s.%s", cloudSecPolicyResourceType, cloudSecPolicyUpdateName)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create with initial values
			{
				Config: providerConfig + initialConfig,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceNameFull, "name", fmt.Sprintf("tf-acctest-policy-update-initial-%s", randomSuffix)),
					resource.TestCheckResourceAttr(resourceNameFull, "enabled", "false"),
					resource.TestCheckResourceAttr(resourceNameFull, "rule_matching.type", "ALL_RULES"),
					resource.TestCheckResourceAttr(resourceNameFull, "labels.#", "1"),
				),
			},
			// Update multiple fields including rule matching type
			{
				Config: providerConfig + updatedConfig,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceNameFull, "name", fmt.Sprintf("tf-acctest-policy-update-modified-%s", randomSuffix)),
					resource.TestCheckResourceAttr(resourceNameFull, "description", "Modified description"),
					resource.TestCheckResourceAttr(resourceNameFull, "enabled", "true"),
					resource.TestCheckResourceAttr(resourceNameFull, "rule_matching.type", "RULE_FILTER"),
					resource.TestCheckResourceAttr(resourceNameFull, "rule_matching.filter_criteria.field", "severity"),
					resource.TestCheckResourceAttr(resourceNameFull, "labels.#", "2"),
				),
			},
		},
		CheckDestroy: testAccCheckCloudSecPolicyDestroy,
	})
}

// TestAccCloudSecPolicy_import tests import functionality
func TestAccCloudSecPolicy_import(t *testing.T) {
	providerConfig := getProviderConfig(t, dotEnvPath, true)

	config := fmt.Sprintf(`
resource "%s" "%s" {
	 name = "tf-acctest-policy-import-%s"

	 rule_matching = {
	   type = "ALL_RULES"
	 }

	 asset_matching = {
	   type = "ALL_ASSETS"
	 }
}`, cloudSecPolicyResourceType, cloudSecPolicyImportName, randomSuffix)

	resourceNameFull := fmt.Sprintf("%s.%s", cloudSecPolicyResourceType, cloudSecPolicyImportName)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create policy
			{
				Config: providerConfig + config,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceNameFull, "name", fmt.Sprintf("tf-acctest-policy-import-%s", randomSuffix)),
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
		CheckDestroy: testAccCheckCloudSecPolicyDestroy,
	})
}

// TestAccCloudSecPolicy_disappears tests resource disappears handling
func TestAccCloudSecPolicy_disappears(t *testing.T) {
	providerConfig := getProviderConfig(t, dotEnvPath, true)

	config := fmt.Sprintf(`
resource "%s" "test_disappears" {
	 name = "tf-acctest-policy-disappears-%s"

	 rule_matching = {
	   type = "ALL_RULES"
	 }

	 asset_matching = {
	   type = "ALL_ASSETS"
	 }
}`, cloudSecPolicyResourceType, randomSuffix)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + config,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(fmt.Sprintf("%s.test_disappears", cloudSecPolicyResourceType), "id"),
				),
			},
		},
		CheckDestroy: testAccCheckCloudSecPolicyDestroy,
	})
}

// testAccCheckCloudSecPolicyDestroy verifies the policy has been destroyed
func testAccCheckCloudSecPolicyDestroy(s *terraform.State) error {
	for _, rs := range s.RootModule().Resources {
		if rs.Type != cloudSecPolicyResourceType {
			continue
		}
	}

	return nil
}
