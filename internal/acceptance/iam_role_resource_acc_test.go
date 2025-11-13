// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package acceptance

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

const (
	iamRoleResourceName = "cortexcloud_iam_role.test"
)

func buildCreateOnlyConfig(prettyName, description string) string {
	return fmt.Sprintf(`
resource "cortexcloud_iam_role" "test" {
  pretty_name = "%s"
  description = "%s"

  component_permissions = [
    "rules_action",
    "wf_verdict_change"
  ]

  dataset_permissions = [
    {
      category    = "Lookup"
      access_all  = true
      permissions = []
    }
  ]
}
`, prettyName, description)
}

// Test Only Create/Read（remote no update, no test）
func TestAccIamRoleResource_CreateOnly(t *testing.T) {
	suffix := acctest.RandStringFromCharSet(6, acctest.CharSetAlphaNum)
	pretty := fmt.Sprintf("CustomRoleName-%s", suffix)
	desc := "A custom role with specific permissions"

	cfg := buildCreateOnlyConfig(pretty, desc)
	providerConfig := getProviderConfig(t, dotEnvPath, true)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + cfg,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(iamRoleResourceName, "pretty_name", pretty),
					resource.TestCheckResourceAttr(iamRoleResourceName, "description", desc),

					resource.TestCheckResourceAttr(iamRoleResourceName, "component_permissions.#", "2"),
					resource.TestCheckTypeSetElemAttr(iamRoleResourceName, "component_permissions.*", "rules_action"),
					resource.TestCheckTypeSetElemAttr(iamRoleResourceName, "component_permissions.*", "wf_verdict_change"),

					resource.TestCheckResourceAttr(iamRoleResourceName, "dataset_permissions.#", "1"),
					resource.TestCheckResourceAttr(iamRoleResourceName, "dataset_permissions.0.category", "Lookup"),
					resource.TestCheckResourceAttr(iamRoleResourceName, "dataset_permissions.0.access_all", "true"),
					resource.TestCheckResourceAttr(iamRoleResourceName, "dataset_permissions.0.permissions.#", "0"),
				),
			},
		},
	})
}
