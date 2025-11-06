package acceptance

import (
	"fmt"
	"os"
	"strconv"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAcc_UserResource(t *testing.T) {
	t.Log("Creating test configurations")

	providerConfig := getProviderConfig(t, dotEnvPath, true)

	email := os.Getenv("TF_ACC_TEST_USER_EMAIL")

	if email == "" {
		t.Skip("skipping: please set TF_ACC_TEST_USER_EMAIL (or TEST_CORTEX_USER_EMAIL)")
	}

	resourceName := "cortexcloud_user.test"
	dataName := "data.cortexcloud_user.current"

	cfgReadOnly := fmt.Sprintf(`
		data "cortexcloud_user" "current" {
		  user_email = %s
		}
	`, strconv.Quote(email))

	cfgForImport := fmt.Sprintf(`
		resource "cortexcloud_user" "test" {
		  user_email = %s
		}
	`, strconv.Quote(email))

	t.Log("Running tests")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + cfgReadOnly,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(dataName, "user_email", email),
					resource.TestCheckResourceAttrSet(dataName, "user_first_name"),
					resource.TestCheckResourceAttrSet(dataName, "user_last_name"),
					resource.TestCheckResourceAttrSet(dataName, "status"),
				),
			},
			{
				Config:                               providerConfig + cfgForImport,
				ResourceName:                         resourceName,
				ImportState:                          true,
				ImportStateId:                        email,
				ImportStateVerifyIdentifierAttribute: "user_email",
				ImportStateVerify:                    false,
			},
		},
	})
}
