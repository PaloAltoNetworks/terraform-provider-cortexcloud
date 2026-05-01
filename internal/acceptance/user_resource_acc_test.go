package acceptance

import (
	"fmt"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAcc_UserResource(t *testing.T) {
	t.Log("Creating test configurations")

	providerConfig := getProviderConfig(t, dotEnvPath, true)

	email := os.Getenv("CORTEXCLOUD_ACCTEST_USER_EMAIL")
	if email == "" {
		// Fallback for legacy env name used by the original test.
		email = os.Getenv("CORTEXCLOUD_USER_EMAIL")
	}
	if email == "" {
		// Last-resort hard-coded value to preserve the previous behavior.
		// Prefer setting CORTEXCLOUD_ACCTEST_USER_EMAIL in .env.acctest.
		email = "qa-test13@panw.com"
	}

	resourceName := "cortexcloud_user.test"

	cfgForImport := fmt.Sprintf(`
resource "cortexcloud_user" "test" {
  user_email = %q
}
`, email)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// The user resource represents an existing IAM user (identified by email).
				// Import it and validate that Read populates key computed attributes.
				Config:                               providerConfig + cfgForImport,
				ResourceName:                         resourceName,
				ImportState:                          true,
				ImportStateId:                        email,
				ImportStateVerifyIdentifierAttribute: "user_email",
				ImportStateVerify:                    false,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "user_email", email),
					resource.TestCheckResourceAttrSet(resourceName, "user_type"),
					resource.TestCheckResourceAttrSet(resourceName, "status"),
				),
			},
		},
	})
}
