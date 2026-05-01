// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package acceptance

import (
	"fmt"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

const userGroupResourceName = "cortexcloud_user_group.test"

// userGroupAcctestEnv holds environment-variable-driven values that must be
// provided by the test environment for acceptance tests that exercise fields
// requiring real tenant data (users, roles, IDP groups).
type userGroupAcctestEnv struct {
	RoleID       string
	UserEmail    string
	UserEmailAlt string
	IDPGroup     string
}

// loadUserGroupAcctestEnv reads the environment variables needed for the full
// user group acceptance test. Missing optional variables are left empty; the
// test skips fields that have no value.
func loadUserGroupAcctestEnv(t *testing.T) userGroupAcctestEnv {
	t.Helper()
	return userGroupAcctestEnv{
		RoleID:       os.Getenv("CORTEXCLOUD_ACCTEST_USER_GROUP_ROLE_ID"),
		UserEmail:    os.Getenv("CORTEXCLOUD_ACCTEST_USER_GROUP_USER_EMAIL"),
		UserEmailAlt: os.Getenv("CORTEXCLOUD_ACCTEST_USER_GROUP_USER_EMAIL_ALT"),
		IDPGroup:     os.Getenv("CORTEXCLOUD_ACCTEST_USER_GROUP_IDP_GROUP"),
	}
}

// TestAcc_UserGroupResource exercises the full create → update → import →
// destroy lifecycle of cortexcloud_user_group with all configurable fields.
//
// Required env vars (in addition to the standard provider credentials):
//
//	CORTEXCLOUD_ACCTEST_USER_GROUP_ROLE_ID        — existing IAM role ID
//	CORTEXCLOUD_ACCTEST_USER_GROUP_USER_EMAIL     — existing CSP user email
//	CORTEXCLOUD_ACCTEST_USER_GROUP_USER_EMAIL_ALT — second existing CSP user email
//	CORTEXCLOUD_ACCTEST_USER_GROUP_IDP_GROUP      — existing IDP group name
func TestAcc_UserGroupResource(t *testing.T) {
	providerConfig := getProviderConfig(t, dotEnvPath, true)
	env := loadUserGroupAcctestEnv(t)

	if env.RoleID == "" {
		t.Skip("CORTEXCLOUD_ACCTEST_USER_GROUP_ROLE_ID not set — skipping full user group acceptance test")
	}
	if env.UserEmail == "" {
		t.Skip("CORTEXCLOUD_ACCTEST_USER_GROUP_USER_EMAIL not set — skipping full user group acceptance test")
	}

	suffix := acctest.RandStringFromCharSet(6, acctest.CharSetAlphaNum)
	nameCreate := fmt.Sprintf("tf-acc-group-%s", suffix)
	nameUpdate := fmt.Sprintf("tf-acc-group-%s-upd", suffix)

	// Build the users block — always include the primary user; add the alt user
	// in the update step if provided.
	usersCreate := fmt.Sprintf(`[%q]`, env.UserEmail)
	usersUpdate := usersCreate
	if env.UserEmailAlt != "" {
		usersUpdate = fmt.Sprintf(`[%q, %q]`, env.UserEmail, env.UserEmailAlt)
	}

	// Build the idp_groups block — only include if the env var is set.
	idpGroupsBlock := ""
	if env.IDPGroup != "" {
		idpGroupsBlock = fmt.Sprintf(`idp_groups = [%q]`, env.IDPGroup)
	}

	cfgCreate := fmt.Sprintf(`
resource "cortexcloud_user_group" "test" {
  group_name  = %q
  description = "Acceptance test user group (create)."
  role_id     = %q
  users       = %s
  %s
}`, nameCreate, env.RoleID, usersCreate, idpGroupsBlock)

	cfgUpdate := fmt.Sprintf(`
resource "cortexcloud_user_group" "test" {
  group_name  = %q
  description = "Acceptance test user group (update)."
  role_id     = %q
  users       = %s
  %s
}`, nameUpdate, env.RoleID, usersUpdate, idpGroupsBlock)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: Create & Read — verify all configured and computed fields.
			{
				Config: providerConfig + cfgCreate,
				Check: resource.ComposeAggregateTestCheckFunc(
					// Configured fields.
					resource.TestCheckResourceAttr(userGroupResourceName, "group_name", nameCreate),
					resource.TestCheckResourceAttr(userGroupResourceName, "description", "Acceptance test user group (create)."),
					resource.TestCheckResourceAttr(userGroupResourceName, "role_id", env.RoleID),
					resource.TestCheckResourceAttr(userGroupResourceName, "users.#", "1"),
					resource.TestCheckTypeSetElemAttr(userGroupResourceName, "users.*", env.UserEmail),
					// Computed fields set by the API.
					resource.TestCheckResourceAttrSet(userGroupResourceName, "id"),
					resource.TestCheckResourceAttrSet(userGroupResourceName, "pretty_role_name"),
					resource.TestCheckResourceAttrSet(userGroupResourceName, "created_by"),
					resource.TestCheckResourceAttrSet(userGroupResourceName, "created_ts"),
					resource.TestCheckResourceAttrSet(userGroupResourceName, "updated_ts"),
					resource.TestCheckResourceAttrSet(userGroupResourceName, "group_type"),
					// idp_users is computed — may be 0 or more depending on tenant SSO config.
					resource.TestCheckResourceAttrSet(userGroupResourceName, "idp_users.#"),
				),
			},
			// Step 2: Update & Read — rename, change description, add second user.
			{
				Config: providerConfig + cfgUpdate,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(userGroupResourceName, "group_name", nameUpdate),
					resource.TestCheckResourceAttr(userGroupResourceName, "description", "Acceptance test user group (update)."),
					resource.TestCheckResourceAttr(userGroupResourceName, "role_id", env.RoleID),
					// Primary user must still be present.
					resource.TestCheckTypeSetElemAttr(userGroupResourceName, "users.*", env.UserEmail),
					// If alt user was configured, verify it too.
					func() resource.TestCheckFunc {
						if env.UserEmailAlt != "" {
							return resource.ComposeAggregateTestCheckFunc(
								resource.TestCheckResourceAttr(userGroupResourceName, "users.#", "2"),
								resource.TestCheckTypeSetElemAttr(userGroupResourceName, "users.*", env.UserEmailAlt),
							)
						}
						return resource.TestCheckResourceAttr(userGroupResourceName, "users.#", "1")
					}(),
					// Timestamps should be set.
					resource.TestCheckResourceAttrSet(userGroupResourceName, "updated_ts"),
				),
			},
			// Step 3: Import — verify the resource can be imported by ID.
			{
				Config:            providerConfig + cfgUpdate,
				ResourceName:      userGroupResourceName,
				ImportState:       true,
				ImportStateVerify: true,
				// idp_users is computed from ListUsers and may differ between
				// the apply and the import read if SSO state changes; exclude it.
				ImportStateVerifyIgnore: []string{"idp_users"},
			},
			// Step 4: Destroy.
			{
				Config:  providerConfig,
				Destroy: true,
			},
		},
	})
}

// TestAcc_UserGroupResource_MinimalConfig verifies that a user group can be
// created with only the required field (group_name) and that all optional
// computed fields are populated with sensible defaults.
func TestAcc_UserGroupResource_MinimalConfig(t *testing.T) {
	providerConfig := getProviderConfig(t, dotEnvPath, true)

	suffix := acctest.RandStringFromCharSet(6, acctest.CharSetAlphaNum)
	name := fmt.Sprintf("tf-acc-group-min-%s", suffix)

	cfg := fmt.Sprintf(`
resource "cortexcloud_user_group" "test" {
  group_name = %q
}`, name)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + cfg,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(userGroupResourceName, "group_name", name),
					// description defaults to empty string.
					resource.TestCheckResourceAttr(userGroupResourceName, "description", ""),
					// users and idp_groups default to empty sets.
					resource.TestCheckResourceAttr(userGroupResourceName, "users.#", "0"),
					resource.TestCheckResourceAttr(userGroupResourceName, "idp_groups.#", "0"),
					resource.TestCheckResourceAttr(userGroupResourceName, "idp_users.#", "0"),
					// Computed fields are populated by the API.
					resource.TestCheckResourceAttrSet(userGroupResourceName, "id"),
					resource.TestCheckResourceAttrSet(userGroupResourceName, "created_ts"),
					resource.TestCheckResourceAttrSet(userGroupResourceName, "group_type"),
				),
			},
			{
				Config:  providerConfig,
				Destroy: true,
			},
		},
	})
}
