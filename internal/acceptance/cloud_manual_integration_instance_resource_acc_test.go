// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package acceptance

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	cortexEnums "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/enums"
	cloudOnboardingTypes "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/types/cloudonboarding"
	filterTypes "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/types/filter"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

// manualInstanceResourceType is the Terraform resource type under test.
const manualInstanceResourceType = "cortexcloud_cloud_manual_integration_instance"

// The connector this test creates is a real record on a shared tenant. Every
// input that identifies a cloud-side principal is read from the environment and
// never hard-coded, because a connector built from invented credentials is not
// merely a failed test: create_instance answers HTTP 500 for a role it cannot
// assume and still leaves a PENDING record behind that no API call can remove.
// Supplying credentials that are known to work is therefore a cleanliness
// requirement, not a convenience.
const (
	manualInstanceAWSAccountIDEnvVar  = "TEST_MANUAL_INSTANCE_AWS_ACCOUNT_ID"
	manualInstanceAWSAccountNameEnv   = "TEST_MANUAL_INSTANCE_AWS_ACCOUNT_NAME"
	manualInstanceAWSRoleARNEnvVar    = "TEST_MANUAL_INSTANCE_AWS_ROLE_ARN"
	manualInstanceAWSExternalIDEnvVar = "TEST_MANUAL_INSTANCE_AWS_EXTERNAL_ID"

	manualInstanceAzureSubscriptionIDEnvVar = "TEST_MANUAL_INSTANCE_AZURE_SUBSCRIPTION_ID"
	manualInstanceAzureAccountNameEnvVar    = "TEST_MANUAL_INSTANCE_AZURE_ACCOUNT_NAME"
	manualInstanceAzureTenantIDEnvVar       = "TEST_MANUAL_INSTANCE_AZURE_TENANT_ID"
	manualInstanceAzureClientIDEnvVar       = "TEST_MANUAL_INSTANCE_AZURE_CLIENT_ID"
	manualInstanceAzureClientSecretEnvVar   = "TEST_MANUAL_INSTANCE_AZURE_CLIENT_SECRET"
)

// manualInstanceNamePrefix marks every connector this test creates.
//
// Residue on a shared tenant is only identifiable if it is labelled, and the
// cleanup sweep refuses to touch anything whose name does not begin with this.
const manualInstanceNamePrefix = "tfacc-manual-"

// manualInstanceConfigTmpl renders an AWS manual connector.
//
// Only the members the platform reports back are declared. cloudtrail_role,
// sqs_url and subscription_id are accepted on write but never returned, so
// declaring them here would assert a round trip the platform cannot perform.
const manualInstanceConfigTmpl = `
resource "%s" "test" {
  cloud_provider = "AWS"
  scope          = "ACCOUNT"
  scan_mode      = "MANAGED"

  instance_name = %q

  manual_details = {
    account_id   = %q
    account_name = %q
    role_arn     = %q
    external_id  = %q
  }

  additional_capabilities = {
    xsiam_analytics = %t
  }
}
`

// awsManualCredentials carries the cloud-side identities the connector is built
// from.
type awsManualCredentials struct {
	accountID   string
	accountName string
	roleARN     string
	externalID  string
}

// requireAWSManualCredentials reads the credentials or skips.
//
// A skip is the correct outcome rather than a synthesised value: see the
// comment on the environment variable block.
func requireAWSManualCredentials(t *testing.T) awsManualCredentials {
	t.Helper()

	credentials := awsManualCredentials{
		accountID:   os.Getenv(manualInstanceAWSAccountIDEnvVar),
		accountName: os.Getenv(manualInstanceAWSAccountNameEnv),
		roleARN:     os.Getenv(manualInstanceAWSRoleARNEnvVar),
		externalID:  os.Getenv(manualInstanceAWSExternalIDEnvVar),
	}

	missing := []string{}
	for name, value := range map[string]string{
		manualInstanceAWSAccountIDEnvVar:  credentials.accountID,
		manualInstanceAWSAccountNameEnv:   credentials.accountName,
		manualInstanceAWSRoleARNEnvVar:    credentials.roleARN,
		manualInstanceAWSExternalIDEnvVar: credentials.externalID,
	} {
		if value == "" {
			missing = append(missing, name)
		}
	}

	if len(missing) > 0 {
		t.Skipf(
			"Skipping: %s must be set to a cloud-side IAM role the platform can "+
				"actually assume. Creating this connector from invented values "+
				"does not fail cleanly -- the create is answered with HTTP 500 "+
				"and still leaves a PENDING record on the tenant that no API "+
				"call can remove.",
			strings.Join(missing, ", "),
		)
	}

	return credentials
}

// manualInstanceAzureConfigTmpl renders an Azure manual connector.
//
// Azure identifies its account by "subscription_id", which the platform accepts
// on write and never reports back, so unlike the AWS template no member of this
// one can be asserted through "reported_manual_details".
const manualInstanceAzureConfigTmpl = `
resource "%s" "test" {
  cloud_provider = "AZURE"
  scope          = "ACCOUNT"
  scan_mode      = "MANAGED"

  instance_name = %q

  manual_details = {
    subscription_id = %q
    account_name    = %q
    tenant_id       = %q
    client_id       = %q
    client_secret   = %q
  }

  additional_capabilities = {
    xsiam_analytics = %t
  }
}
`

// azureManualCredentials carries the cloud-side identities the connector is
// built from.
type azureManualCredentials struct {
	subscriptionID string
	accountName    string
	tenantID       string
	clientID       string
	clientSecret   string
}

// requireAzureManualCredentials reads the credentials or skips.
//
// As with AWS, a skip is the correct outcome rather than a synthesised value:
// an app registration the platform cannot authenticate against is rejected
// after the onboarding record has already been written, so the cost of a
// guessed credential is a permanent row on a shared tenant.
func requireAzureManualCredentials(t *testing.T) azureManualCredentials {
	t.Helper()

	credentials := azureManualCredentials{
		subscriptionID: os.Getenv(manualInstanceAzureSubscriptionIDEnvVar),
		accountName:    os.Getenv(manualInstanceAzureAccountNameEnvVar),
		tenantID:       os.Getenv(manualInstanceAzureTenantIDEnvVar),
		clientID:       os.Getenv(manualInstanceAzureClientIDEnvVar),
		clientSecret:   os.Getenv(manualInstanceAzureClientSecretEnvVar),
	}

	missing := []string{}
	for name, value := range map[string]string{
		manualInstanceAzureSubscriptionIDEnvVar: credentials.subscriptionID,
		manualInstanceAzureAccountNameEnvVar:    credentials.accountName,
		manualInstanceAzureTenantIDEnvVar:       credentials.tenantID,
		manualInstanceAzureClientIDEnvVar:       credentials.clientID,
		manualInstanceAzureClientSecretEnvVar:   credentials.clientSecret,
	} {
		if value == "" {
			missing = append(missing, name)
		}
	}

	if len(missing) > 0 {
		t.Skipf(
			"Skipping: %s must be set to an Azure app registration the platform "+
				"can actually authenticate as. Creating this connector from "+
				"invented values does not fail cleanly -- the onboarding record "+
				"is written before the credentials are exercised, so a bad guess "+
				"leaves a PENDING record behind on the tenant.",
			strings.Join(missing, ", "),
		)
	}

	return credentials
}

// TestAccCloudManualIntegrationInstance_azureLifecycle exercises the same cycle
// as the AWS case against an Azure connector.
//
// It is a separate test rather than a table case because the two providers do
// not accept the same "manual_details": Azure's members are subscription_id,
// tenant_id, client_id and client_secret, and the platform validates the set it
// is given against the provider. The value in running it is that the provider's
// conditional handling of manual_details is exercised on a second shape; the
// AWS run alone cannot distinguish "handles the manual path" from "handles AWS".
func TestAccCloudManualIntegrationInstance_azureLifecycle(t *testing.T) {
	credentials := requireAzureManualCredentials(t)

	providerConfig := getProviderConfig(t, dotEnvPath, true)
	resourceName := fmt.Sprintf("%s.test", manualInstanceResourceType)

	instanceName := fmt.Sprintf("%sazure-%d", manualInstanceNamePrefix, time.Now().Unix())
	renamedInstanceName := instanceName + "-renamed"

	config := func(name string, analytics bool) string {
		return providerConfig + fmt.Sprintf(
			manualInstanceAzureConfigTmpl,
			manualInstanceResourceType,
			name,
			credentials.subscriptionID,
			credentials.accountName,
			credentials.tenantID,
			credentials.clientID,
			credentials.clientSecret,
			analytics,
		)
	}

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckManualInstanceDestroyed(t),
		Steps: []resource.TestStep{
			{
				Config: config(instanceName, false),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "instance_name", instanceName),
					resource.TestCheckResourceAttr(resourceName, "cloud_provider", "AZURE"),
					resource.TestCheckResourceAttr(resourceName, "manual_details.subscription_id", credentials.subscriptionID),
					testAccCheckManualInstanceListedLive(t, resourceName, true),
				),
			},
			{
				Config:   config(instanceName, false),
				PlanOnly: true,
			},
			{
				Config: config(renamedInstanceName, true),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(resourceName, plancheck.ResourceActionUpdate),
					},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "instance_name", renamedInstanceName),
					resource.TestCheckResourceAttr(resourceName, "additional_capabilities.xsiam_analytics", "true"),
					testAccCheckManualInstanceListedLive(t, resourceName, true),
				),
			},
		},
	})
}

// TestAccCloudManualIntegrationInstance_lifecycle exercises the full create,
// read, update and delete cycle against a live tenant.
//
// The step that carries the most weight is the destroy. delete_instance answers
// HTTP 200 whether it removed a connector or nothing at all, so the provider
// ignores that reply and decides the outcome from a listing filtered to the
// connector's identifier. Until this test ran, that listing had never been
// issued against a live tenant by the provider itself.
//
// The update step asserts an in-place update rather than a replacement. Getting
// that wrong would destroy and recreate a live connector on every capability
// toggle.
func TestAccCloudManualIntegrationInstance_lifecycle(t *testing.T) {
	credentials := requireAWSManualCredentials(t)

	providerConfig := getProviderConfig(t, dotEnvPath, true)
	resourceName := fmt.Sprintf("%s.test", manualInstanceResourceType)

	instanceName := fmt.Sprintf("%saws-%d", manualInstanceNamePrefix, time.Now().Unix())
	renamedInstanceName := instanceName + "-renamed"

	config := func(name string, analytics bool) string {
		return providerConfig + fmt.Sprintf(
			manualInstanceConfigTmpl,
			manualInstanceResourceType,
			name,
			credentials.accountID,
			credentials.accountName,
			credentials.roleARN,
			credentials.externalID,
			analytics,
		)
	}

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckManualInstanceDestroyed(t),
		Steps: []resource.TestStep{
			// Create, and read the connector back.
			{
				Config: config(instanceName, false),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "instance_name", instanceName),
					resource.TestCheckResourceAttr(resourceName, "cloud_provider", "AWS"),
					resource.TestCheckResourceAttr(resourceName, "scope", "ACCOUNT"),
					resource.TestCheckResourceAttr(resourceName, "scan_mode", "MANAGED"),
					resource.TestCheckResourceAttr(resourceName, "manual_details.account_id", credentials.accountID),
					resource.TestCheckResourceAttr(resourceName, "manual_details.role_arn", credentials.roleARN),
					// reported_manual_details is refreshed from the platform, so
					// a value here proves the read reached the tenant rather
					// than echoing the plan back.
					resource.TestCheckResourceAttr(resourceName, "reported_manual_details.account_id", credentials.accountID),
					testAccCheckManualInstanceListedLive(t, resourceName, true),
				),
			},
			// The plan immediately after the create must be empty. A connector
			// whose refresh disagrees with its own configuration would show a
			// diff on every plan for the rest of its life.
			{
				Config:   config(instanceName, false),
				PlanOnly: true,
			},
			// Update in place: rename and toggle a capability. The plan check is
			// the assertion that matters; a replacement here would destroy a
			// live connector.
			{
				Config: config(renamedInstanceName, true),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(resourceName, plancheck.ResourceActionUpdate),
					},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "instance_name", renamedInstanceName),
					resource.TestCheckResourceAttr(resourceName, "additional_capabilities.xsiam_analytics", "true"),
					testAccCheckManualInstanceListedLive(t, resourceName, true),
				),
			},
		},
	})
}

// testAccCheckManualInstanceListedLive asserts out-of-band that the connector
// named by the resource is, or is not, present in the platform's listing.
//
// This is the same question the provider's own delete verification asks, put to
// the platform independently of the provider. Asserting presence during the
// lifecycle is what makes the absence asserted after the destroy meaningful: a
// check that only ever reports "absent" proves nothing, which is precisely how
// the filter defect survived five green mutations.
func testAccCheckManualInstanceListedLive(t *testing.T, resourceName string, wantListed bool) resource.TestCheckFunc {
	return func(state *terraform.State) error {
		res, ok := state.RootModule().Resources[resourceName]
		if !ok {
			return fmt.Errorf("resource %s not found in state", resourceName)
		}
		instanceID := res.Primary.Attributes["id"]
		if instanceID == "" {
			return fmt.Errorf("resource %s has no id in state", resourceName)
		}

		listed, err := manualInstanceListed(t, instanceID)
		if err != nil {
			return err
		}
		if listed != wantListed {
			return fmt.Errorf(
				"connector %s: listed=%t, want listed=%t",
				instanceID, listed, wantListed,
			)
		}
		return nil
	}
}

// testAccCheckManualInstanceDestroyed asserts every connector the test created
// is gone from the platform once the test case tears down.
//
// The framework's destroy runs before this, so a connector still listed here is
// residue on a shared tenant.
func testAccCheckManualInstanceDestroyed(t *testing.T) resource.TestCheckFunc {
	return func(state *terraform.State) error {
		for name, res := range state.RootModule().Resources {
			if res.Type != manualInstanceResourceType {
				continue
			}
			instanceID := res.Primary.Attributes["id"]
			if instanceID == "" {
				continue
			}

			listed, err := manualInstanceListed(t, instanceID)
			if err != nil {
				return err
			}
			if listed {
				return fmt.Errorf(
					"connector %s (%s) is still listed after destroy; it is "+
						"residue on a shared tenant and must be removed by hand",
					instanceID, name,
				)
			}
		}
		return nil
	}
}

// manualInstanceListed asks the platform whether one connector is present.
//
// The predicate is wrapped in an AND because the listing endpoint parses the top
// level of "filter" as a boolean operator and rejects a bare comparison with
// HTTP 500 -- identically for a connector that exists and one that does not.
// An error is returned rather than swallowed, so a crashed endpoint can never be
// read as "absent".
func manualInstanceListed(t *testing.T, instanceID string) (bool, error) {
	t.Helper()

	instances, err := newCloudOnboardingTestClient(t).ListIntegrationInstances(
		context.Background(),
		cloudOnboardingTypes.NewListIntegrationInstancesRequest(
			cloudOnboardingTypes.WithIntegrationFilterData(
				filterTypes.FilterData{
					Filter: filterTypes.NewAndFilter(
						filterTypes.NewSearchFilter(
							cortexEnums.SearchFieldID.String(),
							cortexEnums.SearchTypeEqualTo.String(),
							instanceID,
						),
					),
					Paging: filterTypes.PagingFilter{From: 0, To: 1000},
				},
			),
		),
	)
	if err != nil {
		return false, fmt.Errorf(
			"listing connector %s failed, so its presence is unknown: %w",
			instanceID, err,
		)
	}

	for _, instance := range instances {
		if instance.ID == instanceID {
			return true, nil
		}
	}
	return false, nil
}
