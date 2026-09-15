// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

//go:build acceptance

package cloudonboarding

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"testing"
	"time"

	types "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/types/cloudonboarding"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupManualAcceptanceTest(t *testing.T) *Client {
	t.Helper()

	apiKeyID, err := strconv.Atoi(os.Getenv("TEST_CORTEX_API_KEY_ID"))
	require.NoError(t, err, "TEST_CORTEX_API_KEY_ID must be a valid integer")

	client, err := NewClient(
		WithCortexAPIURL(os.Getenv("TEST_CORTEX_API_URL")),
		WithCortexAPIKey(os.Getenv("TEST_CORTEX_API_KEY")),
		WithCortexAPIKeyID(apiKeyID),
		WithCortexAPIKeyType("standard"),
		WithLogLevel("debug"),
	)
	require.NoError(t, err)
	require.NotNil(t, client)

	return client
}

func strEnv(t *testing.T, key string) *string {
	t.Helper()
	v := os.Getenv(key)
	if v == "" {
		t.Skipf("%s must be set to run this acceptance test", key)
	}
	return &v
}

// TestAccManualInstanceAwsAccountLifecycle creates a manually onboarded AWS
// connector and edits it, exercising both manual onboarding endpoints against a
// live tenant.
//
// Requires TEST_CORTEX_API_URL, TEST_CORTEX_API_KEY, TEST_CORTEX_API_KEY_ID and
// the AWS fixture variables TEST_AWS_ACCOUNT_ID, TEST_AWS_ROLE_ARN and
// TEST_AWS_EXTERNAL_ID.
func TestAccManualInstanceAwsAccountLifecycle(t *testing.T) {
	client := setupManualAcceptanceTest(t)
	ctx := context.Background()

	accountID := strEnv(t, "TEST_AWS_ACCOUNT_ID")
	roleARN := strEnv(t, "TEST_AWS_ROLE_ARN")
	externalID := strEnv(t, "TEST_AWS_EXTERNAL_ID")

	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	instanceName := fmt.Sprintf("acctest-manual-aws-%s", timestamp)

	manualDetails := types.ManualDetails{
		AccountID:  accountID,
		RoleARN:    roleARN,
		ExternalID: externalID,
	}
	capabilities := types.ManualAdditionalCapabilities{}
	collection := types.ManualCollectionConfiguration{
		AuditLogs: types.ManualAuditLogsConfiguration{CollectionMethod: "CUSTOM"},
	}
	scopeMods := types.ManualScopeModifications{
		Regions: &types.ScopeModificationRegions{Enabled: false},
	}

	created, err := client.CreateManualInstance(ctx, types.NewCreateManualInstanceRequest(
		"AWS", "ACCOUNT", "MANAGED", manualDetails,
		types.WithManualCreateInstanceName(instanceName),
		types.WithManualCreateAdditionalCapabilities(capabilities),
		types.WithManualCreateCollectionConfiguration(collection),
		types.WithManualCreateScopeModifications(scopeMods),
	))
	require.NoError(t, err)
	require.NotEmpty(t, created.ID, "create must return the new connector id")

	t.Cleanup(func() {
		if err := client.DeleteIntegrationInstances(context.Background(), []string{created.ID}); err != nil {
			t.Logf("failed to clean up connector %s: %s", created.ID, err.Error())
		}
	})

	// The edit is partial, so the full desired state is resent. cloud_provider,
	// scope and scan_mode must repeat their creation values unchanged.
	renamed := instanceName + "-edited"
	err = client.EditManualInstance(ctx, types.NewEditManualInstanceRequest(
		created.ID, "AWS", "ACCOUNT", "MANAGED", manualDetails,
		types.WithManualEditInstanceName(renamed),
		types.WithManualEditAdditionalCapabilities(capabilities),
		types.WithManualEditCollectionConfiguration(collection),
		types.WithManualEditScopeModifications(scopeMods),
	))
	require.NoError(t, err)

	instance, err := client.GetIntegrationInstanceDetails(ctx, created.ID)
	require.NoError(t, err)
	assert.Equal(t, renamed, instance.InstanceName)
	assert.Equal(t, "AWS", instance.CloudProvider)
}

// TestAccManualInstanceRejectsCloudProviderChange asserts that the immutability
// of cloud_provider is enforced by the API, not merely assumed by the SDK.
func TestAccManualInstanceRejectsCloudProviderChange(t *testing.T) {
	client := setupManualAcceptanceTest(t)
	ctx := context.Background()

	instanceID := strEnv(t, "TEST_MANUAL_AWS_INSTANCE_ID")

	err := client.EditManualInstance(ctx, types.NewEditManualInstanceRequest(
		*instanceID, "AZURE", "ACCOUNT", "MANAGED", types.ManualDetails{},
	))
	require.Error(t, err, "changing cloud_provider on a manual connector must be rejected")
}
