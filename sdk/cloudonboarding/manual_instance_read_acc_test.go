// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

//go:build acceptance

package cloudonboarding

import (
	"context"
	"fmt"
	"strconv"
	"testing"
	"time"

	types "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/types/cloudonboarding"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAccGetEditInstanceDetailsReadsBackAManualInstance creates a manual AWS
// connector and reads it back, asserting that the read reflects what was
// written.
//
// The assertion is deliberately made on the returned instance_name, not on the
// call succeeding. The endpoint has been observed returning identical payloads
// for different identifiers, so a 200 alone proves nothing; a unique name is
// self-discriminating and cannot be produced by another connector.
//
// Requires TEST_CORTEX_API_URL, TEST_CORTEX_API_KEY, TEST_CORTEX_API_KEY_ID and
// the AWS fixture variables TEST_AWS_ACCOUNT_ID, TEST_AWS_ROLE_ARN and
// TEST_AWS_EXTERNAL_ID.
func TestAccGetEditInstanceDetailsReadsBackAManualInstance(t *testing.T) {
	client := setupManualAcceptanceTest(t)
	ctx := context.Background()

	accountID := strEnv(t, "TEST_AWS_ACCOUNT_ID")
	roleARN := strEnv(t, "TEST_AWS_ROLE_ARN")
	externalID := strEnv(t, "TEST_AWS_EXTERNAL_ID")

	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	instanceName := fmt.Sprintf("acctest-manual-read-%s", timestamp)

	created, err := client.CreateManualInstance(ctx, types.NewCreateManualInstanceRequest(
		"AWS", "ACCOUNT", "MANAGED",
		types.ManualDetails{
			AccountID:  accountID,
			RoleARN:    roleARN,
			ExternalID: externalID,
		},
		types.WithManualCreateInstanceName(instanceName),
		types.WithManualCreateCollectionConfiguration(types.ManualCollectionConfiguration{
			AuditLogs: types.ManualAuditLogsConfiguration{CollectionMethod: "CUSTOM"},
		}),
		types.WithManualCreateScopeModifications(types.ManualScopeModifications{
			Regions: &types.ScopeModificationRegions{Enabled: false},
		}),
	))
	require.NoError(t, err)
	require.NotEmpty(t, created.ID)

	t.Cleanup(func() {
		if err := client.DeleteIntegrationInstances(context.Background(), []string{created.ID}); err != nil {
			t.Logf("failed to clean up connector %s: %s", created.ID, err.Error())
		}
	})

	details, err := client.GetEditInstanceDetails(ctx,
		types.NewGetEditInstanceDetailsRequest(created.ID))
	require.NoError(t, err)

	f := details.Fields
	// The unique name is the only assertion that identifies the row.
	assert.Equal(t, instanceName, f.InstanceName)
	assert.Equal(t, "AWS", f.CloudProvider)
	assert.Equal(t, "ACCOUNT", f.Scope)
	assert.Equal(t, "MANAGED", f.ScanMode)
	assert.Equal(t, "MANUAL", f.ProvisioningMethod)

	require.NotNil(t, f.ManualDetails, "a manual connector must report manual_details")
	require.NotNil(t, f.ManualDetails.RoleARN)
	assert.Equal(t, *roleARN, *f.ManualDetails.RoleARN)
	require.NotNil(t, f.ManualDetails.ExternalID)
	assert.Equal(t, *externalID, *f.ManualDetails.ExternalID)
}

// TestAccGetEditInstanceDetailsRejectsAnUnknownID asserts that an identifier
// with no connector behind it is refused rather than answered with a
// substitute row.
func TestAccGetEditInstanceDetailsRejectsAnUnknownID(t *testing.T) {
	client := setupManualAcceptanceTest(t)

	_, err := client.GetEditInstanceDetails(context.Background(),
		types.NewGetEditInstanceDetailsRequest("deadbeefdeadbeefdeadbeefdeadbeef"))
	require.Error(t, err, "an identifier with no connector must be rejected")
}

// TestAccDeleteInstanceTemplateIsIdempotent asserts the documented behaviour
// that deleting a template which does not exist reports success.
//
// This encodes an adjudicated decision, not a wish: the API team reviewed this
// behaviour and declined to change it. The test fails if the API starts
// returning an error, which would be a breaking change for callers relying on
// idempotent deletes.
func TestAccDeleteInstanceTemplateIsIdempotent(t *testing.T) {
	client := setupManualAcceptanceTest(t)

	err := client.DeleteInstanceTemplate(context.Background(),
		types.NewDeleteInstanceTemplateRequest("deadbeefdeadbeefdeadbeefdeadbeef"))
	require.NoError(t, err, "deleting an absent template is documented to succeed")
}

// TestAccDeleteInstanceTemplateRemovesATemplate deletes a real template.
//
// TEST_INSTANCE_TEMPLATE_ID must name a template that is safe to destroy; the
// test is skipped when it is unset because there is no way to create a
// throwaway template and no way to confirm one exists beforehand.
func TestAccDeleteInstanceTemplateRemovesATemplate(t *testing.T) {
	client := setupManualAcceptanceTest(t)

	templateID := strEnv(t, "TEST_INSTANCE_TEMPLATE_ID")

	err := client.DeleteInstanceTemplate(context.Background(),
		types.NewDeleteInstanceTemplateRequest(*templateID))
	require.NoError(t, err)
}
