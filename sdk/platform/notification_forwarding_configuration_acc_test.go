// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

//go:build acceptance

package platform

import (
	"context"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/enums"
	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/internal/tests"
	filterTypes "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/types/filter"
	platformTypes "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/types/platform"
)

func TestAccNotificationForwardingConfigurationManagementAuditLogsLifecycle(t *testing.T) {
	config := tests.NewTestConfigFromEnv(t)
	client, err := NewClientFromConfig(config)
	if err != nil {
		t.Fatalf("failed to initialize client: %s", err.Error())
	}

	ctx := context.Background()
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)

	// Create notification forwarding configuration
	testName := fmt.Sprintf("go-sdk-acctest-mgmt-audit-logs-%s", timestamp)
	testDescription := "Acceptance test for Go SDK"
	testFilter := filterTypes.NewRootFilter(
		[]filterTypes.Filter{
			filterTypes.NewSearchFilter("AUDIT_ENTITY", "EQ", "ASSET_GROUPS"),
		},
		[]filterTypes.Filter{},
	)
	testEmailDL := []string{"test1@email.com", "test2@gmail.com", "test3@gmail.com"}
	testEmailCustomSubject := "Go SDK Acceptance Test"
	testForwardSource := platformTypes.ForwardSource{
		Email: &platformTypes.EmailForwardSource{
			DistributionList:  testEmailDL,
			CustomMailSubject: testEmailCustomSubject,
		},
	}

	createReq := platformTypes.CreateOrUpdateNotificationForwardingConfigurationRequest{
		Name:        testName,
		Description: testDescription,
		Filter: struct {
			Filter filterTypes.FilterRoot `json:"filter"`
		}{
			Filter: testFilter,
		},
		ForwardSource: testForwardSource,
		ForwardType:   enums.NotificationForwardingConfigurationTypeManagementAuditLogs.String(),
	}

	createResp, createErr := client.CreateNotificationForwardingConfiguration(ctx, createReq)
	require.NoError(t, createErr, "failed to create notification forwarding configuration")
	require.NotNil(t, createResp, "create response is nil")
	require.NotEmpty(t, createResp.ID)

	configID := createResp.ID

	// Defer cleanup
	defer func() {
		deleteErr := client.DeleteNotificationForwardingConfiguration(ctx, configID)
		if deleteErr != nil {
			t.Logf("WARNING: failed to delete notification forwarding configuration: %s", deleteErr.Error())
		} else {
			t.Logf("Successfully deleted notification forwarding configuration: %s", configID)
		}
	}()

	// Verify created notification forwarding configuration
	assert.Equal(t, createResp.Name, testName)
	assert.Equal(t, createResp.Description, testDescription)
	assert.Equal(t, createResp.Filter, testFilter)
	assert.Equal(t, createResp.Applications, []string{})
	assert.NotNil(t, createResp.ForwardSource)
	assert.Equal(t, *createResp.ForwardSource, testForwardSource)
	assert.Equal(t, createResp.ForwardType, enums.NotificationForwardingConfigurationTypeManagementAuditLogs.String())
	assert.Equal(t, createResp.TimeZone, "UTC") // defaults to UTC if not configured
	assert.True(t, createResp.Enabled)

	// Get notification forwarding configuration
	getResp, getErr := client.GetNotificationForwardingConfiguration(ctx, configID)
	require.NoError(t, getErr, "failed to get notification forwarding configuration")
	require.NotNil(t, getResp, "get response is nil")

	// Verify the retrieved notification forwarding configuration
	assert.Equal(t, getResp.Name, testName)
	assert.Equal(t, getResp.Description, testDescription)
	assert.Equal(t, getResp.Filter, testFilter)
	assert.Equal(t, getResp.Applications, []string{})
	assert.NotNil(t, getResp.ForwardSource)
	assert.Equal(t, *getResp.ForwardSource, testForwardSource)
	assert.Equal(t, getResp.ForwardType, enums.NotificationForwardingConfigurationTypeManagementAuditLogs.String())
	assert.Equal(t, getResp.TimeZone, "UTC") // defaults to UTC if not configured
	assert.True(t, getResp.Enabled)

	// Update notification forwarding configuration
	updatedTestName := fmt.Sprintf("go-sdk-acctest-mgmt-audit-logs-updated-%s", timestamp)
	updatedTestDescription := "Updated acceptance test for Go SDK"
	updatedTestFilter := filterTypes.NewRootFilter(
		[]filterTypes.Filter{
			filterTypes.NewSearchFilter("Severity", "EQ", "SEV_040_HIGH"),
		},
		[]filterTypes.Filter{},
	)
	updatedTestEmailDL := []string{"test4@email.com", "test5@gmail.com", "test6@gmail.com"}
	updatedTestEmailAggregation := 123
	updatedTestEmailCustomSubject := "Updated Go SDK Acceptance Test"
	updatedTestForwardSource := platformTypes.ForwardSource{
		Email: &platformTypes.EmailForwardSource{
			DistributionList:  updatedTestEmailDL,
			Aggregation:       updatedTestEmailAggregation,
			CustomMailSubject: updatedTestEmailCustomSubject,
		},
	}

	updateReq := platformTypes.CreateOrUpdateNotificationForwardingConfigurationRequest{
		Name:        updatedTestName,
		Description: updatedTestDescription,
		Filter: struct {
			Filter filterTypes.FilterRoot `json:"filter"`
		}{
			Filter: updatedTestFilter,
		},
		ForwardSource: updatedTestForwardSource,
		ForwardType:   string(enums.NotificationForwardingConfigurationTypeManagementAuditLogs.String()),
	}

	updateResp, updateErr := client.UpdateNotificationForwardingConfiguration(ctx, configID, updateReq)
	require.NoError(t, updateErr, "failed to update notification forwarding configuration")
	require.NotNil(t, updateResp, "update response is nil")

	// Verify updated notification forwarding configuration
	assert.Equal(t, updateResp.Name, updatedTestName)
	assert.Equal(t, updateResp.Description, updatedTestDescription)
	assert.Equal(t, updateResp.Filter, updatedTestFilter)
	assert.Equal(t, updateResp.Applications, []string{})
	assert.NotNil(t, updateResp.ForwardSource)
	assert.Equal(t, *updateResp.ForwardSource, updatedTestForwardSource)
	assert.Equal(t, updateResp.ForwardType, enums.NotificationForwardingConfigurationTypeManagementAuditLogs.String())
	assert.Equal(t, updateResp.TimeZone, "UTC") // defaults to UTC if not configured
	assert.True(t, updateResp.Enabled)

	// List notification forwarding configurations
	listResp, totalCount, listErr := client.ListNotificationForwardingConfigurations(ctx)
	require.NoError(t, listErr, "failed to list notification forwarding configurations")
	require.NotNil(t, listResp, "list response is nil")
	assert.GreaterOrEqual(t, totalCount, 1, "list endpoint returned a total count of 0")
	require.NotEmpty(t, listResp)

	// Verify the created notification forwarding configuration is in the list response body
	returnedConfig := platformTypes.NotificationForwardingConfiguration{}
	for _, config := range listResp {
		if config.ID == configID {
			returnedConfig = config
		}
	}
	require.NotEqual(t, platformTypes.NotificationForwardingConfiguration{}, returnedConfig)

	// Verify the retrieved notification forwarding configuration
	assert.Equal(t, returnedConfig.Name, updatedTestName)
	assert.Equal(t, returnedConfig.Description, updatedTestDescription)
	assert.Equal(t, returnedConfig.Filter, updatedTestFilter)
	assert.Equal(t, returnedConfig.Applications, []string{})
	assert.NotNil(t, returnedConfig.ForwardSource)
	assert.Equal(t, *returnedConfig.ForwardSource, updatedTestForwardSource)
	assert.Equal(t, returnedConfig.ForwardType, enums.NotificationForwardingConfigurationTypeManagementAuditLogs.String())
	assert.Equal(t, returnedConfig.TimeZone, "UTC") // defaults to UTC if not configured
	assert.True(t, returnedConfig.Enabled)

	// Disable notification forwarding configuration
	disableErr := client.DisableNotificationForwardingConfiguration(ctx, configID)
	require.NoError(t, disableErr, "failed to disable notification forwarding configuration")

	// Re-enable notification forwarding configuration
	enableErr := client.EnableNotificationForwardingConfiguration(ctx, configID)
	require.NoError(t, enableErr, "failed to re-enable notification forwarding configuration")
}

func TestAccNotificationForwardingConfigurationAgentAuditLogsLifecycle(t *testing.T) {
	config := tests.NewTestConfigFromEnv(t)
	client, err := NewClientFromConfig(config)
	if err != nil {
		t.Fatalf("failed to initialize client: %s", err.Error())
	}

	ctx := context.Background()
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)

	// Create notification forwarding configuration
	testName := fmt.Sprintf("go-sdk-acctest-agent-audit-logs-%s", timestamp)
	testDescription := "Acceptance test for Go SDK"
	testFilter := filterTypes.NewRootFilter(
		[]filterTypes.Filter{
			filterTypes.NewSearchFilter("CATEGORY", "EQ", "Audit"),
		},
		[]filterTypes.Filter{},
	)
	testEmailDL := []string{"test1@email.com", "test2@gmail.com", "test3@gmail.com"}
	testEmailAggregation := 789
	testEmailCustomSubject := "Go SDK Acceptance Test"
	testForwardSource := platformTypes.ForwardSource{
		Email: &platformTypes.EmailForwardSource{
			DistributionList:  testEmailDL,
			Aggregation:       testEmailAggregation,
			CustomMailSubject: testEmailCustomSubject,
		},
	}

	createReq := platformTypes.CreateOrUpdateNotificationForwardingConfigurationRequest{
		Name:        testName,
		Description: testDescription,
		Filter: struct {
			Filter filterTypes.FilterRoot `json:"filter"`
		}{
			Filter: testFilter,
		},
		ForwardSource: testForwardSource,
		ForwardType:   enums.NotificationForwardingConfigurationTypeAgentAuditLogs.String(),
	}

	createResp, createErr := client.CreateNotificationForwardingConfiguration(ctx, createReq)
	require.NoError(t, createErr, "failed to create notification forwarding configuration")
	require.NotNil(t, createResp, "create response is nil")
	require.NotEmpty(t, createResp.ID)

	configID := createResp.ID

	// Defer cleanup
	defer func() {
		deleteErr := client.DeleteNotificationForwardingConfiguration(ctx, configID)
		if deleteErr != nil {
			t.Logf("WARNING: failed to delete notification forwarding configuration: %s", deleteErr.Error())
		} else {
			t.Logf("Successfully deleted notification forwarding configuration: %s", configID)
		}
	}()

	// Verify created notification forwarding configuration
	assert.Equal(t, createResp.Name, testName)
	assert.Equal(t, createResp.Description, testDescription)
	assert.Equal(t, createResp.Filter, testFilter)
	assert.Equal(t, createResp.Applications, []string{})
	assert.NotNil(t, createResp.ForwardSource)
	assert.Equal(t, *createResp.ForwardSource, testForwardSource)
	assert.Equal(t, createResp.ForwardType, enums.NotificationForwardingConfigurationTypeAgentAuditLogs.String())
	assert.Equal(t, createResp.TimeZone, "UTC") // defaults to UTC if not configured
	assert.True(t, createResp.Enabled)

	// Update notification forwarding configuration
	updatedTestName := fmt.Sprintf("go-sdk-acctest-notification-fwd-config-updated-%s", timestamp)
	updatedTestDescription := "Updated acceptance test for Go SDK"
	updatedTestFilter := filterTypes.NewRootFilter(
		[]filterTypes.Filter{
			filterTypes.NewSearchFilter("Severity", "EQ", "SEV_040_HIGH"),
		},
		[]filterTypes.Filter{},
	)
	updatedTestEmailDL := []string{"test4@email.com", "test5@gmail.com", "test6@gmail.com"}
	updatedTestEmailAggregation := 123
	updatedTestEmailCustomSubject := "Updated Go SDK Acceptance Test"
	updatedTestForwardSource := platformTypes.ForwardSource{
		Email: &platformTypes.EmailForwardSource{
			DistributionList:  updatedTestEmailDL,
			Aggregation:       updatedTestEmailAggregation,
			CustomMailSubject: updatedTestEmailCustomSubject,
		},
	}

	updateReq := platformTypes.CreateOrUpdateNotificationForwardingConfigurationRequest{
		Name:        updatedTestName,
		Description: updatedTestDescription,
		Filter: struct {
			Filter filterTypes.FilterRoot `json:"filter"`
		}{
			Filter: updatedTestFilter,
		},
		ForwardSource: updatedTestForwardSource,
		ForwardType:   enums.NotificationForwardingConfigurationTypeAgentAuditLogs.String(),
	}

	updateResp, updateErr := client.UpdateNotificationForwardingConfiguration(ctx, configID, updateReq)
	require.NoError(t, updateErr, "failed to update notification forwarding configuration")
	require.NotNil(t, updateResp, "update response is nil")

	// Verify updated notification forwarding configuration
	assert.Equal(t, updateResp.Name, updatedTestName)
	assert.Equal(t, updateResp.Description, updatedTestDescription)
	assert.Equal(t, updateResp.Filter, updatedTestFilter)
	assert.Equal(t, updateResp.Applications, []string{})
	assert.NotNil(t, updateResp.ForwardSource)
	assert.Equal(t, *updateResp.ForwardSource, updatedTestForwardSource)
	assert.Equal(t, updateResp.ForwardType, enums.NotificationForwardingConfigurationTypeAgentAuditLogs.String())
	assert.Equal(t, updateResp.TimeZone, "UTC") // defaults to UTC if not configured
	assert.True(t, updateResp.Enabled)

	// Disable notification forwarding configuration
	disableErr := client.DisableNotificationForwardingConfiguration(ctx, configID)
	require.NoError(t, disableErr, "failed to disable notification forwarding configuration")

	// Re-enable notification forwarding configuration
	enableErr := client.EnableNotificationForwardingConfiguration(ctx, configID)
	require.NoError(t, enableErr, "failed to re-enable notification forwarding configuration")
}

func TestAccNotificationForwardingConfigurationIssuesLifecycle(t *testing.T) {
	config := tests.NewTestConfigFromEnv(t)
	client, err := NewClientFromConfig(config)
	if err != nil {
		t.Fatalf("failed to initialize client: %s", err.Error())
	}

	ctx := context.Background()
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	configType := enums.NotificationForwardingConfigurationTypeIssues.String()

	// Create notification forwarding configuration
	testName := fmt.Sprintf("go-sdk-acctest-issues-%s", timestamp)
	testDescription := "Acceptance test for Go SDK"
	testFilter := filterTypes.NewRootFilter(
		[]filterTypes.Filter{
			filterTypes.NewSearchFilter("IS_WHITELISTED", "EQ", "Audit"),
		},
		[]filterTypes.Filter{},
	)
	testEmailDL := []string{"test1@email.com", "test2@gmail.com", "test3@gmail.com"}
	testEmailAggregation := 789
	testEmailCustomSubject := "Go SDK Acceptance Test"
	testForwardSource := platformTypes.ForwardSource{
		Email: &platformTypes.EmailForwardSource{
			DistributionList:  testEmailDL,
			Aggregation:       testEmailAggregation,
			CustomMailSubject: testEmailCustomSubject,
		},
	}
	testEmailFormat := enums.NotificationFormatIssue.String()

	createReq := platformTypes.CreateOrUpdateNotificationForwardingConfigurationRequest{
		Name:        testName,
		Description: testDescription,
		Filter: struct {
			Filter filterTypes.FilterRoot `json:"filter"`
		}{
			Filter: testFilter,
		},
		ForwardSource: testForwardSource,
		ForwardType:   configType,
		MailFormat:    testEmailFormat,
	}

	createResp, createErr := client.CreateNotificationForwardingConfiguration(ctx, createReq)
	require.NoError(t, createErr, "failed to create notification forwarding configuration")
	require.NotNil(t, createResp, "create response is nil")
	require.NotEmpty(t, createResp.ID)

	configID := createResp.ID

	// Defer cleanup
	defer func() {
		deleteErr := client.DeleteNotificationForwardingConfiguration(ctx, configID)
		if deleteErr != nil {
			t.Logf("WARNING: failed to delete notification forwarding configuration: %s", deleteErr.Error())
		} else {
			t.Logf("Successfully deleted notification forwarding configuration: %s", configID)
		}
	}()

	// Verify created notification forwarding configuration
	assert.Equal(t, createResp.Name, testName)
	assert.Equal(t, createResp.Description, testDescription)
	assert.Equal(t, createResp.Filter, testFilter)
	assert.Equal(t, createResp.Applications, []string{})
	assert.NotNil(t, createResp.ForwardSource)
	assert.Equal(t, *createResp.ForwardSource, testForwardSource)
	assert.Equal(t, createResp.ForwardType, configType)
	assert.Equal(t, testEmailFormat, createResp.MailFormat)
	assert.Equal(t, createResp.TimeZone, "UTC") // defaults to UTC if not configured
	assert.True(t, createResp.Enabled)

	// Update notification forwarding configuration
	updatedTestName := fmt.Sprintf("go-sdk-acctest-issues-updated-%s", timestamp)
	updatedTestDescription := "Updated acceptance test for Go SDK"
	updatedTestFilter := filterTypes.NewRootFilter(
		[]filterTypes.Filter{
			filterTypes.NewOrFilter(
				filterTypes.NewSearchFilter("Severity", "EQ", "SEV_040_HIGH"),
				filterTypes.NewSearchFilter("Severity", "EQ", "SEV_050_CRITICAL"),
			),
		},
		[]filterTypes.Filter{},
	)
	updatedTestEmailDL := []string{"test4@email.com", "test5@gmail.com", "test6@gmail.com"}
	updatedTestEmailAggregation := 123
	updatedTestEmailCustomSubject := "Updated Go SDK Acceptance Test"
	updatedTestForwardSource := platformTypes.ForwardSource{
		Email: &platformTypes.EmailForwardSource{
			DistributionList:  updatedTestEmailDL,
			Aggregation:       updatedTestEmailAggregation,
			CustomMailSubject: updatedTestEmailCustomSubject,
		},
	}
	updatedTestEmailFormat := enums.NotificationFormatStandardAlert.String()

	updateReq := platformTypes.CreateOrUpdateNotificationForwardingConfigurationRequest{
		Name:        updatedTestName,
		Description: updatedTestDescription,
		Filter: struct {
			Filter filterTypes.FilterRoot `json:"filter"`
		}{
			Filter: updatedTestFilter,
		},
		ForwardSource: updatedTestForwardSource,
		ForwardType:   configType,
		MailFormat:    updatedTestEmailFormat,
	}

	updateResp, updateErr := client.UpdateNotificationForwardingConfiguration(ctx, configID, updateReq)
	require.NoError(t, updateErr, "failed to update notification forwarding configuration")
	require.NotNil(t, updateResp, "update response is nil")

	// Verify updated notification forwarding configuration
	assert.Equal(t, updateResp.Name, updatedTestName)
	assert.Equal(t, updateResp.Description, updatedTestDescription)
	assert.Equal(t, updateResp.Filter, updatedTestFilter)
	assert.Equal(t, updateResp.Applications, []string{})
	assert.NotNil(t, updateResp.ForwardSource)
	assert.Equal(t, *updateResp.ForwardSource, updatedTestForwardSource)
	assert.Equal(t, updateResp.ForwardType, configType)
	assert.Equal(t, updateResp.MailFormat, updatedTestEmailFormat)
	assert.Equal(t, updateResp.TimeZone, "UTC") // defaults to UTC if not configured
	assert.True(t, updateResp.Enabled)

	// Disable notification forwarding configuration
	disableErr := client.DisableNotificationForwardingConfiguration(ctx, configID)
	require.NoError(t, disableErr, "failed to disable notification forwarding configuration")

	// Re-enable notification forwarding configuration
	enableErr := client.EnableNotificationForwardingConfiguration(ctx, configID)
	require.NoError(t, enableErr, "failed to re-enable notification forwarding configuration")
}

func TestAccNotificationForwardingConfigurationCasesLifecycle(t *testing.T) {
	config := tests.NewTestConfigFromEnv(t)
	client, err := NewClientFromConfig(config)
	if err != nil {
		t.Fatalf("failed to initialize client: %s", err.Error())
	}

	ctx := context.Background()
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	configType := enums.NotificationForwardingConfigurationTypeCases.String()

	// Create notification forwarding configuration
	testName := fmt.Sprintf("go-sdk-acctest-cases-%s", timestamp)
	testDescription := "Acceptance test for Go SDK"
	testFilter := filterTypes.NewRootFilter(
		[]filterTypes.Filter{
			filterTypes.NewSearchFilter("STATUS_PROGRESS", "NEQ", "STATUS_025_RESOLVED"),
		},
		[]filterTypes.Filter{},
	)
	testEmailDL := []string{"test1@email.com", "test2@gmail.com", "test3@gmail.com"}
	testEmailAggregation := 789
	testEmailCustomSubject := "Go SDK Acceptance Test"
	testForwardSource := platformTypes.ForwardSource{
		Email: &platformTypes.EmailForwardSource{
			DistributionList:  testEmailDL,
			Aggregation:       testEmailAggregation,
			CustomMailSubject: testEmailCustomSubject,
		},
	}

	createReq := platformTypes.CreateOrUpdateNotificationForwardingConfigurationRequest{
		Name:        testName,
		Description: testDescription,
		Filter: struct {
			Filter filterTypes.FilterRoot `json:"filter"`
		}{
			Filter: testFilter,
		},
		ForwardSource: testForwardSource,
		ForwardType:   configType,
	}

	createResp, createErr := client.CreateNotificationForwardingConfiguration(ctx, createReq)
	require.NoError(t, createErr, "failed to create notification forwarding configuration")
	require.NotNil(t, createResp, "create response is nil")
	require.NotEmpty(t, createResp.ID)

	configID := createResp.ID

	// Defer cleanup
	defer func() {
		deleteErr := client.DeleteNotificationForwardingConfiguration(ctx, configID)
		if deleteErr != nil {
			t.Logf("WARNING: failed to delete notification forwarding configuration: %s", deleteErr.Error())
		} else {
			t.Logf("Successfully deleted notification forwarding configuration: %s", configID)
		}
	}()

	// Verify created notification forwarding configuration
	assert.Equal(t, createResp.Name, testName)
	assert.Equal(t, createResp.Description, testDescription)
	assert.Equal(t, createResp.Filter, testFilter)
	assert.Equal(t, createResp.Applications, []string{})
	assert.NotNil(t, createResp.ForwardSource)
	assert.Equal(t, *createResp.ForwardSource, testForwardSource)
	assert.Equal(t, createResp.ForwardType, configType)
	assert.Equal(t, createResp.TimeZone, "UTC") // defaults to UTC if not configured
	assert.True(t, createResp.Enabled)

	// Update notification forwarding configuration
	updatedTestName := fmt.Sprintf("go-sdk-acctest-cases-updated-%s", timestamp)
	updatedTestDescription := "Updated acceptance test for Go SDK"
	updatedTestFilter := filterTypes.NewRootFilter(
		[]filterTypes.Filter{
			filterTypes.NewOrFilter(
				filterTypes.NewSearchFilter("STATUS_PROGRESS", "EQ", "STATUS_025_RESOLVED"),
			),
		},
		[]filterTypes.Filter{},
	)
	updatedTestEmailDL := []string{"test4@email.com", "test5@gmail.com", "test6@gmail.com"}
	updatedTestEmailAggregation := 123
	updatedTestEmailCustomSubject := "Updated Go SDK Acceptance Test"
	updatedTestForwardSource := platformTypes.ForwardSource{
		Email: &platformTypes.EmailForwardSource{
			DistributionList:  updatedTestEmailDL,
			Aggregation:       updatedTestEmailAggregation,
			CustomMailSubject: updatedTestEmailCustomSubject,
		},
	}

	updateReq := platformTypes.CreateOrUpdateNotificationForwardingConfigurationRequest{
		Name:        updatedTestName,
		Description: updatedTestDescription,
		Filter: struct {
			Filter filterTypes.FilterRoot `json:"filter"`
		}{
			Filter: updatedTestFilter,
		},
		ForwardSource: updatedTestForwardSource,
		ForwardType:   configType,
	}

	updateResp, updateErr := client.UpdateNotificationForwardingConfiguration(ctx, configID, updateReq)
	require.NoError(t, updateErr, "failed to update notification forwarding configuration")
	require.NotNil(t, updateResp, "update response is nil")

	// Verify updated notification forwarding configuration
	assert.Equal(t, updateResp.Name, updatedTestName)
	assert.Equal(t, updateResp.Description, updatedTestDescription)
	assert.Equal(t, updateResp.Filter, updatedTestFilter)
	assert.Equal(t, updateResp.Applications, []string{})
	assert.NotNil(t, updateResp.ForwardSource)
	assert.Equal(t, *updateResp.ForwardSource, updatedTestForwardSource)
	assert.Equal(t, updateResp.ForwardType, configType)
	assert.Equal(t, updateResp.TimeZone, "UTC") // defaults to UTC if not configured
	assert.True(t, updateResp.Enabled)

	// Disable notification forwarding configuration
	disableErr := client.DisableNotificationForwardingConfiguration(ctx, configID)
	require.NoError(t, disableErr, "failed to disable notification forwarding configuration")

	// Re-enable notification forwarding configuration
	enableErr := client.EnableNotificationForwardingConfiguration(ctx, configID)
	require.NoError(t, enableErr, "failed to re-enable notification forwarding configuration")
}
