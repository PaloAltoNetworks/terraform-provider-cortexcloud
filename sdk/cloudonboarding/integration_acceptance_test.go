// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

//go:build acceptance

package cloudonboarding

//import (
//	"context"
//	"fmt"
//	"strconv"
//	"testing"
//	"time"
//
//	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/enums"
//	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/internal/client"
//	acctest "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/internal/test/acceptance"
//	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/types/cloudonboarding"
//	"github.com/stretchr/testify/assert"
//)
//
//func setupAcceptanceTest(t *testing.T) *Client {
//	client, err := NewClientFromFile(acctest.ConfigFile, false)
//	if err != nil {
//		t.Fatalf("failed to read config file: %s", err.Error())
//	}
//
//	assert.NoError(t, err)
//	assert.NotNil(t, client)
//	return client
//}
//
//func TestAccAwsOrganizationIntegrationTemplateLifecycle(t *testing.T) {
//	client := setupAcceptanceTest(t)
//	ctx := context.Background()
//	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
//
//	// Test values
//	instanceName := fmt.Sprintf("tf-acctest-aws-account-%s", timestamp)
//	cloudProvider := enums.CloudProviderAWS.String()
//	scope := enums.ScopeAccount.String()
//	scanMode := enums.ScanModeManaged.String()
//
//	additionalCapabilities := types.AdditionalCapabilities{
//		DataSecurityPostureManagement: true,
//		RegistryScanning:              true,
//		RegistryScanningOptions: types.RegistryScanningOptions{
//			Type: enums.RegistryScanningTypeAll.String(),
//		},
//		XsiamAnalytics: true,
//	}
//	collectionConfiguration := types.CollectionConfiguration{
//		AuditLogs: types.AuditLogsConfiguration{
//			Enabled: true,
//		},
//	}
//	customResourcesTags := []types.Tag{
//		{
//			Key:   "managed_by",
//			Value: "paloaltonetworks",
//		},
//		{
//			Key:   "test_tag",
//			Value: timestamp,
//		},
//	}
//	scopeModifications := types.ScopeModifications{
//		Regions: &types.ScopeModificationsOptionsRegions{
//			Enabled: true,
//			Type:    enums.ScopeModificationTypeInclude.String(),
//			Regions: []string{"us-east-1"},
//		},
//	}
//
//	// Execute create request
//	createReq := types.CreateIntegrationTemplateRequest{
//		InstanceName:            instanceName,
//		CloudProvider:           cloudProvider,
//		Scope:                   scope,
//		ScanMode:                scanMode,
//		AdditionalCapabilities:  additionalCapabilities,
//		CollectionConfiguration: collectionConfiguration,
//		CustomResourcesTags:     customResourcesTags,
//		ScopeModifications:      scopeModifications,
//	}
//	createResp, err := client.CreateIntegrationTemplate(ctx, createReq)
//	if err != nil {
//		t.Fatalf("failed to create integration template: %s", err.Error())
//	}
//
//	// Check response
//	assert.NotNil(t, createResp)
//	assert.NotNil(t, createResp.Automated)
//	assert.Regexp(t, acctest.AWSIntegrationTemplateAutomatedLinkRegexp, createResp.Automated.Link)
//	assert.Regexp(t, TrackingGUIDRegexp, createResp.Automated.TrackingGuid)
//
//	// Execute get request
//	instanceID := createResp.Automated.TrackingGuid
//	getReq := types.ListIntegrationInstancesRequest{
//		FilterData: filterTypes.FilterData{
//			Paging: filterTypes.PagingFilter{
//				From: 0,
//				To:   1000,
//			},
//			Filter: filterTypes.NewAndFilter(
//				filterTypes.NewSearchFilter(
//					"ID",
//					"WILDCARD",
//					instanceID,
//				),
//			),
//		},
//	}
//	getResp, err := client.ListIntegrationInstances(ctx, getReq)
//	if err != nil {
//		t.Fatalf("failed to retrieve integration template: %s", err.Error())
//	}
//	assert.NotNil(t, getResp)
//	assert.Len(t, getResp, 1)
//	getRespData := getResp[0]
//
//	// Check response
//	assert.NotNil(t, getRespData)
//	assert.Equal(t, instanceID, getRespData.ID)
//	assert.Equal(t, cloudProvider, getRespData.CloudProvider)
//	assert.Equal(t, instanceName, getRespData.InstanceName)
//	assert.Equal(t, scope, getRespData.Scope)
//	assert.Equal(t, scanMode, getRespData.Scan.ScanMethod)
//	assert.Equal(t, "PENDING", getRespData.Status)
//
//	assert.NotNil(t, getRespData.CustomResourcesTags)
//	assert.Equal(t, getRespData.AdditionalCapabilities, additionalCapabilities)
//	assert.Equal(t, getRespData.CustomResourcesTags, customResourcesTags)
//}
