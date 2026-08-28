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
//	"github.com/stretchr/testify/assert"
//)
//
//const (
//	AWSIntegrationTemplateAutomatedLinkRegexp = `^https:\/\/([a-z0-9-]+\.)?console\.aws\.amazon\.com\/cloudformation\/home#\/stacks\/quickcreate\?templateURL=https%3A%2F%2F.+$`
//	AWSIntegrationTemplateManualLinkRegexp    = `^\/.*\.ya?ml(\?.*)?$`
//)
//
//const (
//	GUIDRegexp         = `^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$`
//	TrackingGUIDRegexp = `^[0-9a-fA-F]{32}$`
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
//	//scope := enums.ScopeOrganization.String()
//	scope := enums.ScopeAccount.String()
//	scanMode := enums.ScanModeManaged.String()
//
//	additionalCapabilities := AdditionalCapabilities{
//		DataSecurityPostureManagement: true,
//		RegistryScanning:              true,
//		RegistryScanningOptions: RegistryScanningOptions{
//			Type: enums.RegistryScanningTypeAll.String(),
//		},
//		XsiamAnalytics: true,
//	}
//	collectionConfiguration := CollectionConfiguration{
//		AuditLogs: AuditLogsConfiguration{
//			Enabled: true,
//		},
//	}
//	customResourcesTags := []Tag{
//		{
//			Key:   "managed_by",
//			Value: "paloaltonetworks",
//		},
//		{
//			Key:   "test_tag",
//			Value: timestamp,
//		},
//	}
//	scopeModifications := ScopeModifications{
//		//Accounts: &ScopeModificationsOptionsGeneric{
//		//	Enabled: false,
//		//	//Enabled: true,
//		//	//Type: "INCLUDE",
//		//	//AccountIDs: []string{"123456789012"},
//		//},
//		Regions: &ScopeModificationsOptionsRegions{
//			//Enabled: false,
//			Enabled: true,
//			Type:    enums.ScopeModificationTypeInclude.String(),
//			Regions: []string{"us-east-1"},
//		},
//	}
//
//	// Execute create request
//	createReq := CreateIntegrationTemplateRequest{
//		Data: CreateIntegrationTemplateRequestData{
//			InstanceName:            instanceName,
//			CloudProvider:           cloudProvider,
//			Scope:                   scope,
//			ScanMode:                scanMode,
//			AdditionalCapabilities:  additionalCapabilities,
//			CollectionConfiguration: collectionConfiguration,
//			CustomResourcesTags:     customResourcesTags,
//			ScopeModifications:      scopeModifications,
//		},
//	}
//	createResp, err := client.CreateIntegrationTemplate(ctx, createReq)
//	if err != nil {
//		t.Fatalf("failed to create integration template: %s", err.Error())
//	}
//	createRespData := createResp.Reply
//
//	// Check response
//	assert.NotNil(t, createResp)
//	assert.NotNil(t, createRespData)
//	assert.NotNil(t, createRespData.Automated)
//	assert.Regexp(t, acctest.AWSIntegrationTemplateAutomatedLinkRegexp, createRespData.Automated.Link)
//	assert.Regexp(t, TrackingGUIDRegexp, createRespData.Automated.TrackingGuid)
//
//	// Execute get request
//	instanceID := createRespData.Automated.TrackingGuid
//	getReq := ListIntegrationInstancesRequest{
//		RequestData: ListIntegrationInstancesRequestData{
//			FilterData: FilterData{
//				Paging: PagingFilter{
//					From: 0,
//					To:   1000,
//				},
//				Filter: CriteriaFilter{
//					And: []Criteria{
//						{
//							SearchField: "ID",
//							SearchType:  "WILDCARD",
//							SearchValue: instanceID,
//						},
//					},
//				},
//			},
//		},
//	}
//	getResp, err := client.ListIntegrationInstances(ctx, getReq)
//	if err != nil {
//		t.Fatalf("failed to retrieve integration template: %s", err.Error())
//	}
//	assert.NotNil(t, getResp)
//	assert.NotNil(t, getResp.Reply)
//	assert.NotNil(t, getResp.Reply.Data)
//	assert.Len(t, getResp.Reply.Data, 1)
//	getRespData := getResp.Reply.Data[0]
//
//	// Check response
//	assert.NotNil(t, getRespData)
//	assert.Equal(t, instanceID, getRespData.InstanceID)
//	assert.Equal(t, cloudProvider, getRespData.CloudProvider)
//	assert.Equal(t, instanceName, getRespData.InstanceName)
//	assert.Equal(t, scope, getRespData.Scope)
//	assert.Equal(t, scanMode, getRespData.ScanMode)
//	assert.Equal(t, "PENDING", getRespData.Status)
//
//	marshalledGetResp, err := getResp.Marshal()
//	assert.NoError(t, err)
//	assert.NotNil(t, marshalledGetResp)
//	assert.Len(t, marshalledGetResp, 1)
//	marshalledGetRespData := marshalledGetResp[0]
//
//	assert.NotNil(t, marshalledGetRespData)
//	assert.NotNil(t, marshalledGetRespData.CustomResourcesTags)
//	assert.Equal(t, marshalledGetRespData.AdditionalCapabilities, additionalCapabilities)
//	assert.Equal(t, marshalledGetRespData.CustomResourcesTags, customResourcesTags)
//
//	// Deploy CloudFormation stack
//	templateURL, err := createResp.GetTemplateUrl()
//	if err != nil {
//		t.Fatalf("failed to parse CloudFormation template URL: %s", err.Error())
//	}
//	t.Logf("CloudFormation template URL: %s", templateURL)
//	acctest.DeployCloudFormationStack(t, ctx, "us-east-1", timestamp, templateURL)
//}
