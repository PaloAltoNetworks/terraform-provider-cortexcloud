// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

//go:build acceptance

package appsec

//import (
//	"context"
//	"fmt"
//	"testing"
//	"time"
//
//	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/internal/client"
//	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/enums"
//	"github.com/stretchr/testify/assert"
//)
//
//func setupAcceptanceTest(t *testing.T) *Client {
//	client, err := NewClient(
//		WithCortexAPIURL(""),
//		WithCortexAPIKey(""),
//		WithCortexAPIKeyID(0),
//	)
//
//	assert.NoError(t, err)
//	assert.NotNil(t, client)
//	return client
//}
//
//func TestAppsecRuleLifecycle(t *testing.T) {
//	client := setupAcceptanceTest(t)
//	ctx := context.Background()
//
//	// Create a new rule
//	ruleName := fmt.Sprintf("test-rule-%d", time.Now().Unix())
//	createReq := CreateOrCloneRequest{
//		Name:        ruleName,
//		Description: "test description",
//		Category:    string(enums.IacCategoryCompute),
//		SubCategory: string(enums.IacSubCategoryComputeOverprovisioned),
//		Scanner:     string(enums.ScannerIAC),
//		Severity:    string(enums.SeverityLow),
//		Frameworks: []FrameworkData{
//			{
//				Name:       string(enums.FrameworkNameTerraform),
//				Definition: "scope:\n  provider: \"aws\"\ndefinition:\n  or:\n    - cond_type: \"attribute\"\n      resource_types:\n        - \"aws_instance\"\n      attribute: \"instance_type\"\n      operator: \"equals\"\n      value: \"t3.micro\"",
//			},
//		},
//		Labels: []string{"test-label"},
//	}
//	createdRule, err := client.CreateOrClone(ctx, createReq)
//	assert.NoError(t, err)
//	assert.NotNil(t, createdRule)
//	assert.Equal(t, ruleName, createdRule.Name)
//	ruleID := createdRule.Id
//
//	// Get the rule
//	gotRule, err := client.Get(ctx, ruleID)
//	assert.NoError(t, err)
//	assert.NotNil(t, gotRule)
//	assert.Equal(t, ruleID, gotRule.Id)
//	assert.Equal(t, ruleName, gotRule.Name)
//
//	// Update the rule
//	updatedName := fmt.Sprintf("updated-test-rule-%d", time.Now().Unix())
//	updateReq := UpdateRequest{
//		Name: updatedName,
//	}
//	updatedResp, err := client.Update(ctx, ruleID, updateReq)
//	assert.NoError(t, err)
//	assert.NotNil(t, updatedResp)
//	assert.Equal(t, updatedName, updatedResp.Rule.Name)
//
//	// Delete the rule
//	err = client.Delete(ctx, ruleID)
//	assert.NoError(t, err)
//
//	// Verify the rule is deleted
//	_, err = client.Get(ctx, ruleID)
//	assert.Error(t, err) // Expect an error when getting a deleted rule
//}
//
//func TestClient_List_Acceptance(t *testing.T) {
//	t.Skip("Skipping test due to persistent failures")
//	client := setupAcceptanceTest(t)
//	listReq := ListRequest{
//		Limit: 1,
//	}
//	resp, err := client.List(context.Background(), listReq)
//	assert.NoError(t, err)
//	assert.NotNil(t, resp)
//}
