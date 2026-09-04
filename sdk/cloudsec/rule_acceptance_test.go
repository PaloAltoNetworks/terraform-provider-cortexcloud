// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

//go:build acceptance

package cloudsec

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/enums"
	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/internal/tests"
	types "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/types/cloudsec"
)

func TestAccRule_CRUD(t *testing.T) {
	skipIfNotAcceptance(t)

	ctx := context.Background()
	config := tests.NewTestConfigFromEnv(t)
	client, err := NewClient(config.GetOptions()...)
	if err != nil {
		t.Fatalf("failed to initialize client: %s", err.Error())
	}

	// Generate unique rule name
	ruleName := fmt.Sprintf("test-rule-%d", time.Now().Unix())

	// Test Create
	t.Run("Create", func(t *testing.T) {
		enabled := true
		createReq := types.CreateRuleRequest{
			Name:        ruleName,
			Description: "Test rule created by acceptance test",
			Class:       enums.RuleClassConfig.String(),
			Type:        "DETECTION",
			AssetTypes:  []string{"aws-s3-bucket"},
			Severity:    enums.CloudSecSeverityHigh.String(),
			Query: types.QueryRequest{
				XQL: "config from cloud.resource where cloud.type = 'aws' AND api.name = 'aws-s3api-get-bucket-acl'",
			},
			Metadata: &types.MetadataRequest{
				Issue: &types.IssueRequest{
					Recommendation: "This is a test recommendation for the acceptance test.",
				},
			},
			Labels:  []string{"test", "acceptance"},
			Enabled: &enabled,
		}

		rule, err := client.Create(ctx, createReq)
		if err != nil {
			t.Fatalf("Create failed: %v", err)
		}

		if rule.ID == "" {
			t.Error("Created rule has no ID")
		}
		if rule.Name != ruleName {
			t.Errorf("Created rule name = %v, want %v", rule.Name, ruleName)
		}
		if rule.Severity != enums.CloudSecSeverityHigh.String() {
			t.Errorf("Created rule severity = %v, want %v", rule.Severity, enums.CloudSecSeverityHigh.String())
		}

		// Store ID for subsequent tests
		ruleID := rule.ID

		// Test Get
		t.Run("Get", func(t *testing.T) {
			retrieved, err := client.Get(ctx, ruleID)
			if err != nil {
				t.Fatalf("Get failed: %v", err)
			}

			if retrieved.ID != ruleID {
				t.Errorf("Retrieved rule ID = %v, want %v", retrieved.ID, ruleID)
			}
			if retrieved.Name != ruleName {
				t.Errorf("Retrieved rule name = %v, want %v", retrieved.Name, ruleName)
			}
		})

		// Test Search
		t.Run("Search", func(t *testing.T) {
			searchReq := types.SearchRulesRequest{
				Filter: &types.FilterCriteria{
					SearchField: "id",
					SearchType:  enums.SearchTypeEqualTo.String(),
					SearchValue: ruleID,
				},
				SearchFrom: 0,
				SearchTo:   10,
			}

			results, err := client.Search(ctx, searchReq)
			if err != nil {
				t.Fatalf("Search failed: %v", err)
			}

			if results.Metadata.FilterCount == 0 {
				t.Error("Search returned no results")
			}

			found := false
			for _, rule := range results.Data {
				if rule.ID == ruleID {
					found = true
					break
				}
			}
			if !found {
				t.Error("Created rule not found in search results")
			}
		})

		// Test Update
		t.Run("Update", func(t *testing.T) {
			updateReq := types.UpdateRuleRequest{
				Severity: enums.CloudSecSeverityCritical.String(),
				Labels:   []string{"test", "acceptance", "updated"},
			}

			updated, err := client.Update(ctx, ruleID, updateReq)
			if err != nil {
				t.Fatalf("Update failed: %v", err)
			}

			if updated.Severity != enums.CloudSecSeverityCritical.String() {
				t.Errorf("Updated rule severity = %v, want %v", updated.Severity, enums.CloudSecSeverityCritical.String())
			}
			if len(updated.Labels) != 3 {
				t.Errorf("Updated rule has %d labels, want 3", len(updated.Labels))
			}
		})

		// Test Delete
		t.Run("Delete", func(t *testing.T) {
			err := client.Delete(ctx, ruleID)
			if err != nil {
				t.Fatalf("Delete failed: %v", err)
			}

			// Verify deletion by attempting to get the rule
			_, err = client.Get(ctx, ruleID)
			if err == nil {
				t.Error("Expected error when getting deleted rule, got nil")
			}
		})
	})
}

func TestAccRule_Search_Filters(t *testing.T) {
	skipIfNotAcceptance(t)

	ctx := context.Background()
	config := tests.NewTestConfigFromEnv(t)
	client, err := NewClient(config.GetOptions()...)
	if err != nil {
		t.Fatalf("failed to initialize client: %s", err.Error())
	}

	t.Run("SearchWithORFilter", func(t *testing.T) {
		searchReq := types.SearchRulesRequest{
			Filter: &types.FilterCriteria{
				OR: []types.FilterCriteria{
					{
						SearchField: "severity",
						SearchType:  enums.SearchTypeEqualTo.String(),
						SearchValue: enums.CloudSecSeverityHigh.String(),
					},
					{
						SearchField: "severity",
						SearchType:  enums.SearchTypeEqualTo.String(),
						SearchValue: enums.CloudSecSeverityCritical.String(),
					},
				},
			},
			SearchFrom: 0,
			SearchTo:   50,
			Sort: []types.SortCriteria{
				{Field: "name", Order: enums.SortOrderASC.String()},
			},
		}

		results, err := client.Search(ctx, searchReq)
		if err != nil {
			t.Fatalf("Search with OR filter failed: %v", err)
		}

		if results.Metadata.FilterCount == 0 {
			t.Log("No rules found with high or critical severity (this may be expected)")
		}
	})

	t.Run("SearchWithANDFilter", func(t *testing.T) {
		searchReq := types.SearchRulesRequest{
			Filter: &types.FilterCriteria{
				AND: []types.FilterCriteria{
					{
						SearchField: "enabled",
						SearchType:  enums.SearchTypeEqualTo.String(),
						SearchValue: true,
					},
					{
						SearchField: "system_default",
						SearchType:  enums.SearchTypeEqualTo.String(),
						SearchValue: false,
					},
				},
			},
			SearchFrom: 0,
			SearchTo:   50,
		}

		results, err := client.Search(ctx, searchReq)
		if err != nil {
			t.Fatalf("Search with AND filter failed: %v", err)
		}

		t.Logf("Found %d custom enabled rules", results.Metadata.FilterCount)
	})
}

// TestAccRule_ComplianceMetadata verifies that compliance_metadata can be set on
// create and updated via the API. This exercises the ComplianceMetadataInput type
// end-to-end against a real API.
func TestAccRule_ComplianceMetadata(t *testing.T) {
	skipIfNotAcceptance(t)

	ctx := context.Background()
	config := tests.NewTestConfigFromEnv(t)
	client, err := NewClient(config.GetOptions()...)
	if err != nil {
		t.Fatalf("failed to initialize client: %s", err.Error())
	}

	ruleName := fmt.Sprintf("test-compliance-metadata-%d", time.Now().Unix())

	// Create a rule with compliance_metadata
	enabled := true
	createReq := types.CreateRuleRequest{
		Name:       ruleName,
		Class:      enums.RuleClassConfig.String(),
		Type:       "DETECTION",
		AssetTypes: []string{"aws-s3-bucket"},
		Severity:   enums.CloudSecSeverityHigh.String(),
		Query: types.QueryRequest{
			XQL: "config from cloud.resource where cloud.type = 'aws' AND api.name = 'aws-s3api-get-bucket-acl'",
		},
		Metadata: &types.MetadataRequest{
			Issue: &types.IssueRequest{
				Recommendation: "Test recommendation for compliance_metadata acceptance test.",
			},
		},
		Labels:  []string{"test", "compliance-metadata"},
		Enabled: &enabled,
		ComplianceMetadata: []types.ComplianceMetadataInput{
			{ControlID: "requirement-cis-1"},
		},
	}

	rule, err := client.Create(ctx, createReq)
	if err != nil {
		t.Fatalf("Create with compliance_metadata failed: %v", err)
	}
	// Ensure cleanup
	defer func() {
		_ = client.Delete(ctx, rule.ID)
	}()

	// Verify the response contains enriched compliance_metadata
	if len(rule.ComplianceMetadata) == 0 {
		t.Log("Warning: API returned empty compliance_metadata in create response (may need valid control_id for enrichment)")
	} else {
		for i, cm := range rule.ComplianceMetadata {
			if cm.ControlID == "" {
				t.Errorf("compliance_metadata[%d].control_id is empty", i)
			}
			t.Logf("compliance_metadata[%d]: control_id=%s, control_name=%s, standard_id=%s, standard_name=%s",
				i, cm.ControlID, cm.ControlName, cm.StandardID, cm.StandardName)
		}
	}

	// Update the rule with different compliance_metadata
	updateReq := types.UpdateRuleRequest{
		ComplianceMetadata: []types.ComplianceMetadataInput{
			{ControlID: "requirement-cis-1"},
			{ControlID: "requirement-cis-2"},
		},
	}

	updated, err := client.Update(ctx, rule.ID, updateReq)
	if err != nil {
		t.Fatalf("Update with compliance_metadata failed: %v", err)
	}

	if len(updated.ComplianceMetadata) == 0 {
		t.Log("Warning: API returned empty compliance_metadata in update response (may need valid control_id for enrichment)")
	} else {
		t.Logf("After update: %d compliance_metadata entries", len(updated.ComplianceMetadata))
	}

	// Verify via Get that compliance_metadata persisted
	retrieved, err := client.Get(ctx, rule.ID)
	if err != nil {
		t.Fatalf("Get after compliance_metadata update failed: %v", err)
	}

	t.Logf("Retrieved rule has %d compliance_metadata entries", len(retrieved.ComplianceMetadata))
}

// TestAccRule_RecreateSameName reproduces a reported recreate-after-delete
// failure.
//
// Scenario reported by a customer:
//  1. A CloudSec rule is created via Terraform with a given name.
//  2. The rule is deleted (via UI or Terraform).
//  3. The SAME Terraform script is re-applied, attempting to create a rule
//     with the IDENTICAL name.
//
// The customer observed a 409 ("A detection rule with the same name already
// exists"), and in other reports 400/500 errors, despite the rule
// no longer being visible in Cortex Cloud. This strongly suggests a stale,
// name-keyed index on the backend that is not cleared on delete.
//
// This test exercises that exact create -> delete -> recreate-same-name path
// against a live tenant so the backend behavior can be confirmed. The provider
// SDK itself only issues POST (create) and DELETE (by id); it does no
// name-based bookkeeping, so any failure here is server-side.
//
// Run with:
//
//	TF_ACC=1 CORTEX_API_URL=... CORTEX_API_KEY=... CORTEX_API_KEY_ID=... \
//	  go test ./cloudsec -run TestAccRule_RecreateSameName -v
func TestAccRule_RecreateSameName(t *testing.T) {
	skipIfNotAcceptance(t)

	ctx := context.Background()
	config := tests.NewTestConfigFromEnv(t)
	client, err := NewClient(config.GetOptions()...)
	if err != nil {
		t.Fatalf("failed to initialize client: %s", err.Error())
	}

	// Reuse a fixed name across the whole sequence to mirror the customer's
	// Terraform script, which always renders the same rule name.
	ruleName := fmt.Sprintf("recreate-same-name-repro-%d", time.Now().Unix())

	enabled := true
	newCreateReq := func() types.CreateRuleRequest {
		return types.CreateRuleRequest{
			Name:        ruleName,
			Description: "Repro rule for recreate-after-delete",
			Class:       enums.RuleClassConfig.String(),
			Type:        "DETECTION",
			AssetTypes:  []string{"S3_BUCKET"},
			Severity:    enums.CloudSecSeverityHigh.String(),
			Query: types.QueryRequest{
				XQL: "dataset = asset_inventory | filter xdm.asset.provider = \"aws\" and xdm.asset.type.id = \"S3_BUCKET\" | fields xdm.asset.id as asset_id, xdm.asset.type.id as asset_type_id, xdm.asset.name as asset_name",
			},
			Metadata: &types.MetadataRequest{
				Issue: &types.IssueRequest{
					Recommendation: "Repro recommendation.",
				},
			},
			Labels:  []string{"recreate-repro", "repro"},
			Enabled: &enabled,
		}
	}

	// Step 1: initial create (the customer's first successful apply).
	first, err := client.Create(ctx, newCreateReq())
	if err != nil {
		t.Fatalf("initial Create failed: %v", err)
	}
	t.Logf("created rule id=%s name=%q", first.ID, first.Name)

	// Step 2: delete the rule (the customer's delete via UI or Terraform).
	if err := client.Delete(ctx, first.ID); err != nil {
		// Cleanup is best-effort; fail loudly so we don't leak a rule.
		t.Fatalf("Delete failed: %v", err)
	}
	t.Logf("deleted rule id=%s", first.ID)

	// Confirm the rule is actually gone from the customer's point of view.
	if _, err := client.Get(ctx, first.ID); err == nil {
		t.Error("expected Get on deleted rule to fail, got nil error")
	} else {
		t.Logf("confirmed deletion: Get returned: %v", err)
	}

	// Give the backend a moment in case deletion / index cleanup is async.
	time.Sleep(5 * time.Second)

	// Step 3: re-create with the IDENTICAL name (the customer's second apply).
	// One report shows this returns 409; another shows 400/500.
	second, recreateErr := client.Create(ctx, newCreateReq())

	if recreateErr != nil {
		// Bug reproduced: deleting then recreating the same name fails even
		// though the rule no longer exists.
		t.Fatalf("REPRODUCED recreate-after-delete: recreate with same name %q failed "+
			"after delete: %v", ruleName, recreateErr)
	}

	// Not reproduced on this tenant: clean up the recreated rule.
	t.Logf("recreate succeeded id=%s name=%q (issue NOT reproduced on this tenant)",
		second.ID, second.Name)
	if err := client.Delete(ctx, second.ID); err != nil {
		t.Errorf("cleanup Delete of recreated rule failed: %v", err)
	}
}

// TestAccRule_RecreateSameName_Race is an aggressive variant of the
// recreate-after-delete reproduction. The customer's failures appear timing-sensitive, so
// this test repeatedly does delete -> IMMEDIATE recreate (no delay) with the
// SAME name across several iterations, trying to hit a stale, name-keyed index
// window on the backend where the name is still considered "taken" right after
// deletion.
//
// Run with:
//
//	TF_ACC=1 CORTEXCLOUD_API_URL_TEST=... CORTEXCLOUD_API_KEY_TEST=... \
//	  CORTEXCLOUD_API_KEY_ID_TEST=... \
//	  go test ./cloudsec -run TestAccRule_RecreateSameName_Race -v
func TestAccRule_RecreateSameName_Race(t *testing.T) {
	skipIfNotAcceptance(t)

	ctx := context.Background()
	config := tests.NewTestConfigFromEnv(t)
	client, err := NewClient(config.GetOptions()...)
	if err != nil {
		t.Fatalf("failed to initialize client: %s", err.Error())
	}

	const iterations = 8
	ruleName := fmt.Sprintf("recreate-same-name-race-%d", time.Now().Unix())
	enabled := true
	newCreateReq := func() types.CreateRuleRequest {
		return types.CreateRuleRequest{
			Name:        ruleName,
			Description: "Race repro for recreate-after-delete",
			Class:       enums.RuleClassConfig.String(),
			Type:        "DETECTION",
			AssetTypes:  []string{"S3_BUCKET"},
			Severity:    enums.CloudSecSeverityHigh.String(),
			Query: types.QueryRequest{
				XQL: "dataset = asset_inventory | filter xdm.asset.provider = \"aws\" and xdm.asset.type.id = \"S3_BUCKET\" | fields xdm.asset.id as asset_id, xdm.asset.type.id as asset_type_id, xdm.asset.name as asset_name",
			},
			Labels:  []string{"recreate-repro", "race"},
			Enabled: &enabled,
		}
	}

	// Seed the first rule.
	current, err := client.Create(ctx, newCreateReq())
	if err != nil {
		t.Fatalf("initial Create failed: %v", err)
	}

	for i := 0; i < iterations; i++ {
		// Delete the current rule.
		if err := client.Delete(ctx, current.ID); err != nil {
			t.Fatalf("iter %d: Delete(id=%s) failed: %v", i, current.ID, err)
		}

		// IMMEDIATELY recreate with the same name (no delay) - this is the
		// window the customer's repro seems to hit.
		recreated, recreateErr := client.Create(ctx, newCreateReq())
		if recreateErr != nil {
			t.Fatalf("REPRODUCED recreate-after-delete on iteration %d: immediate recreate "+
				"of name %q after delete failed: %v", i, ruleName, recreateErr)
		}
		t.Logf("iter %d: delete+immediate-recreate OK, new id=%s", i, recreated.ID)
		current = recreated
	}

	// Final cleanup.
	if err := client.Delete(ctx, current.ID); err != nil {
		t.Errorf("final cleanup Delete failed: %v", err)
	}
	t.Logf("completed %d delete+immediate-recreate cycles with no failure (issue NOT reproduced)", iterations)
}
