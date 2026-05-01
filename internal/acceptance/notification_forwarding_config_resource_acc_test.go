// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package acceptance

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/PaloAltoNetworks/cortex-cloud-go/log"
	"github.com/PaloAltoNetworks/cortex-cloud-go/platform"
	platformTypes "github.com/PaloAltoNetworks/cortex-cloud-go/types/platform"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

// ----------------------------------------------------------------------------
// Shared templates
// ----------------------------------------------------------------------------

const (
	notificationForwardingConfigTmpl = `
resource "%s" "%s" {
  name = "%s"	
  description = "%s"
  
  // Enabled
  %s

  // Scope
  %s

  // Email config
  %s

  // Syslog config
  %s
}`

	notificationForwardingConfigScopeFilterConditionTmpl = `
	  { 
	    search_field = "%s"
            search_type = "%s"
            search_value = "%s"
          }`

	notificationForwardingConfigEmailConfigTmpl = `email_config = {
    distribution_list = ["%s"]
    grouping_timeframe = %d
    subject = "%s"
  }`

	notificationForwardingConfigSyslogConfigTmpl = `syslog_config = {
    server_id = "%d"
    %s
  }`
)

// ----------------------------------------------------------------------------
// Agent Audit Logs Test Data
// ----------------------------------------------------------------------------

const (
	notificationForwardingConfigAgentAuditLogsResourceType          = "cortexcloud_notification_forwarding_config_agent_audit_logs"
	notificationForwardingConfigAgentAuditLogsResourceName          = "test-agent-audit-logs"
	notificationForwardingConfigAgentAuditLogsName                  = "tf-provider-acc-test-agent-audit-logs"
	notificationForwardingConfigAgentAuditLogsDescription           = "Cortex Cloud Terraform provider lifecycle acceptance test (agent audit logs)"
	notificationForwardingConfigAgentAuditLogsEnabled               = true
	notificationForwardingConfigAgentAuditLogsSyslogServerID        = 1
	notificationForwardingConfigAgentAuditLogsNameUpdated           = "tf-provider-acc-test-agent-audit-logs-updated"
	notificationForwardingConfigAgentAuditLogsDescriptionUpdated    = "Cortex Cloud Terraform provider lifecycle acceptance test (agent audit logs) updated"
	notificationForwardingConfigAgentAuditLogsEnabledUpdated        = false
	notificationForwardingConfigAgentAuditLogsSyslogServerIDUpdated = 2
)

var (
	notificationForwardingConfigAgentAuditLogsResourceNameFull = fmt.Sprintf(
		"%s.%s",
		notificationForwardingConfigAgentAuditLogsResourceType,
		notificationForwardingConfigAgentAuditLogsResourceName,
	)
	notificationForwardingConfigAgentAuditLogsScopeConditionCategory = fmt.Sprintf(
		notificationForwardingConfigScopeFilterConditionTmpl,
		"CATEGORY",
		"EQ",
		"Audit",
	)
	notificationForwardingConfigAgentAuditLogsScopeConditionType = fmt.Sprintf(
		notificationForwardingConfigScopeFilterConditionTmpl,
		"TYPE",
		"EQ",
		"Action",
	)
	notificationForwardingConfigAgentAuditLogsScopeConditionSeverityHigh = fmt.Sprintf(
		notificationForwardingConfigScopeFilterConditionTmpl,
		"SEVERITY",
		"EQ",
		"SEV_040_HIGH",
	)
	notificationForwardingConfigAgentAuditLogsScopeFull = fmt.Sprintf(`scope = {
    or = [
      {
        and = [
	  %s,
	  %s
        ]
      },
      {
        and = [
	  %s
        ]
      }
    ]
  }`,
		notificationForwardingConfigAgentAuditLogsScopeConditionCategory,
		notificationForwardingConfigAgentAuditLogsScopeConditionType,
		notificationForwardingConfigAgentAuditLogsScopeConditionSeverityHigh,
	)
	notificationForwardingConfigAgentAuditLogsScopeConditionCategoryUpdated = fmt.Sprintf(
		notificationForwardingConfigScopeFilterConditionTmpl,
		"CATEGORY",
		"NEQ",
		"Audit",
	)
	notificationForwardingConfigAgentAuditLogsScopeConditionTypeUpdated = fmt.Sprintf(
		notificationForwardingConfigScopeFilterConditionTmpl,
		"TYPE",
		"NEQ",
		"Action",
	)
	notificationForwardingConfigAgentAuditLogsScopeConditionSeverityHighUpdated = fmt.Sprintf(
		notificationForwardingConfigScopeFilterConditionTmpl,
		"SEVERITY",
		"NEQ",
		"SEV_040_HIGH",
	)
	notificationForwardingConfigAgentAuditLogsScopeFullUpdated = fmt.Sprintf(`scope = {
    or = [
      {
        and = [
	  %s,
	  %s
        ]
      },
      {
        and = [
	  %s
        ]
      }
    ]
  }`,
		notificationForwardingConfigAgentAuditLogsScopeConditionCategoryUpdated,
		notificationForwardingConfigAgentAuditLogsScopeConditionTypeUpdated,
		notificationForwardingConfigAgentAuditLogsScopeConditionSeverityHighUpdated,
	)
	notificationForwardingConfigAgentAuditLogsEmailConfig = fmt.Sprintf(
		notificationForwardingConfigEmailConfigTmpl,
		"test@email.com",
		123,
		"test subject agent audit logs",
	)
	notificationForwardingConfigAgentAuditLogsEmailConfigUpdated = fmt.Sprintf(
		notificationForwardingConfigEmailConfigTmpl,
		strings.Join([]string{"test11@email.com", "test22@email.com"}, "\", \""),
		321,
		"test subject agent audit logs updated",
	)
	notificationForwardingConfigAgentAuditLogsSyslogConfig = fmt.Sprintf(
		notificationForwardingConfigSyslogConfigTmpl,
		notificationForwardingConfigAgentAuditLogsSyslogServerID,
		"",
	)
	notificationForwardingConfigAgentAuditLogsSyslogConfigUpdated = fmt.Sprintf(
		notificationForwardingConfigSyslogConfigTmpl,
		notificationForwardingConfigAgentAuditLogsSyslogServerIDUpdated,
		"",
	)
	notificationForwardingConfigResourceAgentAuditLogsFull = fmt.Sprintf(
		notificationForwardingConfigTmpl,
		notificationForwardingConfigAgentAuditLogsResourceType,
		notificationForwardingConfigAgentAuditLogsResourceName,
		notificationForwardingConfigAgentAuditLogsName,
		notificationForwardingConfigAgentAuditLogsDescription,
		"enabled = "+strconv.FormatBool(notificationForwardingConfigAgentAuditLogsEnabled),
		notificationForwardingConfigAgentAuditLogsScopeFull,
		notificationForwardingConfigAgentAuditLogsEmailConfig,
		notificationForwardingConfigAgentAuditLogsSyslogConfig,
	)
	notificationForwardingConfigResourceAgentAuditLogsFullUpdated = fmt.Sprintf(
		notificationForwardingConfigTmpl,
		notificationForwardingConfigAgentAuditLogsResourceType,
		notificationForwardingConfigAgentAuditLogsResourceName,
		notificationForwardingConfigAgentAuditLogsNameUpdated,
		notificationForwardingConfigAgentAuditLogsDescriptionUpdated,
		"enabled = "+strconv.FormatBool(notificationForwardingConfigAgentAuditLogsEnabledUpdated),
		notificationForwardingConfigAgentAuditLogsScopeFullUpdated,
		notificationForwardingConfigAgentAuditLogsEmailConfigUpdated,
		notificationForwardingConfigAgentAuditLogsSyslogConfigUpdated,
	)
)

// ----------------------------------------------------------------------------
// Management Audit Logs Test Data
// ----------------------------------------------------------------------------

const (
	// Management Audit Logs resource
	notificationForwardingConfigMgmtAuditLogsResourceType          = "cortexcloud_notification_forwarding_config_mgmt_audit_logs"
	notificationForwardingConfigMgmtAuditLogsResourceName          = "test-mgmt-audit-logs"
	notificationForwardingConfigMgmtAuditLogsName                  = "tf-provider-acc-test-mgmt-audit-logs"
	notificationForwardingConfigMgmtAuditLogsDescription           = "Cortex Cloud Terraform provider lifecycle acceptance test (mgmt audit logs)"
	notificationForwardingConfigMgmtAuditLogsEnabled               = true
	notificationForwardingConfigMgmtAuditLogsSyslogServerID        = 1
	notificationForwardingConfigMgmtAuditLogsNameUpdated           = "tf-provider-acc-test-mgmt-audit-logs-updated"
	notificationForwardingConfigMgmtAuditLogsDescriptionUpdated    = "Cortex Cloud Terraform provider lifecycle acceptance test (mgmt audit logs) updated"
	notificationForwardingConfigMgmtAuditLogsEnabledUpdated        = false
	notificationForwardingConfigMgmtAuditLogsSyslogServerIDUpdated = 2
)

var (
	notificationForwardingConfigMgmtAuditLogsResourceNameFull = fmt.Sprintf(
		"%s.%s",
		notificationForwardingConfigMgmtAuditLogsResourceType,
		notificationForwardingConfigMgmtAuditLogsResourceName,
	)
	notificationForwardingConfigMgmtAuditLogsScopeConditionCategory = fmt.Sprintf(
		notificationForwardingConfigScopeFilterConditionTmpl,
		"CATEGORY",
		"EQ",
		"Audit",
	)
	notificationForwardingConfigMgmtAuditLogsScopeConditionType = fmt.Sprintf(
		notificationForwardingConfigScopeFilterConditionTmpl,
		"TYPE",
		"EQ",
		"Action",
	)
	notificationForwardingConfigMgmtAuditLogsScopeConditionSeverityHigh = fmt.Sprintf(
		notificationForwardingConfigScopeFilterConditionTmpl,
		"SEVERITY",
		"EQ",
		"SEV_040_HIGH",
	)
	notificationForwardingConfigMgmtAuditLogsScopeFull = fmt.Sprintf(`scope = {
    or = [
      {
        and = [
	  %s,
	  %s
        ]
      },
      {
        and = [
	  %s
        ]
      }
    ]
  }`,
		notificationForwardingConfigMgmtAuditLogsScopeConditionCategory,
		notificationForwardingConfigMgmtAuditLogsScopeConditionType,
		notificationForwardingConfigMgmtAuditLogsScopeConditionSeverityHigh,
	)
	notificationForwardingConfigMgmtAuditLogsScopeConditionCategoryUpdated = fmt.Sprintf(
		notificationForwardingConfigScopeFilterConditionTmpl,
		"CATEGORY",
		"NEQ",
		"Audit",
	)
	notificationForwardingConfigMgmtAuditLogsScopeConditionTypeUpdated = fmt.Sprintf(
		notificationForwardingConfigScopeFilterConditionTmpl,
		"TYPE",
		"NEQ",
		"Action",
	)
	notificationForwardingConfigMgmtAuditLogsScopeConditionSeverityHighUpdated = fmt.Sprintf(
		notificationForwardingConfigScopeFilterConditionTmpl,
		"SEVERITY",
		"NEQ",
		"SEV_040_HIGH",
	)
	notificationForwardingConfigMgmtAuditLogsScopeFullUpdated = fmt.Sprintf(`scope = {
    or = [
      {
        and = [
	  %s,
	  %s
        ]
      },
      {
        and = [
	  %s
        ]
      }
    ]
  }`,
		notificationForwardingConfigMgmtAuditLogsScopeConditionCategoryUpdated,
		notificationForwardingConfigMgmtAuditLogsScopeConditionTypeUpdated,
		notificationForwardingConfigMgmtAuditLogsScopeConditionSeverityHighUpdated,
	)
	notificationForwardingConfigMgmtAuditLogsEmailConfig = fmt.Sprintf(
		notificationForwardingConfigEmailConfigTmpl,
		"test@email.com",
		123,
		"test subject mgmt audit logs",
	)
	notificationForwardingConfigMgmtAuditLogsEmailConfigUpdated = fmt.Sprintf(
		notificationForwardingConfigEmailConfigTmpl,
		strings.Join([]string{"test11@email.com", "test22@email.com"}, "\", \""),
		321,
		"test subject mgmt audit logs updated",
	)
	notificationForwardingConfigMgmtAuditLogsSyslogConfig = fmt.Sprintf(
		notificationForwardingConfigSyslogConfigTmpl,
		notificationForwardingConfigMgmtAuditLogsSyslogServerID,
		"",
	)
	notificationForwardingConfigMgmtAuditLogsSyslogConfigUpdated = fmt.Sprintf(
		notificationForwardingConfigSyslogConfigTmpl,
		notificationForwardingConfigMgmtAuditLogsSyslogServerIDUpdated,
		"",
	)
	notificationForwardingConfigResourceMgmtAuditLogsFull = fmt.Sprintf(
		notificationForwardingConfigTmpl,
		notificationForwardingConfigMgmtAuditLogsResourceType,
		notificationForwardingConfigMgmtAuditLogsResourceName,
		notificationForwardingConfigMgmtAuditLogsName,
		notificationForwardingConfigMgmtAuditLogsDescription,
		"enabled = "+strconv.FormatBool(notificationForwardingConfigMgmtAuditLogsEnabled),
		notificationForwardingConfigMgmtAuditLogsScopeFull,
		notificationForwardingConfigMgmtAuditLogsEmailConfig,
		notificationForwardingConfigMgmtAuditLogsSyslogConfig,
	)
	notificationForwardingConfigResourceMgmtAuditLogsFullUpdated = fmt.Sprintf(
		notificationForwardingConfigTmpl,
		notificationForwardingConfigMgmtAuditLogsResourceType,
		notificationForwardingConfigMgmtAuditLogsResourceName,
		notificationForwardingConfigMgmtAuditLogsNameUpdated,
		notificationForwardingConfigMgmtAuditLogsDescriptionUpdated,
		"enabled = "+strconv.FormatBool(notificationForwardingConfigMgmtAuditLogsEnabledUpdated),
		notificationForwardingConfigMgmtAuditLogsScopeFullUpdated,
		notificationForwardingConfigMgmtAuditLogsEmailConfigUpdated,
		notificationForwardingConfigMgmtAuditLogsSyslogConfigUpdated,
	)
)

// ----------------------------------------------------------------------------
// Cases
// ----------------------------------------------------------------------------

const (
	notificationForwardingConfigCasesResourceType       = "cortexcloud_notification_forwarding_config_cases"
	notificationForwardingConfigCasesResourceName       = "test-cases"
	notificationForwardingConfigCasesName               = "tf-provider-acc-test-cases"
	notificationForwardingConfigCasesDescription        = "Cortex Cloud Terraform provider lifecycle acceptance test (cases)"
	notificationForwardingConfigCasesEnabled            = true
	notificationForwardingConfigCasesNameUpdated        = "tf-provider-acc-test-cases-updated"
	notificationForwardingConfigCasesDescriptionUpdated = "Cortex Cloud Terraform provider lifecycle acceptance test (cases) updated"
	notificationForwardingConfigCasesEnabledUpdated     = false
)

var (
	notificationForwardingConfigCasesResourceNameFull = fmt.Sprintf(
		"%s.%s",
		notificationForwardingConfigCasesResourceType,
		notificationForwardingConfigCasesResourceName,
	)
	notificationForwardingConfigCasesScopeConditionStatus = fmt.Sprintf(
		notificationForwardingConfigScopeFilterConditionTmpl,
		"STATUS_PROGRESS",
		"NEQ",
		"STATUS_025_RESOLVED",
	)
	notificationForwardingConfigCasesScopeConditionSeverityCritical = fmt.Sprintf(
		notificationForwardingConfigScopeFilterConditionTmpl,
		"SEVERITY",
		"EQ",
		"SEV_050_CRITICAL",
	)
	notificationForwardingConfigCasesScopeConditionCaseID = fmt.Sprintf(
		notificationForwardingConfigScopeFilterConditionTmpl,
		"CASE_ID",
		"EQ",
		"123",
	)
	notificationForwardingConfigCasesScopeFull = fmt.Sprintf(`scope = {
    or = [
      {
        and = [
	  %s,
	  %s
        ]
      },
      {
        and = [
	  %s
        ]
      }
    ]
  }`,
		notificationForwardingConfigCasesScopeConditionStatus,
		notificationForwardingConfigCasesScopeConditionSeverityCritical,
		notificationForwardingConfigCasesScopeConditionCaseID,
	)
	notificationForwardingConfigCasesScopeConditionStatusUpdated = fmt.Sprintf(
		notificationForwardingConfigScopeFilterConditionTmpl,
		"STATUS_PROGRESS",
		"EQ",
		"STATUS_020_UNDER_INVESTIGATION",
	)
	notificationForwardingConfigCasesScopeConditionSeverityCriticalUpdated = fmt.Sprintf(
		notificationForwardingConfigScopeFilterConditionTmpl,
		"SEVERITY",
		"EQ",
		"SEV_030_MEDIUM",
	)
	notificationForwardingConfigCasesScopeConditionCaseIDUpdated = fmt.Sprintf(
		notificationForwardingConfigScopeFilterConditionTmpl,
		"CASE_ID",
		"EQ",
		"321",
	)
	notificationForwardingConfigCasesScopeFullUpdated = fmt.Sprintf(`scope = {
    or = [
      {
        and = [
	  %s,
	  %s
        ]
      },
      {
        and = [
	  %s
        ]
      }
    ]
  }`,
		notificationForwardingConfigCasesScopeConditionStatusUpdated,
		notificationForwardingConfigCasesScopeConditionSeverityCriticalUpdated,
		notificationForwardingConfigCasesScopeConditionCaseIDUpdated,
	)
	notificationForwardingConfigCasesEmailConfig = fmt.Sprintf(
		notificationForwardingConfigEmailConfigTmpl,
		"test@email.com",
		123,
		"test subject cases",
	)
	notificationForwardingConfigCasesEmailConfigUpdated = fmt.Sprintf(
		notificationForwardingConfigEmailConfigTmpl,
		strings.Join([]string{"test11@email.com", "test22@email.com"}, "\", \""),
		321,
		"test subject cases updated",
	)
	notificationForwardingConfigResourceCasesFull = fmt.Sprintf(
		notificationForwardingConfigTmpl,
		notificationForwardingConfigCasesResourceType,
		notificationForwardingConfigCasesResourceName,
		notificationForwardingConfigCasesName,
		notificationForwardingConfigCasesDescription,
		"enabled = "+strconv.FormatBool(notificationForwardingConfigCasesEnabled),
		notificationForwardingConfigCasesScopeFull,
		notificationForwardingConfigCasesEmailConfig,
		"",
	)
	notificationForwardingConfigResourceCasesFullUpdated = fmt.Sprintf(
		notificationForwardingConfigTmpl,
		notificationForwardingConfigCasesResourceType,
		notificationForwardingConfigCasesResourceName,
		notificationForwardingConfigCasesNameUpdated,
		notificationForwardingConfigCasesDescriptionUpdated,
		"enabled = "+strconv.FormatBool(notificationForwardingConfigCasesEnabledUpdated),
		notificationForwardingConfigCasesScopeFullUpdated,
		notificationForwardingConfigCasesEmailConfigUpdated,
		"",
	)
)

// ----------------------------------------------------------------------------
// Issues
// ----------------------------------------------------------------------------

const (
	notificationForwardingConfigIssuesResourceType          = "cortexcloud_notification_forwarding_config_issues"
	notificationForwardingConfigIssuesResourceName          = "test-issues"
	notificationForwardingConfigIssuesName                  = "tf-provider-acc-test-issues"
	notificationForwardingConfigIssuesDescription           = "Cortex Cloud Terraform provider lifecycle acceptance test (issues)"
	notificationForwardingConfigIssuesEnabled               = true
	notificationForwardingConfigIssuesSyslogServerID        = 1
	notificationForwardingConfigIssuesEmailFormat           = "issue"
	notificationForwardingConfigIssuesNameUpdated           = "tf-provider-acc-test-issues-updated"
	notificationForwardingConfigIssuesDescriptionUpdated    = "Cortex Cloud Terraform provider lifecycle acceptance test (issues) updated"
	notificationForwardingConfigIssuesEnabledUpdated        = false
	notificationForwardingConfigIssuesEmailFormatUpdated    = "standard_alert"
	notificationForwardingConfigIssuesSyslogServerIDUpdated = 2
)

var (
	notificationForwardingConfigIssuesResourceNameFull = fmt.Sprintf(
		"%s.%s",
		notificationForwardingConfigIssuesResourceType,
		notificationForwardingConfigIssuesResourceName,
	)
	notificationForwardingConfigIssuesScopeConditionExcluded = fmt.Sprintf(
		notificationForwardingConfigScopeFilterConditionTmpl,
		"IS_WHITELISTED",
		"EQ",
		"false",
	)
	notificationForwardingConfigIssuesScopeConditionAlertName = fmt.Sprintf(
		notificationForwardingConfigScopeFilterConditionTmpl,
		"ALERT_NAME",
		"CONTAINS",
		"acctest",
	)
	notificationForwardingConfigIssuesScopeConditionStarred = fmt.Sprintf(
		notificationForwardingConfigScopeFilterConditionTmpl,
		"STARRED",
		"EQ",
		"true",
	)
	notificationForwardingConfigIssuesScopeFull = fmt.Sprintf(`scope = {
    or = [
      {
        and = [
	  %s,
	  %s
        ]
      },
      {
        and = [
	  %s
        ]
      }
    ]
  }`,
		notificationForwardingConfigIssuesScopeConditionExcluded,
		notificationForwardingConfigIssuesScopeConditionAlertName,
		notificationForwardingConfigIssuesScopeConditionStarred,
	)
	notificationForwardingConfigIssuesScopeConditionExcludedUpdated = fmt.Sprintf(
		notificationForwardingConfigScopeFilterConditionTmpl,
		"IS_WHITELISTED",
		"EQ",
		"true",
	)
	notificationForwardingConfigIssuesScopeConditionAlertNameUpdated = fmt.Sprintf(
		notificationForwardingConfigScopeFilterConditionTmpl,
		"ALERT_NAME",
		"CONTAINS",
		"acctestupdated",
	)
	notificationForwardingConfigIssuesScopeConditionStarredUpdated = fmt.Sprintf(
		notificationForwardingConfigScopeFilterConditionTmpl,
		"STARRED",
		"EQ",
		"false",
	)
	notificationForwardingConfigIssuesScopeFullUpdated = fmt.Sprintf(`scope = {
    or = [
      {
        and = [
	  %s,
	  %s
        ]
      },
      {
        and = [
	  %s
        ]
      }
    ]
  }`,
		notificationForwardingConfigIssuesScopeConditionExcludedUpdated,
		notificationForwardingConfigIssuesScopeConditionAlertNameUpdated,
		notificationForwardingConfigIssuesScopeConditionStarredUpdated,
	)
	notificationForwardingConfigIssuesEmailConfig = fmt.Sprintf(
		notificationForwardingConfigEmailConfigTmpl,
		"test@email.com",
		123,
		"test subject issues",
	)
	notificationForwardingConfigIssuesEmailConfigUpdated = fmt.Sprintf(
		notificationForwardingConfigEmailConfigTmpl,
		strings.Join([]string{"test11@email.com", "test22@email.com"}, "\", \""),
		321,
		"test subject issues updated",
	)
	notificationForwardingConfigIssuesSyslogConfig = fmt.Sprintf(
		notificationForwardingConfigSyslogConfigTmpl,
		notificationForwardingConfigIssuesSyslogServerID,
		"format = \""+notificationForwardingConfigIssuesEmailFormat+"\"",
	)
	notificationForwardingConfigIssuesSyslogConfigUpdated = fmt.Sprintf(
		notificationForwardingConfigSyslogConfigTmpl,
		notificationForwardingConfigIssuesSyslogServerIDUpdated,
		"format = \""+notificationForwardingConfigIssuesEmailFormatUpdated+"\"",
	)
	notificationForwardingConfigResourceIssuesFull = fmt.Sprintf(
		notificationForwardingConfigTmpl,
		notificationForwardingConfigIssuesResourceType,
		notificationForwardingConfigIssuesResourceName,
		notificationForwardingConfigIssuesName,
		notificationForwardingConfigIssuesDescription,
		"enabled = "+strconv.FormatBool(notificationForwardingConfigIssuesEnabled),
		notificationForwardingConfigIssuesScopeFull,
		notificationForwardingConfigIssuesEmailConfig,
		notificationForwardingConfigIssuesSyslogConfig,
	)
	notificationForwardingConfigResourceIssuesFullUpdated = fmt.Sprintf(
		notificationForwardingConfigTmpl,
		notificationForwardingConfigIssuesResourceType,
		notificationForwardingConfigIssuesResourceName,
		notificationForwardingConfigIssuesNameUpdated,
		notificationForwardingConfigIssuesDescriptionUpdated,
		"enabled = "+strconv.FormatBool(notificationForwardingConfigIssuesEnabledUpdated),
		notificationForwardingConfigIssuesScopeFullUpdated,
		notificationForwardingConfigIssuesEmailConfigUpdated,
		notificationForwardingConfigIssuesSyslogConfigUpdated,
	)
)

// TestAccNotificationForwardingConfigAgentAuditLogsResourceLifecycle executes the full lifecycle
func TestAccNotificationForwardingConfigAgentAuditLogsResourceLifecycle(t *testing.T) {
	providerConfig := getProviderConfig(t, dotEnvPath, true)

	//err := testAccCheckSyslogIntegration(t)
	//if err != nil {
	//	t.Fatal(err.Error())
	//}

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testAccPreCheck(t)
		},
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				PreConfig: func() {
					t.Log("Executing Create step for notification forwarding configuration agent audits logs resource lifecycle test")
				},
				Config: providerConfig + notificationForwardingConfigResourceAgentAuditLogsFull,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(notificationForwardingConfigAgentAuditLogsResourceNameFull, "name", notificationForwardingConfigAgentAuditLogsName),
					resource.TestCheckResourceAttr(notificationForwardingConfigAgentAuditLogsResourceNameFull, "description", notificationForwardingConfigAgentAuditLogsDescription),
					resource.TestCheckResourceAttr(notificationForwardingConfigAgentAuditLogsResourceNameFull, "enabled", "true"),
					resource.TestCheckResourceAttr(notificationForwardingConfigAgentAuditLogsResourceNameFull, "scope.or.#", "2"),
					resource.TestCheckResourceAttr(notificationForwardingConfigAgentAuditLogsResourceNameFull, "scope.or.0.and.#", "2"),
					resource.TestCheckResourceAttr(notificationForwardingConfigAgentAuditLogsResourceNameFull, "scope.or.0.and.0.search_field", "CATEGORY"),
					resource.TestCheckResourceAttr(notificationForwardingConfigAgentAuditLogsResourceNameFull, "scope.or.0.and.0.search_type", "EQ"),
					resource.TestCheckResourceAttr(notificationForwardingConfigAgentAuditLogsResourceNameFull, "scope.or.0.and.0.search_value", "Audit"),
					resource.TestCheckResourceAttr(notificationForwardingConfigAgentAuditLogsResourceNameFull, "scope.or.0.and.1.search_field", "TYPE"),
					resource.TestCheckResourceAttr(notificationForwardingConfigAgentAuditLogsResourceNameFull, "scope.or.0.and.1.search_type", "EQ"),
					resource.TestCheckResourceAttr(notificationForwardingConfigAgentAuditLogsResourceNameFull, "scope.or.0.and.1.search_value", "Action"),
					resource.TestCheckResourceAttr(notificationForwardingConfigAgentAuditLogsResourceNameFull, "scope.or.1.and.0.search_field", "SEVERITY"),
					resource.TestCheckResourceAttr(notificationForwardingConfigAgentAuditLogsResourceNameFull, "scope.or.1.and.0.search_type", "EQ"),
					resource.TestCheckResourceAttr(notificationForwardingConfigAgentAuditLogsResourceNameFull, "scope.or.1.and.0.search_value", "SEV_040_HIGH"),
					resource.TestCheckNoResourceAttr(notificationForwardingConfigAgentAuditLogsResourceNameFull, "scope.and"),
					resource.TestCheckResourceAttr(notificationForwardingConfigAgentAuditLogsResourceNameFull, "email_config.distribution_list.#", "1"),
					resource.TestCheckResourceAttr(notificationForwardingConfigAgentAuditLogsResourceNameFull, "email_config.distribution_list.0", "test@email.com"),
					resource.TestCheckResourceAttr(notificationForwardingConfigAgentAuditLogsResourceNameFull, "email_config.grouping_timeframe", "123"),
					resource.TestCheckResourceAttr(notificationForwardingConfigAgentAuditLogsResourceNameFull, "email_config.subject", "test subject agent audit logs"),
					resource.TestCheckResourceAttr(notificationForwardingConfigAgentAuditLogsResourceNameFull, "syslog_config.server_id", strconv.Itoa(notificationForwardingConfigAgentAuditLogsSyslogServerIDUpdated)),
				),
			},

			// Update and Read testing
			{
				PreConfig: func() {
					t.Log("Executing Update step for notification forwarding configuration agent audits logs resource lifecycle test")
				},
				Config: providerConfig + notificationForwardingConfigResourceAgentAuditLogsFullUpdated,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(notificationForwardingConfigAgentAuditLogsResourceNameFull, "name", notificationForwardingConfigAgentAuditLogsNameUpdated),
					resource.TestCheckResourceAttr(notificationForwardingConfigAgentAuditLogsResourceNameFull, "description", notificationForwardingConfigAgentAuditLogsDescriptionUpdated),
					resource.TestCheckResourceAttr(notificationForwardingConfigAgentAuditLogsResourceNameFull, "enabled", "false"),
					resource.TestCheckResourceAttr(notificationForwardingConfigAgentAuditLogsResourceNameFull, "scope.or.#", "2"),
					resource.TestCheckResourceAttr(notificationForwardingConfigAgentAuditLogsResourceNameFull, "scope.or.0.and.#", "2"),
					resource.TestCheckResourceAttr(notificationForwardingConfigAgentAuditLogsResourceNameFull, "scope.or.0.and.0.search_field", "CATEGORY"),
					resource.TestCheckResourceAttr(notificationForwardingConfigAgentAuditLogsResourceNameFull, "scope.or.0.and.0.search_type", "NEQ"),
					resource.TestCheckResourceAttr(notificationForwardingConfigAgentAuditLogsResourceNameFull, "scope.or.0.and.0.search_value", "Audit"),
					resource.TestCheckResourceAttr(notificationForwardingConfigAgentAuditLogsResourceNameFull, "scope.or.0.and.1.search_field", "TYPE"),
					resource.TestCheckResourceAttr(notificationForwardingConfigAgentAuditLogsResourceNameFull, "scope.or.0.and.1.search_type", "NEQ"),
					resource.TestCheckResourceAttr(notificationForwardingConfigAgentAuditLogsResourceNameFull, "scope.or.0.and.1.search_value", "Action"),
					resource.TestCheckResourceAttr(notificationForwardingConfigAgentAuditLogsResourceNameFull, "scope.or.1.and.0.search_field", "SEVERITY"),
					resource.TestCheckResourceAttr(notificationForwardingConfigAgentAuditLogsResourceNameFull, "scope.or.1.and.0.search_type", "NEQ"),
					resource.TestCheckResourceAttr(notificationForwardingConfigAgentAuditLogsResourceNameFull, "scope.or.1.and.0.search_value", "SEV_040_HIGH"),
					resource.TestCheckNoResourceAttr(notificationForwardingConfigAgentAuditLogsResourceNameFull, "scope.and"),
					resource.TestCheckResourceAttr(notificationForwardingConfigAgentAuditLogsResourceNameFull, "email_config.distribution_list.#", "2"),
					resource.TestCheckResourceAttr(notificationForwardingConfigAgentAuditLogsResourceNameFull, "email_config.distribution_list.0", "test11@email.com"),
					resource.TestCheckResourceAttr(notificationForwardingConfigAgentAuditLogsResourceNameFull, "email_config.distribution_list.1", "test22@email.com"),
					resource.TestCheckResourceAttr(notificationForwardingConfigAgentAuditLogsResourceNameFull, "email_config.grouping_timeframe", "321"),
					resource.TestCheckResourceAttr(notificationForwardingConfigAgentAuditLogsResourceNameFull, "email_config.subject", "test subject agent audit logs updated"),
					resource.TestCheckResourceAttr(notificationForwardingConfigAgentAuditLogsResourceNameFull, "syslog_config.server_id", "2"),
				),
			},
		},
		CheckDestroy: testAccCheckNotificationForwardingConfigDestroyAgentAuditLogs,
	})
}

func TestAccNotificationForwardingConfigMgmtAuditLogsResourceLifecycle(t *testing.T) {
	providerConfig := getProviderConfig(t, dotEnvPath, true)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				PreConfig: func() {
					t.Log("Executing Create step for notification forwarding configuration management audits logs resource lifecycle test")
				},
				Config: providerConfig + notificationForwardingConfigResourceMgmtAuditLogsFull,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(notificationForwardingConfigMgmtAuditLogsResourceNameFull, "name", notificationForwardingConfigMgmtAuditLogsName),
					resource.TestCheckResourceAttr(notificationForwardingConfigMgmtAuditLogsResourceNameFull, "description", notificationForwardingConfigMgmtAuditLogsDescription),
					resource.TestCheckResourceAttr(notificationForwardingConfigMgmtAuditLogsResourceNameFull, "enabled", "true"),
					resource.TestCheckResourceAttr(notificationForwardingConfigMgmtAuditLogsResourceNameFull, "scope.or.#", "2"),
					resource.TestCheckResourceAttr(notificationForwardingConfigMgmtAuditLogsResourceNameFull, "scope.or.0.and.#", "2"),
					resource.TestCheckResourceAttr(notificationForwardingConfigMgmtAuditLogsResourceNameFull, "scope.or.0.and.0.search_field", "CATEGORY"),
					resource.TestCheckResourceAttr(notificationForwardingConfigMgmtAuditLogsResourceNameFull, "scope.or.0.and.0.search_type", "EQ"),
					resource.TestCheckResourceAttr(notificationForwardingConfigMgmtAuditLogsResourceNameFull, "scope.or.0.and.0.search_value", "Audit"),
					resource.TestCheckResourceAttr(notificationForwardingConfigMgmtAuditLogsResourceNameFull, "scope.or.0.and.1.search_field", "TYPE"),
					resource.TestCheckResourceAttr(notificationForwardingConfigMgmtAuditLogsResourceNameFull, "scope.or.0.and.1.search_type", "EQ"),
					resource.TestCheckResourceAttr(notificationForwardingConfigMgmtAuditLogsResourceNameFull, "scope.or.0.and.1.search_value", "Action"),
					resource.TestCheckResourceAttr(notificationForwardingConfigMgmtAuditLogsResourceNameFull, "scope.or.1.and.0.search_field", "SEVERITY"),
					resource.TestCheckResourceAttr(notificationForwardingConfigMgmtAuditLogsResourceNameFull, "scope.or.1.and.0.search_type", "EQ"),
					resource.TestCheckResourceAttr(notificationForwardingConfigMgmtAuditLogsResourceNameFull, "scope.or.1.and.0.search_value", "SEV_040_HIGH"),
					resource.TestCheckNoResourceAttr(notificationForwardingConfigMgmtAuditLogsResourceNameFull, "scope.and"),
					resource.TestCheckResourceAttr(notificationForwardingConfigMgmtAuditLogsResourceNameFull, "email_config.distribution_list.#", "1"),
					resource.TestCheckResourceAttr(notificationForwardingConfigMgmtAuditLogsResourceNameFull, "email_config.distribution_list.0", "test@email.com"),
					resource.TestCheckResourceAttr(notificationForwardingConfigMgmtAuditLogsResourceNameFull, "email_config.grouping_timeframe", "123"),
					resource.TestCheckResourceAttr(notificationForwardingConfigMgmtAuditLogsResourceNameFull, "email_config.subject", "test subject mgmt audit logs"),
					resource.TestCheckResourceAttr(notificationForwardingConfigMgmtAuditLogsResourceNameFull, "syslog_config.server_id", strconv.Itoa(notificationForwardingConfigMgmtAuditLogsSyslogServerID)),
				),
			},

			// Update and Read testing
			{
				PreConfig: func() {
					t.Log("Executing Update step for notification forwarding configuration management audits logs resource lifecycle test")
				},
				Config: providerConfig + notificationForwardingConfigResourceMgmtAuditLogsFullUpdated,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(notificationForwardingConfigMgmtAuditLogsResourceNameFull, "name", notificationForwardingConfigMgmtAuditLogsNameUpdated),
					resource.TestCheckResourceAttr(notificationForwardingConfigMgmtAuditLogsResourceNameFull, "description", notificationForwardingConfigMgmtAuditLogsDescriptionUpdated),
					resource.TestCheckResourceAttr(notificationForwardingConfigMgmtAuditLogsResourceNameFull, "enabled", "false"),
					resource.TestCheckResourceAttr(notificationForwardingConfigMgmtAuditLogsResourceNameFull, "scope.or.#", "2"),
					resource.TestCheckResourceAttr(notificationForwardingConfigMgmtAuditLogsResourceNameFull, "scope.or.0.and.#", "2"),
					resource.TestCheckResourceAttr(notificationForwardingConfigMgmtAuditLogsResourceNameFull, "scope.or.0.and.0.search_field", "CATEGORY"),
					resource.TestCheckResourceAttr(notificationForwardingConfigMgmtAuditLogsResourceNameFull, "scope.or.0.and.0.search_type", "NEQ"),
					resource.TestCheckResourceAttr(notificationForwardingConfigMgmtAuditLogsResourceNameFull, "scope.or.0.and.0.search_value", "Audit"),
					resource.TestCheckResourceAttr(notificationForwardingConfigMgmtAuditLogsResourceNameFull, "scope.or.0.and.1.search_field", "TYPE"),
					resource.TestCheckResourceAttr(notificationForwardingConfigMgmtAuditLogsResourceNameFull, "scope.or.0.and.1.search_type", "NEQ"),
					resource.TestCheckResourceAttr(notificationForwardingConfigMgmtAuditLogsResourceNameFull, "scope.or.0.and.1.search_value", "Action"),
					resource.TestCheckResourceAttr(notificationForwardingConfigMgmtAuditLogsResourceNameFull, "scope.or.1.and.0.search_field", "SEVERITY"),
					resource.TestCheckResourceAttr(notificationForwardingConfigMgmtAuditLogsResourceNameFull, "scope.or.1.and.0.search_type", "EQ"),
					resource.TestCheckResourceAttr(notificationForwardingConfigMgmtAuditLogsResourceNameFull, "scope.or.1.and.0.search_value", "SEV_040_HIGH"),
					resource.TestCheckNoResourceAttr(notificationForwardingConfigMgmtAuditLogsResourceNameFull, "scope.and"),
					resource.TestCheckResourceAttr(notificationForwardingConfigMgmtAuditLogsResourceNameFull, "email_config.distribution_list.#", "2"),
					resource.TestCheckResourceAttr(notificationForwardingConfigMgmtAuditLogsResourceNameFull, "email_config.distribution_list.0", "test11@email.com"),
					resource.TestCheckResourceAttr(notificationForwardingConfigMgmtAuditLogsResourceNameFull, "email_config.distribution_list.1", "test22@email.com"),
					resource.TestCheckResourceAttr(notificationForwardingConfigMgmtAuditLogsResourceNameFull, "email_config.grouping_timeframe", "321"),
					resource.TestCheckResourceAttr(notificationForwardingConfigMgmtAuditLogsResourceNameFull, "email_config.subject", "test subject mgmt audit logs updated"),
					resource.TestCheckResourceAttr(notificationForwardingConfigMgmtAuditLogsResourceNameFull, "syslog_config.server_id", "2"),
				),
			},
		},
		CheckDestroy: testAccCheckNotificationForwardingConfigDestroyMgmtAuditLogs,
	})
}

func TestAccNotificationForwardingConfigCasesResourceLifecycle(t *testing.T) {
	providerConfig := getProviderConfig(t, dotEnvPath, true)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				PreConfig: func() {
					t.Log("Executing Create step for notification forwarding configuration cases resource lifecycle test")
				},
				Config: providerConfig + notificationForwardingConfigResourceCasesFull,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(notificationForwardingConfigCasesResourceNameFull, "name", notificationForwardingConfigCasesName),
					resource.TestCheckResourceAttr(notificationForwardingConfigCasesResourceNameFull, "description", notificationForwardingConfigCasesDescription),
					resource.TestCheckResourceAttr(notificationForwardingConfigCasesResourceNameFull, "enabled", "true"),
					resource.TestCheckResourceAttr(notificationForwardingConfigCasesResourceNameFull, "scope.or.#", "2"),
					resource.TestCheckResourceAttr(notificationForwardingConfigCasesResourceNameFull, "scope.or.0.and.#", "2"),
					resource.TestCheckResourceAttr(notificationForwardingConfigCasesResourceNameFull, "scope.or.0.and.0.search_field", "STATUS_PROGRESS"),
					resource.TestCheckResourceAttr(notificationForwardingConfigCasesResourceNameFull, "scope.or.0.and.0.search_type", "NEQ"),
					resource.TestCheckResourceAttr(notificationForwardingConfigCasesResourceNameFull, "scope.or.0.and.0.search_value", "STATUS_025_RESOLVED"),
					resource.TestCheckResourceAttr(notificationForwardingConfigCasesResourceNameFull, "scope.or.0.and.1.search_field", "SEVERITY"),
					resource.TestCheckResourceAttr(notificationForwardingConfigCasesResourceNameFull, "scope.or.0.and.1.search_type", "EQ"),
					resource.TestCheckResourceAttr(notificationForwardingConfigCasesResourceNameFull, "scope.or.0.and.1.search_value", "SEV_050_CRITICAL"),
					resource.TestCheckResourceAttr(notificationForwardingConfigCasesResourceNameFull, "scope.or.1.and.0.search_field", "CASE_ID"),
					resource.TestCheckResourceAttr(notificationForwardingConfigCasesResourceNameFull, "scope.or.1.and.0.search_type", "EQ"),
					resource.TestCheckResourceAttr(notificationForwardingConfigCasesResourceNameFull, "scope.or.1.and.0.search_value", "123"),
					resource.TestCheckNoResourceAttr(notificationForwardingConfigCasesResourceNameFull, "scope.and"),
					resource.TestCheckResourceAttr(notificationForwardingConfigCasesResourceNameFull, "email_config.distribution_list.#", "1"),
					resource.TestCheckResourceAttr(notificationForwardingConfigCasesResourceNameFull, "email_config.distribution_list.0", "test@email.com"),
					resource.TestCheckResourceAttr(notificationForwardingConfigCasesResourceNameFull, "email_config.grouping_timeframe", "123"),
					resource.TestCheckResourceAttr(notificationForwardingConfigCasesResourceNameFull, "email_config.subject", "test subject cases"),
				),
			},

			// Update and Read testing
			{
				PreConfig: func() {
					t.Log("Executing Update step for notification forwarding configuration management audits logs resource lifecycle test")
				},
				Config: providerConfig + notificationForwardingConfigResourceCasesFullUpdated,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(notificationForwardingConfigCasesResourceNameFull, "name", notificationForwardingConfigCasesNameUpdated),
					resource.TestCheckResourceAttr(notificationForwardingConfigCasesResourceNameFull, "description", notificationForwardingConfigCasesDescriptionUpdated),
					resource.TestCheckResourceAttr(notificationForwardingConfigCasesResourceNameFull, "enabled", "false"),
					resource.TestCheckResourceAttr(notificationForwardingConfigCasesResourceNameFull, "scope.or.#", "2"),
					resource.TestCheckResourceAttr(notificationForwardingConfigCasesResourceNameFull, "scope.or.0.and.#", "2"),
					resource.TestCheckResourceAttr(notificationForwardingConfigCasesResourceNameFull, "scope.or.0.and.0.search_field", "STATUS_PROGRESS"),
					resource.TestCheckResourceAttr(notificationForwardingConfigCasesResourceNameFull, "scope.or.0.and.0.search_type", "EQ"),
					resource.TestCheckResourceAttr(notificationForwardingConfigCasesResourceNameFull, "scope.or.0.and.0.search_value", "STATUS_020_UNDER_INVESTIGATION"),
					resource.TestCheckResourceAttr(notificationForwardingConfigCasesResourceNameFull, "scope.or.0.and.1.search_field", "SEVERITY"),
					resource.TestCheckResourceAttr(notificationForwardingConfigCasesResourceNameFull, "scope.or.0.and.1.search_type", "EQ"),
					resource.TestCheckResourceAttr(notificationForwardingConfigCasesResourceNameFull, "scope.or.0.and.1.search_value", "SEV_030_MEDIUM"),
					resource.TestCheckResourceAttr(notificationForwardingConfigCasesResourceNameFull, "scope.or.1.and.0.search_field", "CASE_ID"),
					resource.TestCheckResourceAttr(notificationForwardingConfigCasesResourceNameFull, "scope.or.1.and.0.search_type", "EQ"),
					resource.TestCheckResourceAttr(notificationForwardingConfigCasesResourceNameFull, "scope.or.1.and.0.search_value", "321"),
					resource.TestCheckNoResourceAttr(notificationForwardingConfigCasesResourceNameFull, "scope.and"),
					resource.TestCheckResourceAttr(notificationForwardingConfigCasesResourceNameFull, "email_config.distribution_list.#", "2"),
					resource.TestCheckResourceAttr(notificationForwardingConfigCasesResourceNameFull, "email_config.distribution_list.0", "test11@email.com"),
					resource.TestCheckResourceAttr(notificationForwardingConfigCasesResourceNameFull, "email_config.distribution_list.1", "test22@email.com"),
					resource.TestCheckResourceAttr(notificationForwardingConfigCasesResourceNameFull, "email_config.grouping_timeframe", "321"),
					resource.TestCheckResourceAttr(notificationForwardingConfigCasesResourceNameFull, "email_config.subject", "test subject cases updated"),
				),
			},
		},
		CheckDestroy: testAccCheckNotificationForwardingConfigDestroyCases,
	})
}

func TestAccNotificationForwardingConfigIssuesResourceLifecycle(t *testing.T) {
	providerConfig := getProviderConfig(t, dotEnvPath, true)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				PreConfig: func() {
					t.Log("Executing Create step for notification forwarding configuration issues resource lifecycle test")
				},
				Config: providerConfig + notificationForwardingConfigResourceIssuesFull,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(notificationForwardingConfigIssuesResourceNameFull, "name", notificationForwardingConfigIssuesName),
					resource.TestCheckResourceAttr(notificationForwardingConfigIssuesResourceNameFull, "description", notificationForwardingConfigIssuesDescription),
					resource.TestCheckResourceAttr(notificationForwardingConfigIssuesResourceNameFull, "enabled", "true"),
					resource.TestCheckResourceAttr(notificationForwardingConfigIssuesResourceNameFull, "scope.or.#", "2"),
					resource.TestCheckResourceAttr(notificationForwardingConfigIssuesResourceNameFull, "scope.or.0.and.#", "2"),
					resource.TestCheckResourceAttr(notificationForwardingConfigIssuesResourceNameFull, "scope.or.0.and.0.search_field", "IS_WHITELISTED"),
					resource.TestCheckResourceAttr(notificationForwardingConfigIssuesResourceNameFull, "scope.or.0.and.0.search_type", "EQ"),
					resource.TestCheckResourceAttr(notificationForwardingConfigIssuesResourceNameFull, "scope.or.0.and.0.search_value", "false"),
					resource.TestCheckResourceAttr(notificationForwardingConfigIssuesResourceNameFull, "scope.or.0.and.1.search_field", "ALERT_NAME"),
					resource.TestCheckResourceAttr(notificationForwardingConfigIssuesResourceNameFull, "scope.or.0.and.1.search_type", "CONTAINS"),
					resource.TestCheckResourceAttr(notificationForwardingConfigIssuesResourceNameFull, "scope.or.0.and.1.search_value", "acctest"),
					resource.TestCheckResourceAttr(notificationForwardingConfigIssuesResourceNameFull, "scope.or.1.and.0.search_field", "STARRED"),
					resource.TestCheckResourceAttr(notificationForwardingConfigIssuesResourceNameFull, "scope.or.1.and.0.search_type", "EQ"),
					resource.TestCheckResourceAttr(notificationForwardingConfigIssuesResourceNameFull, "scope.or.1.and.0.search_value", "true"),
					resource.TestCheckNoResourceAttr(notificationForwardingConfigIssuesResourceNameFull, "scope.and"),
					resource.TestCheckResourceAttr(notificationForwardingConfigIssuesResourceNameFull, "email_config.distribution_list.#", "1"),
					resource.TestCheckResourceAttr(notificationForwardingConfigIssuesResourceNameFull, "email_config.distribution_list.0", "test@email.com"),
					resource.TestCheckResourceAttr(notificationForwardingConfigIssuesResourceNameFull, "email_config.grouping_timeframe", "123"),
					resource.TestCheckResourceAttr(notificationForwardingConfigIssuesResourceNameFull, "email_config.subject", "test subject issues"),
					resource.TestCheckResourceAttr(notificationForwardingConfigIssuesResourceNameFull, "syslog_config.server_id", strconv.Itoa(notificationForwardingConfigIssuesSyslogServerID)),
					resource.TestCheckResourceAttr(notificationForwardingConfigIssuesResourceNameFull, "syslog_config.format", "issue"),
				),
			},

			// Update and Read testing
			{
				PreConfig: func() {
					t.Log("Executing Update step for notification forwarding configuration issues resource lifecycle test")
				},
				Config: providerConfig + notificationForwardingConfigResourceIssuesFullUpdated,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(notificationForwardingConfigIssuesResourceNameFull, "name", notificationForwardingConfigIssuesNameUpdated),
					resource.TestCheckResourceAttr(notificationForwardingConfigIssuesResourceNameFull, "description", notificationForwardingConfigIssuesDescriptionUpdated),
					resource.TestCheckResourceAttr(notificationForwardingConfigIssuesResourceNameFull, "enabled", "false"),
					resource.TestCheckResourceAttr(notificationForwardingConfigIssuesResourceNameFull, "scope.or.#", "2"),
					resource.TestCheckResourceAttr(notificationForwardingConfigIssuesResourceNameFull, "scope.or.0.and.#", "2"),
					resource.TestCheckResourceAttr(notificationForwardingConfigIssuesResourceNameFull, "scope.or.0.and.0.search_field", "IS_WHITELISTED"),
					resource.TestCheckResourceAttr(notificationForwardingConfigIssuesResourceNameFull, "scope.or.0.and.0.search_type", "EQ"),
					resource.TestCheckResourceAttr(notificationForwardingConfigIssuesResourceNameFull, "scope.or.0.and.0.search_value", "true"),
					resource.TestCheckResourceAttr(notificationForwardingConfigIssuesResourceNameFull, "scope.or.0.and.1.search_field", "ALERT_NAME"),
					resource.TestCheckResourceAttr(notificationForwardingConfigIssuesResourceNameFull, "scope.or.0.and.1.search_type", "CONTAINS"),
					resource.TestCheckResourceAttr(notificationForwardingConfigIssuesResourceNameFull, "scope.or.0.and.1.search_value", "acctestupdated"),
					resource.TestCheckResourceAttr(notificationForwardingConfigIssuesResourceNameFull, "scope.or.1.and.0.search_field", "STARRED"),
					resource.TestCheckResourceAttr(notificationForwardingConfigIssuesResourceNameFull, "scope.or.1.and.0.search_type", "EQ"),
					resource.TestCheckResourceAttr(notificationForwardingConfigIssuesResourceNameFull, "scope.or.1.and.0.search_value", "false"),
					resource.TestCheckNoResourceAttr(notificationForwardingConfigIssuesResourceNameFull, "scope.and"),
					resource.TestCheckResourceAttr(notificationForwardingConfigIssuesResourceNameFull, "email_config.distribution_list.#", "2"),
					resource.TestCheckResourceAttr(notificationForwardingConfigIssuesResourceNameFull, "email_config.distribution_list.0", "test11@email.com"),
					resource.TestCheckResourceAttr(notificationForwardingConfigIssuesResourceNameFull, "email_config.distribution_list.1", "test22@email.com"),
					resource.TestCheckResourceAttr(notificationForwardingConfigIssuesResourceNameFull, "email_config.grouping_timeframe", "321"),
					resource.TestCheckResourceAttr(notificationForwardingConfigIssuesResourceNameFull, "email_config.subject", "test subject issues updated"),
					resource.TestCheckResourceAttr(notificationForwardingConfigIssuesResourceNameFull, "syslog_config.server_id", "2"),
					resource.TestCheckResourceAttr(notificationForwardingConfigIssuesResourceNameFull, "syslog_config.format", "standard_alert"),
				),
			},
		},
		CheckDestroy: testAccCheckNotificationForwardingConfigDestroyIssues,
	})
}

// testAccCheckNotificationForwardingConfigDestroyAgentAuditLogs verifies that
// the notification forwarding configuration for agent audit logs has been destroyed.
func testAccCheckNotificationForwardingConfigDestroyAgentAuditLogs(s *terraform.State) error {
	return testAccCheckNotificationForwardingConfigDestroy(s, "cortexcloud_notification_forwarding_config_agent_audit_logs")
}

// testAccCheckNotificationForwardingConfigDestroyMgmtAuditLogs verifies that
// the notification forwarding configuration for management audit logs has been destroyed.
func testAccCheckNotificationForwardingConfigDestroyMgmtAuditLogs(s *terraform.State) error {
	return testAccCheckNotificationForwardingConfigDestroy(s, "cortexcloud_notification_forwarding_config_mgmt_audit_logs")
}

// testAccCheckNotificationForwardingConfigDestroyCases verifies that the
// notification forwarding configuration for cases has been destroyed.
func testAccCheckNotificationForwardingConfigDestroyCases(s *terraform.State) error {
	return testAccCheckNotificationForwardingConfigDestroy(s, "cortexcloud_notification_forwarding_config_cases")
}

// testAccCheckNotificationForwardingConfigDestroyCases verifies that the
// notification forwarding configuration for issues has been destroyed.
func testAccCheckNotificationForwardingConfigDestroyIssues(s *terraform.State) error {
	return testAccCheckNotificationForwardingConfigDestroy(s, "cortexcloud_notification_forwarding_config_issues")
}

// testAccCheckNotificationForwardingConfigDestroy verifies that the
// notification forwarding configuration resource of the specified type has
// been destroyed.
func testAccCheckNotificationForwardingConfigDestroy(s *terraform.State, resourceType string) error {
	ctx := context.Background()

	platformClient, err := platform.NewClient(
		platform.WithCortexAPIURL(testAPIURL),
		platform.WithCortexAPIKey(testAPIKey),
		platform.WithCortexAPIKeyID(testAPIKeyID),
		platform.WithCortexAPIKeyType("standard"),
		platform.WithLogger(log.TflogAdapter{}),
		platform.WithLogLevel("debug"),
	)

	if err != nil {
		return fmt.Errorf("error creating SDK client for destruction check: %s", err.Error())
	}

	for _, rs := range s.RootModule().Resources {
		if rs.Type != resourceType {
			continue
		}

		_, err := platformClient.GetNotificationForwardingConfiguration(ctx, rs.Primary.ID)
		if err == nil {
			return fmt.Errorf("Notification forwarding configuration \"%s\" still exists", rs.Primary.ID)
		} else {
			return nil
		}
	}

	return fmt.Errorf("no resources of type \"%s\" found", resourceType)
}

func testAccCheckSyslogIntegration(t *testing.T) error {
	syslogIntegrationExists, err := checkTestSyslogIntegration(t)
	if err != nil {
		return err
	}

	if !syslogIntegrationExists {
		_, err := createTestSyslogIntegration(t)
		return err
	}

	return nil
}

func checkTestSyslogIntegration(t *testing.T) (bool, error) {
	ctx := context.Background()

	t.Log("checking for test syslog integration")

	platformClient, err := platform.NewClient(
		platform.WithCortexAPIURL(testAPIURL),
		platform.WithCortexAPIKey(testAPIKey),
		platform.WithCortexAPIKeyID(testAPIKeyID),
		platform.WithCortexAPIKeyType("standard"),
		platform.WithLogger(log.TflogAdapter{}),
		platform.WithLogLevel("debug"),
	)
	if err != nil {
		return false, fmt.Errorf("error instantiating SDK client for checking syslog integrations: %s", err.Error())
	}

	resp, err := platformClient.ListSyslogIntegrations(ctx, platformTypes.ListSyslogIntegrationsRequest{
		Filters: []platformTypes.ListSyslogIntegrationsFilter{
			&platformTypes.ListSyslogIntegrationsFilterInteger{
				Field:    "id",
				Operator: "gte",
				Value:    0,
			},
		},
	})
	if err != nil {
		return false, fmt.Errorf("error checking syslog integrations: %s", err.Error())
	}

	return (resp.Count > 0), nil
}

func createTestSyslogIntegration(t *testing.T) (id int, err error) {
	ctx := context.Background()

	t.Log("creating test syslog integration")

	platformClient, err := platform.NewClient(
		platform.WithCortexAPIURL(testAPIURL),
		platform.WithCortexAPIKey(testAPIKey),
		platform.WithCortexAPIKeyID(testAPIKeyID),
		platform.WithCortexAPIKeyType("standard"),
		platform.WithLogger(log.TflogAdapter{}),
		platform.WithLogLevel("debug"),
	)

	if err != nil {
		return 0, fmt.Errorf("error instantiating SDK client for creating syslog integration: %s", err.Error())
	}

	req := platformTypes.CreateSyslogIntegrationRequest{
		Name:     "Acctest Syslog Integration",
		Address:  "syslog.com",
		Port:     443,
		Protocol: "TCP",
		Facility: "FAC_USER",
	}

	resp, err := platformClient.CreateSyslogIntegration(ctx, req)
	if err != nil {
		return 0, fmt.Errorf("error creating syslog integration: %s", err.Error())
	}

	return resp.IntegrationID, nil
}
