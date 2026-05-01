// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package platform_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/PaloAltoNetworks/cortex-cloud-go/enums"
	sdk "github.com/PaloAltoNetworks/cortex-cloud-go/platform"

	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/provider"
	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/tests"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

const (
	testNotificationConfig1ID                    = "00000000-0000-0000-0000-000000000001"
	testNotificationConfig1Name                  = "test-notification-forwarding-config-1"
	testNotificationConfig1Description           = "Test Notification Forwarding Configuration 1"
	testNotificationConfig1Enabled               = "true"
	testNotificationConfig1Filter1Field          = "CATEGORY"
	testNotificationConfig1Filter1Type           = "EQ"
	testNotificationConfig1Filter1Value          = "Audit"
	testNotificationConfig1Filter2Field          = "TYPE"
	testNotificationConfig1Filter2Type           = "EQ"
	testNotificationConfig1Filter2Value          = "Action"
	testNotificationConfig1Filter3Field          = "SEVERITY"
	testNotificationConfig1Filter3Type           = "EQ"
	testNotificationConfig1Filter3Value          = "SEV_010_INFO"
	testNotificationConfig1Email1                = "1@test.com"
	testNotificationConfig1Email2                = "2@test.com"
	testNotificationConfig1Email3                = "3@test.com"
	testNotificationConfig1EmailAggregation      = 400
	testNotificationConfig1EmailSubject          = "Test Subject 1"
	testNotificationConfig1SyslogServerID        = 999
	testNotificationConfig1CreatedBy             = "Public API - 0"
	testNotificationConfig1CreatedAt             = 1000000000000
	testNotificationConfig1ModifiedAt            = 1000000000000
	testNotificationConfig1UpdatedName           = "test-notification-forwarding-config-1-updated"
	testNotificationConfig1UpdatedDescription    = "Test Notification Forwarding Configuration 1 Updated"
	testNotificationConfig1UpdatedEnabled        = "false"
	testNotificationConfig1UpdatedFilter1Field   = "CATEGORY"
	testNotificationConfig1UpdatedFilter1Type    = "EQ"
	testNotificationConfig1UpdatedFilter1Value   = "Audit"
	testNotificationConfig1UpdatedFilter2Field   = "TYPE"
	testNotificationConfig1UpdatedFilter2Type    = "EQ"
	testNotificationConfig1UpdatedFilter2Value   = "Action"
	testNotificationConfig1UpdatedFilter3Field   = "SEVERITY"
	testNotificationConfig1UpdatedFilter3Type    = "EQ"
	testNotificationConfig1UpdatedFilter3Value   = "SEV_010_INFO"
	testNotificationConfig1UpdatedSyslogServerID = 999
	testNotificationConfig1UpdatedModifiedAt     = 2000000000000

	testNotificationConfig2ID                = "00000000-0000-0000-0000-000000000002"
	testNotificationConfig2Name              = "test-notification-forwarding-config-1"
	testNotificationConfig2Description       = "Test Notification Forwarding Configuration 1"
	testNotificationConfig2Enabled           = "true"
	testNotificationConfig2Filter1Field      = "CATEGORY"
	testNotificationConfig2Filter1Type       = "EQ"
	testNotificationConfig2Filter1Value      = "Audit"
	testNotificationConfig2Filter2Field      = "TYPE"
	testNotificationConfig2Filter2Type       = "EQ"
	testNotificationConfig2Filter2Value      = "Action"
	testNotificationConfig2Filter3Field      = "SEVERITY"
	testNotificationConfig2Filter3Type       = "EQ"
	testNotificationConfig2Filter3Value      = "SEV_020_MEDIUM"
	testNotificationConfig2Email1            = "4@test.com"
	testNotificationConfig2Email2            = "5@test.com"
	testNotificationConfig2Email3            = "6@test.com"
	testNotificationConfig2EmailAggregation  = 600
	testNotificationConfig2EmailSubject      = "Test Subject 2"
	testNotificationConfig2SyslogServerID    = 555
	testNotificationConfig2CreatedBy         = "Public API - 00"
	testNotificationConfig2CreatedAt         = 1000000000000
	testNotificationConfig2ModifiedAt        = 1000000000000
	testNotificationConfig2UpdatedModifiedAt = 2000000000000

	testNotificationConfig3ID                = "00000000-0000-0000-0000-000000000003"
	testNotificationConfig3Name              = "test-notification-forwarding-config-3"
	testNotificationConfig3Description       = "Test Notification Forwarding Configuration 3"
	testNotificationConfig3Enabled           = "false"
	testNotificationConfig3Filter1Field      = "CATEGORY"
	testNotificationConfig3Filter1Type       = "EQ"
	testNotificationConfig3Filter1Value      = "Audit"
	testNotificationConfig3Filter2Field      = "TYPE"
	testNotificationConfig3Filter2Type       = "EQ"
	testNotificationConfig3Filter2Value      = "Action"
	testNotificationConfig3Filter3Field      = "SEVERITY"
	testNotificationConfig3Filter3Type       = "EQ"
	testNotificationConfig3Filter3Value      = "SEV_040_HIGH"
	testNotificationConfig3Email1            = "7@test.com"
	testNotificationConfig3Email2            = "8@test.com"
	testNotificationConfig3Email3            = "9@test.com"
	testNotificationConfig3EmailAggregation  = 800
	testNotificationConfig3EmailSubject      = "Test Subject 3"
	testNotificationConfig3SyslogServerID    = 888
	testNotificationConfig3CreatedBy         = "Public API - 000"
	testNotificationConfig3CreatedAt         = 1000000000000
	testNotificationConfig3ModifiedAt        = 1000000000000
	testNotificationConfig3UpdatedModifiedAt = 2000000000000

	notificationForwardingConfigTestScopeTmpl = `scope = {
    or = [
      {
        and = [
          { 
	    search_field = "%s"
            search_type = "%s"
            search_value = "%s"
          }, 
          { 
	    search_field = "%s"
            search_type = "%s"
            search_value = "%s"
          }
	]
      },
      {
        and = [
          {
            search_field = "%s"
            search_type = "%s"
            search_value = "%s"
          }
        ]
      }
    ]
  }
`
	notificationForwardingConfigTestEmailTmpl = `email_config = {
    distribution_list = ["%s"]
    grouping_timeframe = %d
    subject = "%s"
  }`

	notificationForwardingConfigTestSyslogTmpl = `syslog_config = {
    server_id = "%d"
  }`

	notificationForwardingConfigTestResourceTmpl = `
%s

resource "%s" "%s" {
  name = "%s"
  description = "%s"
  enabled = %s
  %s
  %s
  %s
}`
)

var (
	currentTime                   = time.Now().String()
	testNotificationConfig1Emails = []string{
		testNotificationConfig1Email1,
		testNotificationConfig1Email2,
		testNotificationConfig1Email3,
	}
	testNotificationConfig2Emails = []string{
		testNotificationConfig2Email1,
		testNotificationConfig2Email2,
		testNotificationConfig2Email3,
	}
	testNotificationConfig3Emails = []string{
		testNotificationConfig3Email1,
		testNotificationConfig3Email2,
		testNotificationConfig3Email3,
	}
)

func TestUnitNotificationManagementConfigAgentAuditLogsResource_Lifecycle(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		for strings.Contains(path, "//") {
			path = strings.ReplaceAll(path, "//", "/")
		}
		if strings.HasSuffix(path, "/") && path != "/" {
			path = strings.TrimSuffix(path, "/")
		}

		switch {
		// Create
		case path == "/"+sdk.NotificationForwardingConfigurationsEndpoint && r.Method == http.MethodPost:
			w.WriteHeader(http.StatusCreated)
			fmt.Fprintf(w, `
			{
			  "data": {
			    "rule_uuid": "%s",
			    "name": "%s",
			    "description": "%s",
			    "filter": {
			      "filter": {
			        "OR": [
				  {
				    "AND": [
			              {
			                "SEARCH_FIELD": "%s",
			                "SEARCH_TYPE": "%s",
			                "SEARCH_VALUE": "%s"
			              },
			              {
			                "SEARCH_FIELD": "%s",
			                "SEARCH_TYPE": "%s",
			                "SEARCH_VALUE": "%s"
			              }
				    ]
				  },
				  {
				    "AND": [
				      {
			                "SEARCH_FIELD": "%s",
			                "SEARCH_TYPE": "%s",
			                "SEARCH_VALUE": "%s"
				      }
				    ]
				  }
			        ]
			      }
			    },
			    "applications": [],
			    "forward_source": {
			      "email": {
			        "aggregation": %d,
			        "distribution_list": [ "%s" ],
			        "legacy_mail_format": false,
			        "custom_mail_subject": "%s"
			      },
			      "syslog": {
			        "id": %d
			      }
			    },
			    "forward_type": "%s",
			    "time_zone": "UTC",
			    "slack_format": null,
			    "syslog_format": null,
			    "mail_format": null,
			    "created_by": "%s",
			    "created_at": %d,
			    "modified_at": %d,
			    "enabled": %s
			  }
			}`,
				testNotificationConfig1ID,
				testNotificationConfig1Name,
				testNotificationConfig1Description,
				testNotificationConfig1Filter1Field,
				testNotificationConfig1Filter1Type,
				testNotificationConfig1Filter1Value,
				testNotificationConfig1Filter2Field,
				testNotificationConfig1Filter2Type,
				testNotificationConfig1Filter2Value,
				testNotificationConfig1Filter3Field,
				testNotificationConfig1Filter3Type,
				testNotificationConfig1Filter3Value,
				testNotificationConfig1EmailAggregation,
				strings.Join(testNotificationConfig1Emails, "\", \""),
				testNotificationConfig1EmailSubject,
				testNotificationConfig1SyslogServerID,
				enums.NotificationForwardingConfigurationTypeAgentAuditLogs.String(),
				testNotificationConfig1CreatedBy,
				testNotificationConfig1CreatedAt,
				testNotificationConfig1ModifiedAt,
				testNotificationConfig1Enabled,
			)
		// Update
		case strings.HasPrefix(path, "/"+sdk.NotificationForwardingConfigurationsEndpoint+"/") && r.Method == http.MethodPut:
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, `
			{
			  "data": {
			    "rule_uuid": "%s",
			    "name": "%s",
			    "description": "%s",
			    "filter": {
			      "filter": {}
			    },
			    "applications": [],
			    "forward_source": {
			      "syslog": {
			        "id": %d
			      }
			    },
			    "forward_type": "%s",
			    "time_zone": "UTC",
			    "slack_format": null,
			    "syslog_format": null,
			    "mail_format": null,
			    "created_by": "%s",
			    "created_at": %d,
			    "modified_at": %d,
			    "enabled": %s
			  }
			}`,
				testNotificationConfig1ID,
				testNotificationConfig1UpdatedName,
				testNotificationConfig1UpdatedDescription,
				testNotificationConfig1SyslogServerID,
				enums.NotificationForwardingConfigurationTypeAgentAuditLogs.String(),
				testNotificationConfig1CreatedBy,
				testNotificationConfig1CreatedAt,
				testNotificationConfig1UpdatedModifiedAt,
				testNotificationConfig1Enabled,
			)
		// Get
		case strings.HasPrefix(path, "/"+sdk.NotificationForwardingConfigurationsEndpoint+"/") && r.Method == http.MethodGet:
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, `
			{
			  "data": {
			    "rule_uuid": "%s",
			    "name": "%s",
			    "description": "%s",
			    "filter": {
			      "filter": {
			        "OR": [
				  {
				    "AND": [
			              {
			                "SEARCH_FIELD": "%s",
			                "SEARCH_TYPE": "%s",
			                "SEARCH_VALUE": "%s"
			              },
			              {
			                "SEARCH_FIELD": "%s",
			                "SEARCH_TYPE": "%s",
			                "SEARCH_VALUE": "%s"
			              }
				    ]
				  },
				  {
				    "AND": [
				      {
			                "SEARCH_FIELD": "%s",
			                "SEARCH_TYPE": "%s",
			                "SEARCH_VALUE": "%s"
				      }
				    ]
				  }
			        ]
			      }
			    },
			    "applications": [],
			    "forward_source": {
			      "email": {
			        "aggregation": %d,
			        "distribution_list": [ "%s" ],
			        "legacy_mail_format": false,
			        "custom_mail_subject": "%s"
			      },
			      "syslog": {
			        "id": %d
			      }
			    },
			    "forward_type": "%s",
			    "time_zone": "UTC",
			    "slack_format": null,
			    "syslog_format": null,
			    "mail_format": null,
			    "created_by": "%s",
			    "created_at": %d,
			    "modified_at": %d,
			    "enabled": %s
			  }
			}`,
				testNotificationConfig1ID,
				testNotificationConfig1Name,
				testNotificationConfig1Description,
				testNotificationConfig1Filter1Field,
				testNotificationConfig1Filter1Type,
				testNotificationConfig1Filter1Value,
				testNotificationConfig1Filter2Field,
				testNotificationConfig1Filter2Type,
				testNotificationConfig1Filter2Value,
				testNotificationConfig1Filter3Field,
				testNotificationConfig1Filter3Type,
				testNotificationConfig1Filter3Value,
				testNotificationConfig1EmailAggregation,
				strings.Join(testNotificationConfig1Emails, "\", \""),
				testNotificationConfig1EmailSubject,
				testNotificationConfig1SyslogServerID,
				enums.NotificationForwardingConfigurationTypeAgentAuditLogs.String(),
				testNotificationConfig1CreatedBy,
				testNotificationConfig1CreatedAt,
				testNotificationConfig1ModifiedAt,
				testNotificationConfig1Enabled,
			)
		//List
		case path == "/"+sdk.ListNotificationForwardingConfigurationsEndpoint && r.Method == http.MethodGet:
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, `
			{
			  "data": [
			    {
			      "rule_uuid": "%s",
			      "name": "%s",
			      "description": "%s",
			      "filter": {
			        "filter": {
			          "OR": [
			            {
			              "AND": [
			                {
			                  "SEARCH_FIELD": "%s",
			                  "SEARCH_TYPE": "%s",
			                  "SEARCH_VALUE": "%s"
			                },
			                {
			                  "SEARCH_FIELD": "%s",
			                  "SEARCH_TYPE": "%s",
			                  "SEARCH_VALUE": "%s"
			                }
			              ]
			            },
			            {
			              "AND": [
			                {
			                  "SEARCH_FIELD": "%s",
			                  "SEARCH_TYPE": "%s",
			                  "SEARCH_VALUE": "%s"
			                }
			              ]
			            }
			          ]
			        }
			      },
			      "applications": [],
			      "forward_source": {
			        "email": {
			          "aggregation": %d,
			          "distribution_list": [ "%s" ],
			          "legacy_mail_format": false,
			          "custom_mail_subject": "%s"
			        },
			        "syslog": {
			          "id": %d
			        }
			      },
			      "forward_type": "%s",
			      "time_zone": "UTC",
			      "slack_format": null,
			      "syslog_format": null,
			      "mail_format": null,
			      "created_by": "%s",
			      "created_at": %d,
			      "modified_at": %d,
			      "enabled": %s
			    },
			    {
			      "rule_uuid": "%s",
			      "name": "%s",
			      "description": "%s",
			      "filter": {
			        "filter": {
			          "OR": [
			            {
			              "AND": [
			                {
			                  "SEARCH_FIELD": "%s",
			                  "SEARCH_TYPE": "%s",
			                  "SEARCH_VALUE": "%s"
			                },
			                {
			                  "SEARCH_FIELD": "%s",
			                  "SEARCH_TYPE": "%s",
			                  "SEARCH_VALUE": "%s"
			                }
			              ]
			            },
			            {
			              "AND": [
			                {
			                  "SEARCH_FIELD": "%s",
			                  "SEARCH_TYPE": "%s",
			                  "SEARCH_VALUE": "%s"
			                }
			              ]
			            }
			          ]
			        }
			      },
			      "applications": [],
			      "forward_source": {
			        "email": {
			          "aggregation": %d,
			          "distribution_list": [ "%s" ],
			          "legacy_mail_format": false,
			          "custom_mail_subject": "%s"
			        },
			        "syslog": {
			          "id": %d
			        }
			      },
			      "forward_type": "%s",
			      "time_zone": "UTC",
			      "slack_format": null,
			      "syslog_format": null,
			      "mail_format": null,
			      "created_by": "%s",
			      "created_at": %d,
			      "modified_at": %d,
			      "enabled": %s
			    },
			    {
			      "rule_uuid": "%s",
			      "name": "%s",
			      "description": "%s",
			      "filter": {
			        "filter": {
			          "OR": [
			            {
			              "AND": [
			                {
			                  "SEARCH_FIELD": "%s",
			                  "SEARCH_TYPE": "%s",
			                  "SEARCH_VALUE": "%s"
			                },
			                {
			                  "SEARCH_FIELD": "%s",
			                  "SEARCH_TYPE": "%s",
			                  "SEARCH_VALUE": "%s"
			                }
			              ]
			            },
			            {
			              "AND": [
			                {
			                  "SEARCH_FIELD": "%s",
			                  "SEARCH_TYPE": "%s",
			                  "SEARCH_VALUE": "%s"
			                }
			              ]
			            }
			          ]
			        }
			      },
			      "applications": [],
			      "forward_source": {
			        "email": {
			          "aggregation": %d,
			          "distribution_list": [ "%s" ],
			          "legacy_mail_format": false,
			          "custom_mail_subject": "%s"
			        },
			        "syslog": {
			          "id": %d
			        }
			      },
			      "forward_type": "%s",
			      "time_zone": "UTC",
			      "slack_format": null,
			      "syslog_format": null,
			      "mail_format": null,
			      "created_by": "%s",
			      "created_at": %d,
			      "modified_at": %d,
			      "enabled": %s
			    },
			  ],
			  "metadata": {
			    "total_count": 3
			  }
			}`,
				testNotificationConfig1ID,
				testNotificationConfig1Name,
				testNotificationConfig1Description,
				testNotificationConfig1Filter1Field,
				testNotificationConfig1Filter1Type,
				testNotificationConfig1Filter1Value,
				testNotificationConfig1Filter2Field,
				testNotificationConfig1Filter2Type,
				testNotificationConfig1Filter2Value,
				testNotificationConfig1Filter3Field,
				testNotificationConfig1Filter3Type,
				testNotificationConfig1Filter3Value,
				testNotificationConfig1EmailAggregation,
				strings.Join(testNotificationConfig1Emails, "\", \""),
				testNotificationConfig1EmailSubject,
				testNotificationConfig1SyslogServerID,
				enums.NotificationForwardingConfigurationTypeAgentAuditLogs.String(),
				testNotificationConfig1CreatedBy,
				testNotificationConfig1CreatedAt,
				testNotificationConfig1ModifiedAt,
				testNotificationConfig1Enabled,

				testNotificationConfig2ID,
				testNotificationConfig2Name,
				testNotificationConfig2Description,
				testNotificationConfig2Filter1Field,
				testNotificationConfig2Filter1Type,
				testNotificationConfig2Filter1Value,
				testNotificationConfig2Filter2Field,
				testNotificationConfig2Filter2Type,
				testNotificationConfig2Filter2Value,
				testNotificationConfig2Filter3Field,
				testNotificationConfig2Filter3Type,
				testNotificationConfig2Filter3Value,
				testNotificationConfig2EmailAggregation,
				strings.Join(testNotificationConfig2Emails, "\", \""),
				testNotificationConfig2EmailSubject,
				testNotificationConfig2SyslogServerID,
				enums.NotificationForwardingConfigurationTypeAgentAuditLogs.String(),
				testNotificationConfig2CreatedBy,
				testNotificationConfig2CreatedAt,
				testNotificationConfig2ModifiedAt,
				testNotificationConfig2Enabled,

				testNotificationConfig3ID,
				testNotificationConfig3Name,
				testNotificationConfig3Description,
				testNotificationConfig3Filter1Field,
				testNotificationConfig3Filter1Type,
				testNotificationConfig3Filter1Value,
				testNotificationConfig3Filter2Field,
				testNotificationConfig3Filter2Type,
				testNotificationConfig3Filter2Value,
				testNotificationConfig3Filter3Field,
				testNotificationConfig3Filter3Type,
				testNotificationConfig3Filter3Value,
				testNotificationConfig3EmailAggregation,
				strings.Join(testNotificationConfig3Emails, "\", \""),
				testNotificationConfig3EmailSubject,
				testNotificationConfig3SyslogServerID,
				enums.NotificationForwardingConfigurationTypeAgentAuditLogs.String(),
				testNotificationConfig3CreatedBy,
				testNotificationConfig3CreatedAt,
				testNotificationConfig3ModifiedAt,
				testNotificationConfig3Enabled,
			)
		// Enable/Disable
		case strings.HasPrefix(path, "/"+sdk.ToggleNotificationForwardingConfigurationEndpoint+"/") && r.Method == http.MethodPatch:
		// Delete
		case strings.HasPrefix(path, "/"+sdk.NotificationForwardingConfigurationsEndpoint+"/") && r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		// List Syslog Integrations
		case path == sdk.ListSyslogIntegrationsEndpoint && r.Method == http.MethodPost:
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, `
		{
		    "objects_count": 2,
		    "objects": [
		        {
		            "SYSLOG_INTEGRATION_ID": 1,
		            "SYSLOG_INTEGRATION_NAME": "test syslog integration 1",
		            "SYSLOG_INTEGRATION_ADDRESS": "test.com",
		            "SYSLOG_INTEGRATION_PORT": 80,
		            "SYSLOG_INTEGRATION_PROTOCOL": "TCP",
		            "FACILITY": "FAC_SYSLOG",
		            "SYSLOG_INTEGRATION_STATUS": "ACTIVE",
		            "SYSLOG_INTEGRATION_ERROR": null,
		            "SYSLOG_INTEGRATION_CERTIFICATE_NAME": null
		        },
		        {
		            "SYSLOG_INTEGRATION_ID": %d,
		            "SYSLOG_INTEGRATION_NAME": "test syslog integration 2",
		            "SYSLOG_INTEGRATION_ADDRESS": "syslog.com",
		            "SYSLOG_INTEGRATION_PORT": 443,
		            "SYSLOG_INTEGRATION_PROTOCOL": "TCP",
		            "FACILITY": "FAC_USER",
		            "SYSLOG_INTEGRATION_STATUS": "ACTIVE",
		            "SYSLOG_INTEGRATION_ERROR": null,
		            "SYSLOG_INTEGRATION_CERTIFICATE_NAME": null
		        }
		    ]
		}`,
				testNotificationConfig1SyslogServerID,
			)
		default:
			http.Error(w, fmt.Sprintf("[%s] Endpoint not found: %s %s", t.Name(), r.Method, path), http.StatusNotFound)
		}
	}))
	defer server.Close()

	resourceType := "cortexcloud_notification_forwarding_config_agent_audit_logs"
	resourceName := "test-audit-logs"
	resourceNameFull := fmt.Sprintf("%s.%s", resourceType, resourceName)
	providerConfig := tests.GetProviderConfig(t, &server.URL, "../../../../.env.test", true)

	// Generate resource configurations for Create test
	createTestScope := fmt.Sprintf(
		notificationForwardingConfigTestScopeTmpl,
		testNotificationConfig1Filter1Field,
		testNotificationConfig1Filter1Type,
		testNotificationConfig1Filter1Value,
		testNotificationConfig1Filter2Field,
		testNotificationConfig1Filter2Type,
		testNotificationConfig1Filter2Value,
		testNotificationConfig1Filter3Field,
		testNotificationConfig1Filter3Type,
		testNotificationConfig1Filter3Value,
	)
	createTestEmailConfig := fmt.Sprintf(
		notificationForwardingConfigTestEmailTmpl,
		strings.Join(testNotificationConfig1Emails, "\", \""),
		testNotificationConfig1EmailAggregation,
		testNotificationConfig1EmailSubject,
	)

	createTestSyslogConfig := fmt.Sprintf(
		notificationForwardingConfigTestSyslogTmpl,
		testNotificationConfig1SyslogServerID,
	)
	createTestConfig := fmt.Sprintf(
		notificationForwardingConfigTestResourceTmpl,
		providerConfig,
		resourceType,
		resourceName,
		testNotificationConfig1Name,
		testNotificationConfig1Description,
		testNotificationConfig1Enabled,
		createTestScope,
		createTestEmailConfig,
		createTestSyslogConfig,
	)

	// Generate resource configurations for Update test
	updateTestSyslogConfig := fmt.Sprintf(
		notificationForwardingConfigTestSyslogTmpl,
		testNotificationConfig1UpdatedSyslogServerID,
	)
	updateTestConfig := fmt.Sprintf(
		notificationForwardingConfigTestResourceTmpl,
		providerConfig,
		resourceType,
		resourceName,
		testNotificationConfig1UpdatedName,
		testNotificationConfig1UpdatedDescription,
		testNotificationConfig1UpdatedEnabled,
		"",
		"",
		updateTestSyslogConfig,
	)

	//t.Log(createTestConfig)
	//t.Log(updateTestConfig)

	resource.Test(t, resource.TestCase{
		IsUnitTest: true,
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"cortexcloud": providerserver.NewProtocol6WithError(provider.New("test")()),
		},
		Steps: []resource.TestStep{
			{
				Config: createTestConfig,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceNameFull, "id", testNotificationConfig1ID),
					resource.TestCheckResourceAttr(resourceNameFull, "name", testNotificationConfig1Name),
					resource.TestCheckResourceAttr(resourceNameFull, "description", testNotificationConfig1Description),
					resource.TestCheckResourceAttr(resourceNameFull, "enabled", testNotificationConfig1Enabled),
					resource.TestCheckResourceAttr(resourceNameFull, "scope.or.#", "2"),
					resource.TestCheckResourceAttr(resourceNameFull, "scope.or.0.and.#", "2"),
					resource.TestCheckResourceAttr(resourceNameFull, "scope.or.0.and.0.search_field", testNotificationConfig1Filter1Field),
					resource.TestCheckResourceAttr(resourceNameFull, "scope.or.0.and.0.search_type", testNotificationConfig1Filter1Type),
					resource.TestCheckResourceAttr(resourceNameFull, "scope.or.0.and.0.search_value", testNotificationConfig1Filter1Value),
					resource.TestCheckResourceAttr(resourceNameFull, "scope.or.0.and.1.search_field", testNotificationConfig1Filter2Field),
					resource.TestCheckResourceAttr(resourceNameFull, "scope.or.0.and.1.search_type", testNotificationConfig1Filter2Type),
					resource.TestCheckResourceAttr(resourceNameFull, "scope.or.0.and.1.search_value", testNotificationConfig1Filter2Value),
					resource.TestCheckResourceAttr(resourceNameFull, "scope.or.1.and.#", "1"),
					resource.TestCheckResourceAttr(resourceNameFull, "scope.or.1.and.0.search_field", testNotificationConfig1Filter3Field),
					resource.TestCheckResourceAttr(resourceNameFull, "scope.or.1.and.0.search_type", testNotificationConfig1Filter3Type),
					resource.TestCheckResourceAttr(resourceNameFull, "scope.or.1.and.0.search_value", testNotificationConfig1Filter3Value),
					resource.TestCheckResourceAttr(resourceNameFull, "email_config.distribution_list.0", testNotificationConfig1Email1),
					resource.TestCheckResourceAttr(resourceNameFull, "email_config.distribution_list.1", testNotificationConfig1Email2),
					resource.TestCheckResourceAttr(resourceNameFull, "email_config.distribution_list.2", testNotificationConfig1Email3),
					resource.TestCheckResourceAttr(resourceNameFull, "email_config.grouping_timeframe", strconv.Itoa(testNotificationConfig1EmailAggregation)),
					resource.TestCheckResourceAttr(resourceNameFull, "email_config.subject", testNotificationConfig1EmailSubject),
					resource.TestCheckResourceAttr(resourceNameFull, "syslog_config.server_id", strconv.Itoa(testNotificationConfig1SyslogServerID)),
				),
			},
			{
				Config: updateTestConfig,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceNameFull, "id", testNotificationConfig1ID),
					resource.TestCheckResourceAttr(resourceNameFull, "name", testNotificationConfig1UpdatedName),
					resource.TestCheckResourceAttr(resourceNameFull, "description", testNotificationConfig1UpdatedDescription),
					resource.TestCheckResourceAttr(resourceNameFull, "enabled", testNotificationConfig1UpdatedEnabled),
					resource.TestCheckNoResourceAttr(resourceNameFull, "scope"),
					resource.TestCheckNoResourceAttr(resourceNameFull, "email_config"),
					resource.TestCheckResourceAttr(resourceNameFull, "syslog_config.server_id", strconv.Itoa(testNotificationConfig1UpdatedSyslogServerID)),
				),
			},
		},
	})
}
