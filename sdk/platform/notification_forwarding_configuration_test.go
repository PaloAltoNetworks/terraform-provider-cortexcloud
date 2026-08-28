// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package platform

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/enums"
	filterTypes "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/types/filter"
	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/types/platform"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	config1ID                 = "00000000-0000-0000-0000-000000000001"
	config2ID                 = "00000000-0000-0000-0000-000000000002"
	config3ID                 = "00000000-0000-0000-0000-000000000003"
	config1Name               = "notification-forwarding-config-agent-audit-logs"
	config1Description        = "Unit test for Agent Audit Logs"
	config1Enabled            = "true"
	config1Email1             = "test1@email.com"
	config1Email2             = "test2@email.com"
	config1EmailAggregation   = 333
	config1EmailCustomSubject = "Unit testing for agent audit logs"
	config1SyslogServerID     = 10
	config1CreatedBy          = "Public API - 0"
	config1CreatedAt          = 1000000000000
	config1ModifiedAt         = 1000000000000

	// API response body templates
	config1ResponseTmpl = `{
  "data": {
    "rule_uuid": "%s",
    "name": "%s",
    "description": "%s",
    "filter": {
      "filter": {
        "AND": [
          {
            "SEARCH_FIELD": "CATEGORY",
            "SEARCH_TYPE": "EQ",
            "SEARCH_VALUE": "Audit"
          }
        ]
      }
    },
    "applications": [],
    "forward_source": {
      "email": {
        "aggregation": %d,
        "distribution_list": [
          "%s",
          "%s"
        ],
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
    "created_by": "Public API - 0",
    "created_at": %d,
    "modified_at": %d,
    "enabled": %s 
  }
}`
)

var (
	config1EmailDL = []string{config1Email1, config1Email2}
	config1Filter  = filterTypes.NewRootFilter(
		[]filterTypes.Filter{
			filterTypes.NewSearchFilter("CATEGORY", "EQ", "Audit"),
		},
		[]filterTypes.Filter{},
	)
	config1ForwardSource = types.ForwardSource{
		Email: &types.EmailForwardSource{
			DistributionList:  config1EmailDL,
			Aggregation:       config1EmailAggregation,
			CustomMailSubject: config1EmailCustomSubject,
		},
		Syslog: &types.SyslogForwardSource{
			ID: config1SyslogServerID,
		},
	}
	config1ForwardType = enums.NotificationForwardingConfigurationTypeAgentAuditLogs.String()
)

func TestClient_CreateNotificationForwardingConfiguration_AgentAuditLogs(t *testing.T) {
	configForwardType := enums.NotificationForwardingConfigurationTypeAgentAuditLogs.String()

	t.Run("should successfully create an agent audit logs notification forwarding configuration", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.Equal(t, http.MethodPost, r.Method)
			require.Equal(t, "/"+NotificationForwardingConfigurationsEndpoint, r.URL.Path)

			type ReqWrapper struct {
				RequestData types.CreateOrUpdateNotificationForwardingConfigurationRequest `json:"request_data"`
			}

			type FilterWrapper struct {
				Filter filterTypes.FilterRoot `json:"filter"`
			}

			var wrapper ReqWrapper
			err := json.NewDecoder(r.Body).Decode(&wrapper)
			require.NoError(t, err)
			req := wrapper.RequestData

			assert.Equal(t, config1Name, req.Name)
			assert.Equal(t, config1Description, req.Description)
			assert.Equal(t, struct {
				Filter filterTypes.FilterRoot `json:"filter"`
			}{Filter: config1Filter}, req.Filter)
			assert.Equal(t, config1ForwardSource, req.ForwardSource)
			assert.Equal(t, config1ForwardType, req.ForwardType)

			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, `
			{
			  "data": {
			    "rule_uuid": "%s",
			    "name": "%s",
			    "description": "%s",
			    "filter": {
			      "filter": {
			        "AND": [
			          {
			            "SEARCH_FIELD": "CATEGORY",
			            "SEARCH_TYPE": "EQ",
			            "SEARCH_VALUE": "Audit"
			          }
			        ]
			      }
			    },
			    "applications": [],
			    "forward_source": {
			      "email": {
			        "aggregation": %d,
			        "distribution_list": [
			          "%s",
			          "%s"
			        ],
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
			    "created_by": "Public API - 0",
			    "created_at": 1000000000000,
			    "modified_at": 1000000000000,
			    "enabled": true
			  }
			}`, config1ID, config1Name, config1Description, config1EmailAggregation, config1Email1, config1Email2, config1EmailCustomSubject, config1SyslogServerID, configForwardType)
		})
		client, server := setupTest(t, handler)
		defer server.Close()

		req := types.CreateOrUpdateNotificationForwardingConfigurationRequest{
			Name:        config1Name,
			Description: config1Description,
			Filter: struct {
				Filter filterTypes.FilterRoot `json:"filter"`
			}{
				Filter: config1Filter,
			},
			ForwardSource: config1ForwardSource,
			ForwardType:   config1ForwardType,
		}

		resp, err := client.CreateNotificationForwardingConfiguration(context.Background(), req)
		require.NoError(t, err)
		require.NotNil(t, resp)

		assert.Equal(t, config1ID, resp.ID)
		assert.Equal(t, config1Name, resp.Name)
		assert.Equal(t, config1Description, resp.Description)
		assert.Equal(t, config1Filter, resp.Filter)
		assert.Equal(t, []string{}, resp.Applications)
		assert.Equal(t, &config1ForwardSource, resp.ForwardSource)
		assert.Equal(t, configForwardType, resp.ForwardType)
		assert.Equal(t, "UTC", resp.TimeZone)
		assert.Empty(t, resp.SlackFormat)
		assert.Empty(t, resp.SyslogFormat)
		assert.Empty(t, resp.MailFormat)
		assert.Equal(t, "Public API - 0", resp.CreatedBy)
		assert.Equal(t, 1000000000000, resp.CreatedAt)
		assert.Equal(t, 1000000000000, resp.ModifiedAt)
		assert.True(t, resp.Enabled)
	})
}

func TestClient_UpdateNotificationForwardingConfiguration_AgentAuditLogs(t *testing.T) {
	const (
		configName               = "notification-forwarding-config-agent-audit-logs-updated"
		configDescription        = "Unit test for Agent Audit Logs (Updated)"
		configEmail1             = "test3@email.com"
		configEmail2             = "test4@email.com"
		configEmailAggregation   = 666
		configEmailCustomSubject = "Unit testing for agent audit logs UPDATED"
		configSyslogServerID     = 20
	)

	var (
		configEmailDL = []string{configEmail1, configEmail2}
		configFilter  = filterTypes.NewRootFilter(
			[]filterTypes.Filter{
				filterTypes.NewSearchFilter("CATEGORY", "NEQ", "Audit"),
			},
			[]filterTypes.Filter{},
		)
		configForwardSource = types.ForwardSource{
			Email: &types.EmailForwardSource{
				DistributionList:  configEmailDL,
				Aggregation:       configEmailAggregation,
				CustomMailSubject: configEmailCustomSubject,
			},
			Syslog: &types.SyslogForwardSource{
				ID: configSyslogServerID,
			},
		}
		configForwardType = enums.NotificationForwardingConfigurationTypeAgentAuditLogs.String()
	)

	t.Run("should updated notification forwarding configuration for agent audit logs successfully", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.Equal(t, http.MethodPut, r.Method)
			require.Equal(t, fmt.Sprintf("/%s/%s", NotificationForwardingConfigurationsEndpoint, config1ID), r.URL.Path)

			type ReqWrapper struct {
				RequestData types.CreateOrUpdateNotificationForwardingConfigurationRequest `json:"request_data"`
			}

			type FilterWrapper struct {
				Filter filterTypes.FilterRoot `json:"filter"`
			}

			var wrapper ReqWrapper
			err := json.NewDecoder(r.Body).Decode(&wrapper)
			require.NoError(t, err)
			req := wrapper.RequestData

			assert.Equal(t, configName, req.Name)
			assert.Equal(t, configDescription, req.Description)
			assert.Equal(t, struct {
				Filter filterTypes.FilterRoot `json:"filter"`
			}{Filter: configFilter}, req.Filter)
			assert.Equal(t, configForwardSource, req.ForwardSource)
			assert.Equal(t, configForwardType, req.ForwardType)

			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, `
			{
			  "data": {
			    "rule_uuid": "%s",
			    "name": "%s",
			    "description": "%s",
			    "filter": {
			      "filter": {
			        "AND": [
			          {
			            "SEARCH_FIELD": "CATEGORY",
			            "SEARCH_TYPE": "NEQ",
			            "SEARCH_VALUE": "Audit"
			          }
			        ]
			      }
			    },
			    "applications": [],
			    "forward_source": {
			      "email": {
			        "aggregation": %d,
			        "distribution_list": [
			          "%s",
			          "%s"
			        ],
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
			    "created_by": "Public API - 0",
			    "created_at": 1000000000000,
			    "modified_at": 2000000000000,
			    "enabled": true
			  }
			}`, config1ID, configName, configDescription, configEmailAggregation, configEmail1, configEmail2, configEmailCustomSubject, configSyslogServerID, configForwardType)
		})
		client, server := setupTest(t, handler)
		defer server.Close()

		req := types.CreateOrUpdateNotificationForwardingConfigurationRequest{
			Name:        configName,
			Description: configDescription,
			Filter: struct {
				Filter filterTypes.FilterRoot `json:"filter"`
			}{
				Filter: configFilter,
			},
			ForwardSource: configForwardSource,
			ForwardType:   configForwardType,
		}

		resp, err := client.UpdateNotificationForwardingConfiguration(context.Background(), config1ID, req)
		require.NoError(t, err)
		require.NotNil(t, resp)

		assert.Equal(t, config1ID, resp.ID)
		assert.Equal(t, configName, resp.Name)
		assert.Equal(t, configDescription, resp.Description)
		assert.Equal(t, configFilter, resp.Filter)
		assert.Equal(t, []string{}, resp.Applications)
		assert.Equal(t, &configForwardSource, resp.ForwardSource)
		assert.Equal(t, configForwardType, resp.ForwardType)
		assert.Equal(t, "UTC", resp.TimeZone)
		assert.Empty(t, resp.SlackFormat)
		assert.Empty(t, resp.SyslogFormat)
		assert.Empty(t, resp.MailFormat)
		assert.Equal(t, "Public API - 0", resp.CreatedBy)
		assert.Equal(t, 1000000000000, resp.CreatedAt)
		assert.Equal(t, 2000000000000, resp.ModifiedAt)
		assert.True(t, resp.Enabled)
	})
}

func TestClient_GetNotificationForwardingConfiguration_AgentAuditLogs(t *testing.T) {
	const (
		configName               = "notification-forwarding-config-agent-audit-logs"
		configDescription        = "Unit test for Agent Audit Logs"
		configEmail1             = "test1@email.com"
		configEmail2             = "test2@email.com"
		configEmailAggregation   = 333
		configEmailCustomSubject = "Unit testing for agent audit logs"
		configSyslogServerID     = 10
	)

	var (
		configEmailDL = []string{configEmail1, configEmail2}
		configFilter  = filterTypes.NewRootFilter(
			[]filterTypes.Filter{
				filterTypes.NewSearchFilter("CATEGORY", "EQ", "Audit"),
			},
			[]filterTypes.Filter{},
		)
		configForwardSource = types.ForwardSource{
			Email: &types.EmailForwardSource{
				DistributionList:  configEmailDL,
				Aggregation:       configEmailAggregation,
				CustomMailSubject: configEmailCustomSubject,
			},
			Syslog: &types.SyslogForwardSource{
				ID: configSyslogServerID,
			},
		}
		configForwardType = enums.NotificationForwardingConfigurationTypeAgentAuditLogs.String()
	)

	t.Run("should fetch the specified notification forwarding configuration for agent audit logs successfully", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.Equal(t, http.MethodGet, r.Method)
			require.Equal(t, fmt.Sprintf("/%s/%s", NotificationForwardingConfigurationsEndpoint, config1ID), r.URL.Path)

			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, `
			{
			  "data": {
			    "rule_uuid": "%s",
			    "name": "%s",
			    "description": "%s",
			    "filter": {
			      "filter": {
			        "AND": [
			          {
			            "SEARCH_FIELD": "CATEGORY",
			            "SEARCH_TYPE": "EQ",
			            "SEARCH_VALUE": "Audit"
			          }
			        ]
			      }
			    },
			    "applications": [],
			    "forward_source": {
			      "email": {
			        "aggregation": %d,
			        "distribution_list": [
			          "%s",
			          "%s"
			        ],
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
			    "created_by": "Public API - 0",
			    "created_at": 1000000000000,
			    "modified_at": 1000000000000,
			    "enabled": true
			  }
			}`, config1ID, configName, configDescription, configEmailAggregation, configEmail1, configEmail2, configEmailCustomSubject, configSyslogServerID, configForwardType)
		})
		client, server := setupTest(t, handler)
		defer server.Close()

		resp, err := client.GetNotificationForwardingConfiguration(context.Background(), config1ID)
		require.NoError(t, err)
		require.NotNil(t, resp)

		assert.Equal(t, config1ID, resp.ID)
		assert.Equal(t, configName, resp.Name)
		assert.Equal(t, configDescription, resp.Description)
		assert.Equal(t, configFilter, resp.Filter)
		assert.Equal(t, []string{}, resp.Applications)
		assert.Equal(t, &configForwardSource, resp.ForwardSource)
		assert.Equal(t, configForwardType, resp.ForwardType)
		assert.Equal(t, "UTC", resp.TimeZone)
		assert.Empty(t, resp.SlackFormat)
		assert.Empty(t, resp.SyslogFormat)
		assert.Empty(t, resp.MailFormat)
		assert.Equal(t, "Public API - 0", resp.CreatedBy)
		assert.Equal(t, 1000000000000, resp.CreatedAt)
		assert.Equal(t, 1000000000000, resp.ModifiedAt)
		assert.True(t, resp.Enabled)
	})
}

func TestClient_ListNotificationForwardingConfigurations(t *testing.T) {
	const (
		config1Name        = "notification-forwarding-config-agent-audit-logs"
		config2Name        = "notification-forwarding-config-agent-audit-logs"
		config3Name        = "notification-forwarding-config-agent-audit-logs"
		config1Description = "Unit test for Agent Audit Logs"
		config2Description = "Unit test for Agent Audit Logs"
		config3Description = "Unit test for Agent Audit Logs"
		config1Filter      = `"AND": [
			            {
			              "SEARCH_FIELD": "CATEGORY",
			              "SEARCH_TYPE": "EQ",
			              "SEARCH_VALUE": "Audit"
			            }
			          ]`
		config2Filter = `"AND": [
			            {
			              "SEARCH_FIELD": "CATEGORY",
			              "SEARCH_TYPE": "EQ",
			              "SEARCH_VALUE": "Audit"
			            }
			          ]`
		config3Filter = `"AND": [
			            {
			              "SEARCH_FIELD": "CATEGORY",
			              "SEARCH_TYPE": "EQ",
			              "SEARCH_VALUE": "Audit"
			            }
			          ]`
		config1Email1             = "test1@email.com"
		config1Email2             = "test2@email.com"
		config2Email1             = "test3@email.com"
		config2Email2             = "test4@email.com"
		config3Email1             = "test5@email.com"
		config3Email2             = "test6@email.com"
		config1EmailAggregation   = 111
		config2EmailAggregation   = 222
		config3EmailAggregation   = 333
		config1EmailCustomSubject = "List configs unit test 1"
		config2EmailCustomSubject = "List configs unit test 2"
		config3EmailCustomSubject = "List configs unit test 3"
		config1SyslogServerID     = 10
		config2SyslogServerID     = 20
		config3SyslogServerID     = 30
	)

	var (
		config1ForwardType  = enums.NotificationForwardingConfigurationTypeAgentAuditLogs.String()
		config2ForwardType  = enums.NotificationForwardingConfigurationTypeAgentAuditLogs.String()
		config3ForwardType  = enums.NotificationForwardingConfigurationTypeAgentAuditLogs.String()
		config1FilterStruct = filterTypes.NewRootFilter(
			[]filterTypes.Filter{
				filterTypes.NewSearchFilter("CATEGORY", "EQ", "Audit"),
			},
			[]filterTypes.Filter{},
		)
		config2FilterStruct = filterTypes.NewRootFilter(
			[]filterTypes.Filter{
				filterTypes.NewSearchFilter("CATEGORY", "EQ", "Audit"),
			},
			[]filterTypes.Filter{},
		)
		config3FilterStruct = filterTypes.NewRootFilter(
			[]filterTypes.Filter{
				filterTypes.NewSearchFilter("CATEGORY", "EQ", "Audit"),
			},
			[]filterTypes.Filter{},
		)
		config1ForwardSource = types.ForwardSource{
			Email: &types.EmailForwardSource{
				DistributionList:  []string{config1Email1, config1Email2},
				Aggregation:       config1EmailAggregation,
				CustomMailSubject: config1EmailCustomSubject,
			},
			Syslog: &types.SyslogForwardSource{
				ID: config1SyslogServerID,
			},
		}
		config2ForwardSource = types.ForwardSource{
			Email: &types.EmailForwardSource{
				DistributionList:  []string{config2Email1, config2Email2},
				Aggregation:       config2EmailAggregation,
				CustomMailSubject: config2EmailCustomSubject,
			},
			Syslog: &types.SyslogForwardSource{
				ID: config2SyslogServerID,
			},
		}
		config3ForwardSource = types.ForwardSource{
			Email: &types.EmailForwardSource{
				DistributionList:  []string{config3Email1, config3Email2},
				Aggregation:       config3EmailAggregation,
				CustomMailSubject: config3EmailCustomSubject,
			},
			Syslog: &types.SyslogForwardSource{
				ID: config3SyslogServerID,
			},
		}
	)

	t.Run("should list notification forwarding configurations successfully", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.Equal(t, http.MethodGet, r.Method)
			require.Equal(t, fmt.Sprintf("/%s", ListNotificationForwardingConfigurationsEndpoint), r.URL.Path)

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
				  %s
			        }
			      },
			      "applications": [],
			      "forward_source": {
			        "email": {
			          "aggregation": %d,
			          "distribution_list": [
			            "%s",
			            "%s"
			          ],
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
			      "created_by": "Public API - 0",
			      "created_at": 1000000000000,
			      "modified_at": 1000000000000,
			      "enabled": true
			    },
			    {
			      "rule_uuid": "%s",
			      "name": "%s",
			      "description": "%s",
			      "filter": {
			        "filter": {
				  %s
			        }
			      },
			      "applications": [],
			      "forward_source": {
			        "email": {
			          "aggregation": %d,
			          "distribution_list": [
			            "%s",
			            "%s"
			          ],
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
			      "created_by": "Public API - 0",
			      "created_at": 1000000000000,
			      "modified_at": 1000000000000,
			      "enabled": true
			    },
			    {
			      "rule_uuid": "%s",
			      "name": "%s",
			      "description": "%s",
			      "filter": {
			        "filter": {
				  %s
			        }
			      },
			      "applications": [],
			      "forward_source": {
			        "email": {
			          "aggregation": %d,
			          "distribution_list": [
			            "%s",
			            "%s"
			          ],
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
			      "created_by": "Public API - 0",
			      "created_at": 1000000000000,
			      "modified_at": 1000000000000,
			      "enabled": true
			    }
			  ],
			  "metadata": {
			    "total_count": 3
			  }
			}`,
				config1ID, config1Name, config1Description, config1Filter, config1EmailAggregation, config1Email1, config1Email2, config1EmailCustomSubject, config1SyslogServerID, config1ForwardType,
				config2ID, config2Name, config2Description, config2Filter, config2EmailAggregation, config2Email1, config2Email2, config2EmailCustomSubject, config2SyslogServerID, config2ForwardType,
				config3ID, config3Name, config3Description, config3Filter, config3EmailAggregation, config3Email1, config3Email2, config3EmailCustomSubject, config3SyslogServerID, config3ForwardType,
			)
		})
		client, server := setupTest(t, handler)
		defer server.Close()

		resp, totalCount, err := client.ListNotificationForwardingConfigurations(context.Background())
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.Equal(t, 3, totalCount)

		// config 1
		assert.Equal(t, config1ID, resp[0].ID)
		assert.Equal(t, config1Name, resp[0].Name)
		assert.Equal(t, config1Description, resp[0].Description)
		assert.Equal(t, config1FilterStruct, resp[0].Filter)
		assert.Equal(t, []string{}, resp[0].Applications)
		assert.Equal(t, &config1ForwardSource, resp[0].ForwardSource)
		assert.Equal(t, config1ForwardType, resp[0].ForwardType)
		assert.Equal(t, "UTC", resp[0].TimeZone)
		assert.Empty(t, resp[0].SlackFormat)
		assert.Empty(t, resp[0].SyslogFormat)
		assert.Empty(t, resp[0].MailFormat)
		assert.Equal(t, "Public API - 0", resp[0].CreatedBy)
		assert.Equal(t, 1000000000000, resp[0].CreatedAt)
		assert.Equal(t, 1000000000000, resp[0].ModifiedAt)
		assert.True(t, resp[0].Enabled)

		// config 2
		assert.Equal(t, config2ID, resp[1].ID)
		assert.Equal(t, config2Name, resp[1].Name)
		assert.Equal(t, config2Description, resp[1].Description)
		assert.Equal(t, config2FilterStruct, resp[1].Filter)
		assert.Equal(t, []string{}, resp[1].Applications)
		assert.Equal(t, &config2ForwardSource, resp[1].ForwardSource)
		assert.Equal(t, config2ForwardType, resp[1].ForwardType)
		assert.Equal(t, "UTC", resp[1].TimeZone)
		assert.Empty(t, resp[1].SlackFormat)
		assert.Empty(t, resp[1].SyslogFormat)
		assert.Empty(t, resp[1].MailFormat)
		assert.Equal(t, "Public API - 0", resp[1].CreatedBy)
		assert.Equal(t, 1000000000000, resp[1].CreatedAt)
		assert.Equal(t, 1000000000000, resp[1].ModifiedAt)
		assert.True(t, resp[1].Enabled)

		// config 3
		assert.Equal(t, config3ID, resp[2].ID)
		assert.Equal(t, config3Name, resp[2].Name)
		assert.Equal(t, config3Description, resp[2].Description)
		assert.Equal(t, config3FilterStruct, resp[2].Filter)
		assert.Equal(t, []string{}, resp[2].Applications)
		assert.Equal(t, &config3ForwardSource, resp[2].ForwardSource)
		assert.Equal(t, config3ForwardType, resp[2].ForwardType)
		assert.Equal(t, "UTC", resp[2].TimeZone)
		assert.Empty(t, resp[2].SlackFormat)
		assert.Empty(t, resp[2].SyslogFormat)
		assert.Empty(t, resp[2].MailFormat)
		assert.Equal(t, "Public API - 0", resp[2].CreatedBy)
		assert.Equal(t, 1000000000000, resp[2].CreatedAt)
		assert.Equal(t, 1000000000000, resp[2].ModifiedAt)
		assert.True(t, resp[2].Enabled)
	})
}

func TestClient_EnableNotificationForwardingConfiguration(t *testing.T) {
	t.Run("should enable notification forwarding configuration successfully", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.Equal(t, http.MethodPatch, r.Method)
			require.Equal(t, fmt.Sprintf("/%s/%s", ToggleNotificationForwardingConfigurationEndpoint, config1ID), r.URL.Path)

			type ReqWrapper struct {
				RequestData types.ToggleNotificationForwardingConfigurationRequest `json:"request_data"`
			}

			var wrapper ReqWrapper
			err := json.NewDecoder(r.Body).Decode(&wrapper)
			require.NoError(t, err)
			req := wrapper.RequestData

			require.Equal(t, "enable", req.Status)

			w.WriteHeader(http.StatusNoContent)
		})
		client, server := setupTest(t, handler)
		defer server.Close()

		err := client.EnableNotificationForwardingConfiguration(context.Background(), config1ID)
		require.NoError(t, err)
	})
}

func TestClient_DisableNotificationForwardingConfiguration(t *testing.T) {
	t.Run("should disable notification forwarding configuration successfully", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.Equal(t, http.MethodPatch, r.Method)
			require.Equal(t, fmt.Sprintf("/%s/%s", ToggleNotificationForwardingConfigurationEndpoint, config1ID), r.URL.Path)

			type ReqWrapper struct {
				RequestData types.ToggleNotificationForwardingConfigurationRequest `json:"request_data"`
			}

			var wrapper ReqWrapper
			err := json.NewDecoder(r.Body).Decode(&wrapper)
			require.NoError(t, err)
			req := wrapper.RequestData

			require.Equal(t, "disable", req.Status)

			w.WriteHeader(http.StatusNoContent)
		})
		client, server := setupTest(t, handler)
		defer server.Close()

		err := client.DisableNotificationForwardingConfiguration(context.Background(), config1ID)
		require.NoError(t, err)
	})
}
