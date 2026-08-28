// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package types

import (
	filterTypes "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/types/filter"
)

// NotificationForwardingConfiguration represents a notification forwarding configuration.
type NotificationForwardingConfiguration struct {
	ID            string                 `json:"rule_uuid"`
	Name          string                 `json:"name,omitempty"`
	Description   string                 `json:"description,omitempty"`
	CreatedAt     int                    `json:"created_at,omitempty"`
	ModifiedAt    int                    `json:"modified_at,omitempty"`
	CreatedBy     string                 `json:"created_by,omitempty"`
	Applications  []string               `json:"applications,omitempty"`
	ForwardType   string                 `json:"forward_type,omitempty"`
	ForwardSource *ForwardSource         `json:"forward_source,omitempty"`
	Enabled       bool                   `json:"enabled"`
	Filter        filterTypes.FilterRoot `json:"filter"`
	TimeZone      string                 `json:"time_zone,omitempty"`
	MailFormat    string                 `json:"mail_format,omitempty"`
	SyslogFormat  string                 `json:"syslog_format,omitempty"`
	SlackFormat   string                 `json:"slack_format,omitempty"`
}

// ForwardSource specifies the destination for notifications.
type ForwardSource struct {
	Email  *EmailForwardSource  `json:"email,omitempty"`
	Syslog *SyslogForwardSource `json:"syslog,omitempty"`
}

// EmailForwardSource contains settings for email notifications.
type EmailForwardSource struct {
	DistributionList  []string `json:"distribution_list"`
	Aggregation       int      `json:"aggregation"`
	CustomMailSubject string   `json:"custom_mail_subject,omitempty"`
}

// SyslogForwardSource contains settings for syslog notifications.
type SyslogForwardSource struct {
	ID int `json:"id"`
}

// NotificationForwardingConfigurationAPI represents a notification forwarding configuration as represented in the API response body.
type NotificationForwardingConfigurationAPI struct {
	RuleUUID    string `json:"rule_uuid,omitempty"`
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
	Filter      struct {
		Filter filterTypes.FilterRoot `json:"filter"`
	} `json:"filter"`
	Applications  []string      `json:"applications,omitempty"`
	ForwardSource ForwardSource `json:"forward_source"`
	ForwardType   string        `json:"forward_type,omitempty"`
	UseUTC        bool          `json:"useUTC,omitempty"`
	MailFormat    string        `json:"mail_format,omitempty"`
	SyslogFormat  string        `json:"syslog_format,omitempty"`
	SlackFormat   string        `json:"slack_format,omitempty"`
	TimeZone      string        `json:"time_zone"`
	CreatedBy     string        `json:"created_by,omitempty"`
	CreatedAt     int           `json:"created_at,omitempty"`
	ModifiedAt    int           `json:"modified_at,omitempty"`
	Enabled       bool          `json:"enabled"`
}

// ToSDK creates and returns a NotificationForwardingConfiguration using the values from the NotificationForwardingConfigurationAPI struct's fields.
func (c NotificationForwardingConfigurationAPI) ToSDK() NotificationForwardingConfiguration {
	return NotificationForwardingConfiguration{
		ID:            c.RuleUUID,
		Name:          c.Name,
		Description:   c.Description,
		CreatedAt:     c.CreatedAt,
		ModifiedAt:    c.ModifiedAt,
		CreatedBy:     c.CreatedBy,
		Applications:  c.Applications,
		ForwardType:   c.ForwardType,
		ForwardSource: &c.ForwardSource,
		Enabled:       c.Enabled,
		Filter:        c.Filter.Filter,
		TimeZone:      c.TimeZone,
		MailFormat:    c.MailFormat,
		SyslogFormat:  c.SyslogFormat,
		SlackFormat:   c.SlackFormat,
	}
}

// CreateOrUpdateNotificationForwardingConfigurationRequest is the request for creating or updating a notification forwarding configuration.
type CreateOrUpdateNotificationForwardingConfigurationRequest struct {
	Name        string `json:"name,omitempty"`
	Description string `json:"description"`
	Filter      struct {
		Filter filterTypes.FilterRoot `json:"filter"`
	} `json:"filter"`
	Applications  []string      `json:"applications,omitempty"`
	ForwardSource ForwardSource `json:"forward_source"`
	ForwardType   string        `json:"forward_type,omitempty"`
	UseUTC        bool          `json:"useUTC,omitempty"`
	MailFormat    string        `json:"mail_format,omitempty"`
	SyslogFormat  string        `json:"syslog_format,omitempty"`
	SlackFormat   string        `json:"slack_format,omitempty"`
}

// CreateOrUpdateNotificationForwardingConfigurationResponse is the successful response for creating or updating a notification forwarding configuration.
type CreateOrUpdateNotificationForwardingConfigurationResponse struct {
	Data NotificationForwardingConfigurationAPI `json:"data"`
}

// ToggleNotificationForwardingConfigurationRequest is the request to enable or disable a notification forwarding configuration.
type ToggleNotificationForwardingConfigurationRequest struct {
	Status string `json:"status"`
}

// ListNotificationForwardingConfigurationsResponse is the successful response for listing notification forwarding configurations.
type ListNotificationForwardingConfigurationsResponse struct {
	Data     []NotificationForwardingConfigurationAPI `json:"data"`
	Metadata struct {
		TotalCount int `json:"total_count"`
	} `json:"metadata"`
}
