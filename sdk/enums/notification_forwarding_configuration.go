// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package enums

// ==============================================================================
// NotificationForwardingConfigurationTypeEnums
// ==============================================================================

// NotificationForwardingConfigurationType represents the type of a notification forwarding configuration.
type NotificationForwardingConfigurationType string

const (
	NotificationForwardingConfigurationTypeAgentAuditLogs      NotificationForwardingConfigurationType = "agent_audit"
	NotificationForwardingConfigurationTypeIssues              NotificationForwardingConfigurationType = "alert"
	NotificationForwardingConfigurationTypeCases               NotificationForwardingConfigurationType = "case"
	NotificationForwardingConfigurationTypeManagementAuditLogs NotificationForwardingConfigurationType = "audit"
)

// allNotificationForwardingConfigurationTypes holds all valid NotificationForwardingConfigurationType values.
var allNotificationForwardingConfigurationTypes = []NotificationForwardingConfigurationType{
	NotificationForwardingConfigurationTypeAgentAuditLogs,
	NotificationForwardingConfigurationTypeIssues,
	NotificationForwardingConfigurationTypeCases,
	NotificationForwardingConfigurationTypeManagementAuditLogs,
}

// String returns the string representation of a NotificationForwardingConfigurationType.
func (s NotificationForwardingConfigurationType) String() string {
	return string(s)
}

// AllNotificationForwardingConfigurationTypes returns a slice of all valid NotificationForwardingConfigurationType string values.
func AllNotificationForwardingConfigurationTypes() []string {
	result := make([]string, len(allNotificationForwardingConfigurationTypes))
	for i, s := range allNotificationForwardingConfigurationTypes {
		result[i] = string(s)
	}
	return result
}

// ContainsNotificationForwardingConfigurationType checks if the given string is a valid NotificationForwardingConfigurationType.
func ContainsNotificationForwardingConfigurationType(s string) bool {
	for _, item := range allNotificationForwardingConfigurationTypes {
		if string(item) == s {
			return true
		}
	}
	return false
}

// ==============================================================================
// NotificationForwardSourceEnums
// ==============================================================================

// NotificationForwardSource represents the forward source for a notification.
type NotificationForwardSource string

const (
	NotificationForwardSourceEmail   NotificationForwardSource = "EMAIL"
	NotificationForwardSourceSlack   NotificationForwardSource = "SLACK"
	NotificationForwardSourceSyslog  NotificationForwardSource = "SYSLOG"
	NotificationForwardSourceWebhook NotificationForwardSource = "WEBHOOK"
	NotificationForwardSourceSplunk  NotificationForwardSource = "SPLUNK"
	NotificationForwardSourceAWSSQS  NotificationForwardSource = "AWS_SQS"
	NotificationForwardSourceAWSS3   NotificationForwardSource = "AWS_S3"
)

// allNotificationForwardSources holds all valid NotificationForwardSource values.
var allNotificationForwardSources = []NotificationForwardSource{
	NotificationForwardSourceEmail,
	NotificationForwardSourceSlack,
	NotificationForwardSourceSyslog,
	NotificationForwardSourceWebhook,
	NotificationForwardSourceSplunk,
	NotificationForwardSourceAWSSQS,
	NotificationForwardSourceAWSS3,
}

// String returns the string representation of a NotificationForwardSource.
func (s NotificationForwardSource) String() string {
	return string(s)
}

// AllNotificationForwardSources returns a slice of all valid NotificationForwardSource string values.
func AllNotificationForwardSources() []string {
	result := make([]string, len(allNotificationForwardSources))
	for i, s := range allNotificationForwardSources {
		result[i] = string(s)
	}
	return result
}

// ContainsNotificationForwardSource checks if the given string is a valid NotificationForwardSource.
func ContainsNotificationForwardSource(s string) bool {
	for _, item := range allNotificationForwardSources {
		if string(item) == s {
			return true
		}
	}
	return false
}

// ==============================================================================
// NotificationForwardingConfigurationStatusEnums
// ==============================================================================

// NotificationForwardingConfigurationStatus represents the status of a notification forwarding configuration.
type NotificationForwardingConfigurationStatus string

const (
	NotificationForwardingConfigurationStatusEnabled  NotificationForwardingConfigurationStatus = "ENABLED"
	NotificationForwardingConfigurationStatusDisabled NotificationForwardingConfigurationStatus = "DISABLED"
)

// allNotificationForwardingConfigurationStatuses holds all valid NotificationForwardingConfigurationStatus values.
var allNotificationForwardingConfigurationStatuses = []NotificationForwardingConfigurationStatus{
	NotificationForwardingConfigurationStatusEnabled,
	NotificationForwardingConfigurationStatusDisabled,
}

// String returns the string representation of a NotificationForwardingConfigurationStatus.
func (s NotificationForwardingConfigurationStatus) String() string {
	return string(s)
}

// AllNotificationForwardingConfigurationStatuses returns a slice of all valid NotificationForwardingConfigurationStatus string values.
func AllNotificationForwardingConfigurationStatuses() []string {
	result := make([]string, len(allNotificationForwardingConfigurationStatuses))
	for i, s := range allNotificationForwardingConfigurationStatuses {
		result[i] = string(s)
	}
	return result
}

// ContainsNotificationForwardingConfigurationStatus checks if the given string is a valid NotificationForwardingConfigurationStatus.
func ContainsNotificationForwardingConfigurationStatus(s string) bool {
	for _, item := range allNotificationForwardingConfigurationStatuses {
		if string(item) == s {
			return true
		}
	}
	return false
}

// ==============================================================================
// NotificationFormatEnums
// ==============================================================================

// NotificationFormat represents the format of a notification.
type NotificationFormat string

const (
	NotificationFormatIssue         NotificationFormat = "issue"
	NotificationFormatStandardAlert NotificationFormat = "standard_alert"
	NotificationFormatLegacyAlert   NotificationFormat = "legacy_alert"
)

// allNotificationFormats holds all valid NotificationFormat values.
var allNotificationFormats = []NotificationFormat{
	NotificationFormatIssue,
	NotificationFormatStandardAlert,
	NotificationFormatLegacyAlert,
}

// String returns the string representation of a NotificationFormat.
func (s NotificationFormat) String() string {
	return string(s)
}

// AllNotificationFormats returns a slice of all valid NotificationFormat string values.
func AllNotificationFormats() []string {
	result := make([]string, len(allNotificationFormats))
	for i, s := range allNotificationFormats {
		result[i] = string(s)
	}
	return result
}

// ContainsNotificationFormat checks if the given string is a valid NotificationFormat.
func ContainsNotificationFormat(s string) bool {
	for _, item := range allNotificationFormats {
		if string(item) == s {
			return true
		}
	}
	return false
}
