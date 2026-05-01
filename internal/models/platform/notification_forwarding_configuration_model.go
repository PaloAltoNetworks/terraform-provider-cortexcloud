// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package models

import (
	"context"
	"fmt"
	"strings"

	"github.com/PaloAltoNetworks/cortex-cloud-go/enums"
	filterTypes "github.com/PaloAltoNetworks/cortex-cloud-go/types/filter"
	platformTypes "github.com/PaloAltoNetworks/cortex-cloud-go/types/platform"
	sharedModels "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/shared"

	"encoding/json"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"

	//"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	//"github.com/hashicorp/terraform-plugin-log/tflog"
)

const (
	EmailFormatIssue         = "ISSUE"
	EmailFormatAlertStandard = "ALERT_STANDARD"
	EmailFormatAlertLegacy   = "ALERT_LEGACY"
)

var (
	configTypeAgentAuditLogs      = enums.NotificationForwardingConfigurationTypeAgentAuditLogs.String()
	configTypeManagementAuditLogs = enums.NotificationForwardingConfigurationTypeManagementAuditLogs.String()
	configTypeCases               = enums.NotificationForwardingConfigurationTypeCases.String()
	configTypeIssues              = enums.NotificationForwardingConfigurationTypeIssues.String()

	EmailFormatEnums = []string{
		EmailFormatIssue,
		EmailFormatAlertStandard,
		EmailFormatAlertLegacy,
	}
)

// ----------------------------------------------------------------------------
// Interfaces
// ----------------------------------------------------------------------------

type INotificationForwardingConfigurationModel interface {
	Type() string
	ValidateConfig(ctx context.Context, diags *diag.Diagnostics, resp *resource.ValidateConfigResponse)
	Equals(ctx context.Context, diags *diag.Diagnostics, other INotificationForwardingConfigurationModel) (isEqual bool)
	RefreshFromRemote(ctx context.Context, diags *diag.Diagnostics, resp platformTypes.NotificationForwardingConfiguration)
	//ToCreateOrUpdateRequest
}

type ITfsdkConfig interface {
	Get(ctx context.Context, target any) diag.Diagnostics
	GetAttribute(ctx context.Context, path path.Path, target any) diag.Diagnostics
	PathMatches(ctx context.Context, pathExpr path.Expression) (path.Paths, diag.Diagnostics)
}

// ----------------------------------------------------------------------------
// Shared Fields
// ----------------------------------------------------------------------------

type NotificationForwardingConfigurationSharedFields struct {
	ID          types.String                  `tfsdk:"id"`
	Name        types.String                  `tfsdk:"name"`
	Description types.String                  `tfsdk:"description"`
	Enabled     types.Bool                    `tfsdk:"enabled"`
	Scope       *sharedModels.RootFilterModel `tfsdk:"scope"`
	Timezone    types.String                  `tfsdk:"timezone"`
}

func (o *NotificationForwardingConfigurationSharedFields) FromTfsdk(ctx context.Context, diags *diag.Diagnostics, plan ITfsdkConfig) {
	var (
		id          basetypes.StringValue
		name        basetypes.StringValue
		description basetypes.StringValue
		enabled     basetypes.BoolValue
		scope       *sharedModels.RootFilterModel
		timezone    basetypes.StringValue
	)

	diags.Append(plan.GetAttribute(ctx, path.Root("id"), &id)...)
	if diags.HasError() {
		return
	}
	o.ID = id

	diags.Append(plan.GetAttribute(ctx, path.Root("name"), &name)...)
	if diags.HasError() {
		return
	}
	o.Name = name

	diags.Append(plan.GetAttribute(ctx, path.Root("description"), &description)...)
	if diags.HasError() {
		return
	}
	o.Description = description

	diags.Append(plan.GetAttribute(ctx, path.Root("enabled"), &enabled)...)
	if diags.HasError() {
		return
	}
	o.Enabled = enabled

	diags.Append(plan.GetAttribute(ctx, path.Root("scope"), &scope)...)
	if diags.HasError() {
		return
	}
	o.Scope = scope

	diags.Append(plan.GetAttribute(ctx, path.Root("timezone"), &timezone)...)
	if diags.HasError() {
		return
	}
	o.Timezone = timezone
}

// Equals compares two NotificationForwardingConfigurationSharedFields structs and returns true if all of
// their fields are equal, false otherwise.
func (m *NotificationForwardingConfigurationSharedFields) Equals(other *NotificationForwardingConfigurationSharedFields) (isEqual bool, err error) {
	if m == nil && other == nil {
		return true, nil
	}
	if m == nil || other == nil {
		return false, nil
	}

	// Compare primitive-value fields, exiting early if there's any differences
	if !m.ID.Equal(other.ID) ||
		!m.Name.Equal(other.Name) ||
		!m.Description.Equal(other.Description) ||
		!m.Enabled.Equal(other.Enabled) ||
		!m.Timezone.Equal(other.Timezone) {
		return false, nil
	}

	// Compare scope field by marshalling each value into JSON and comparing the resulting strings
	if (m.Scope == nil && other.Scope != nil) || (m.Scope != nil && other.Scope == nil) {
		return false, nil
	} else if m.Scope != nil && other.Scope != nil {
		mScopeJSON, err := json.Marshal(m.Scope)
		if err != nil {
			return false, fmt.Errorf("failed to marshal caller struct scope attribute value to JSON: %s", err.Error())
		}
		otherScopeJSON, err := json.Marshal(other.Scope)
		if err != nil {
			return false, fmt.Errorf("failed to marshal argument struct scope attribute value to JSON: %s", err.Error())
		}
		if string(mScopeJSON) != string(otherScopeJSON) {
			return false, nil
		}
	}

	return true, nil
}

// ----------------------------------------------------------------------------
// Shared Types
// ----------------------------------------------------------------------------

// EmailConfigModel is the model for email notification forwarding settings.
type EmailConfigModel struct {
	DistributionList  types.List   `tfsdk:"distribution_list"`
	Subject           types.String `tfsdk:"subject"`
	GroupingTimeframe types.Int32  `tfsdk:"grouping_timeframe"`
}

// Equals compares two EmailConfigModel structs and returns true if all of
// their fields are equal, false otherwise.
func (m *EmailConfigModel) Equals(other *EmailConfigModel) (isEqual bool) {
	if m == nil && other == nil {
		return true
	}
	if m == nil || other == nil {
		return false
	}

	if !m.DistributionList.Equal(other.DistributionList) ||
		!m.Subject.Equal(other.Subject) ||
		!m.GroupingTimeframe.Equal(other.GroupingTimeframe) {
		return false
	}

	return true
}

func (m *EmailConfigModel) ToSDK(ctx context.Context, diags *diag.Diagnostics) platformTypes.EmailForwardSource {
	distributionList := make([]string, len(m.DistributionList.Elements()))
	diags.Append(m.DistributionList.ElementsAs(ctx, &distributionList, false)...)
	if diags.HasError() {
		return platformTypes.EmailForwardSource{}
	}

	return platformTypes.EmailForwardSource{
		Aggregation:       int(m.GroupingTimeframe.ValueInt32()),
		DistributionList:  distributionList,
		CustomMailSubject: m.Subject.ValueString(),
	}
}

// SyslogConfigModel is the model for syslog notification forwarding settings.
type SyslogConfigModel struct {
	ServerID types.Int64 `tfsdk:"server_id"`
}

// Equals compares two SyslogConfigModel structs and returns true if all of
// their fields are equal, false otherwise.
func (m *SyslogConfigModel) Equals(other *SyslogConfigModel) (isEqual bool) {
	if m == nil && other == nil {
		return true
	}
	if m != nil && other == nil {
		return false
	}

	if (m == nil && other != nil) ||
		(m != nil && other == nil) ||
		!m.ServerID.Equal(other.ServerID) {
		return false
	}

	return true
}

func (m *SyslogConfigModel) ToSDK(ctx context.Context, diags *diag.Diagnostics) platformTypes.SyslogForwardSource {
	return platformTypes.SyslogForwardSource{
		ID: int(m.ServerID.ValueInt64()),
	}
}

// ----------------------------------------------------------------------------
// Agent Audit Logs
// ----------------------------------------------------------------------------

// NotificationForwardingConfigurationAuditLogsModel is the model for the
// notification_forwarding_config_agent_audit_logs resource.
type NotificationForwardingConfigurationAgentAuditLogsModel struct {
	Shared       NotificationForwardingConfigurationSharedFields
	EmailConfig  *EmailConfigModel  `tfsdk:"email_config"`
	SyslogConfig *SyslogConfigModel `tfsdk:"syslog_config"`
}

func (m *NotificationForwardingConfigurationAgentAuditLogsModel) Type() string {
	return configTypeAgentAuditLogs
}

func (m *NotificationForwardingConfigurationAgentAuditLogsModel) ValidateConfig(ctx context.Context, diags *diag.Diagnostics, resp *resource.ValidateConfigResponse) {
	return
}

func (m *NotificationForwardingConfigurationAgentAuditLogsModel) FromTfsdk(ctx context.Context, diags *diag.Diagnostics, config ITfsdkConfig) {
	(&m.Shared).FromTfsdk(ctx, diags, config)
	if diags.HasError() {
		return
	}

	diags.Append(config.GetAttribute(ctx, path.Root("email_config"), &m.EmailConfig)...)
	if diags.HasError() {
		return
	}

	diags.Append(config.GetAttribute(ctx, path.Root("syslog_config"), &m.SyslogConfig)...)
	if diags.HasError() {
		return
	}
}

// ToCreateOrUpdateRequest returns a new CreateOrUpdateNotificationForwardingConfigurationRequest using the values of the NotificationForwardingConfigurationAgentAuditLogsModel's fields.
func (m *NotificationForwardingConfigurationAgentAuditLogsModel) ToCreateOrUpdateRequest(ctx context.Context, diags *diag.Diagnostics) platformTypes.CreateOrUpdateNotificationForwardingConfigurationRequest {
	// Convert scope filter
	var scope filterTypes.FilterRoot
	if m.Shared.Scope != nil {
		scope = sharedModels.RootModelToSDKFilter(ctx, m.Shared.Scope)
	}

	// Convert integration forwarding configurations
	forwardSource := platformTypes.ForwardSource{}
	if m.EmailConfig != nil {
		emailForwardSource := m.EmailConfig.ToSDK(ctx, diags)
		if diags.HasError() {
			return platformTypes.CreateOrUpdateNotificationForwardingConfigurationRequest{}
		}
		forwardSource.Email = &emailForwardSource
	}
	if m.SyslogConfig != nil {
		syslogForwardSource := m.SyslogConfig.ToSDK(ctx, diags)
		if diags.HasError() {
			return platformTypes.CreateOrUpdateNotificationForwardingConfigurationRequest{}
		}
		forwardSource.Syslog = &syslogForwardSource
	}

	return platformTypes.CreateOrUpdateNotificationForwardingConfigurationRequest{
		Name:        m.Shared.Name.ValueString(),
		Description: m.Shared.Description.ValueString(),
		ForwardType: enums.NotificationForwardingConfigurationTypeAgentAuditLogs.String(),
		Filter: struct {
			Filter filterTypes.FilterRoot `json:"filter"`
		}{
			Filter: scope,
		},
		ForwardSource: forwardSource,
	}
}

// Equals compares two NotificationForwardingConfigurationAgentAuditLogsModel
// structs and returns true if all of their fields are equal, false otherwise.
func (m *NotificationForwardingConfigurationAgentAuditLogsModel) Equals(diags *diag.Diagnostics, other *NotificationForwardingConfigurationAgentAuditLogsModel) (isEqual bool) {
	if m == nil && other == nil {
		return true
	}
	if m == nil || other == nil {
		return false
	}

	sharedFieldsEqual, err := m.Shared.Equals(&other.Shared)
	if err != nil {
		diags.AddError(
			"Error Comparing Shared Notification Forwarding Configuration Fields",
			fmt.Sprintf("Error occurred while comparing shared fields between model structs: %s"+
				"\nPlease report this issue to the provider developers.", err.Error()),
		)
		return false
	}

	if !sharedFieldsEqual ||
		!m.EmailConfig.Equals(other.EmailConfig) ||
		!m.SyslogConfig.Equals(other.SyslogConfig) {
		return false
	}

	return true
}

// RefreshFromRemote refreshes the model from the remote API response.
func (m *NotificationForwardingConfigurationAgentAuditLogsModel) RefreshFromRemote(ctx context.Context, diags *diag.Diagnostics, resp platformTypes.NotificationForwardingConfiguration) {
	scope := sharedModels.SDKToModel(ctx, resp.Filter)
	if len(scope.And) == 0 && len(scope.Or) == 0 {
		scope = nil
	}

	if resp.ForwardSource != nil {
		if resp.ForwardSource.Email != nil {
			distributionList, convertDiags := types.ListValueFrom(ctx, types.StringType, resp.ForwardSource.Email.DistributionList)
			diags.Append(convertDiags...)
			if diags.HasError() {
				return
			}

			m.EmailConfig = &EmailConfigModel{
				GroupingTimeframe: types.Int32Value(int32(resp.ForwardSource.Email.Aggregation)),
				DistributionList:  distributionList,
				Subject:           types.StringValue(resp.ForwardSource.Email.CustomMailSubject),
			}
		}

		if resp.ForwardSource.Syslog != nil {
			m.SyslogConfig = &SyslogConfigModel{
				ServerID: types.Int64Value(int64(resp.ForwardSource.Syslog.ID)),
			}
		}
	}

	m.Shared.ID = types.StringValue(resp.ID)
	m.Shared.Name = types.StringValue(resp.Name)
	m.Shared.Description = types.StringValue(resp.Description)
	m.Shared.Enabled = types.BoolValue(resp.Enabled)
	m.Shared.Scope = scope
	m.Shared.Timezone = types.StringValue(resp.TimeZone)
}

// ----------------------------------------------------------------------------
// Management Audit Logs
// ----------------------------------------------------------------------------

// NotificationForwardingConfigurationMgmtAuditLogsModel is the model for the
// notification_forwarding_config_mgmt_audit_logs resource.
type NotificationForwardingConfigurationMgmtAuditLogsModel struct {
	Shared       NotificationForwardingConfigurationSharedFields
	EmailConfig  *EmailConfigModel  `tfsdk:"email_config"`
	SyslogConfig *SyslogConfigModel `tfsdk:"syslog_config"`
}

func (m *NotificationForwardingConfigurationMgmtAuditLogsModel) Type() string {
	return configTypeManagementAuditLogs
}

func (m *NotificationForwardingConfigurationMgmtAuditLogsModel) ValidateConfig(ctx context.Context, diags *diag.Diagnostics, resp *resource.ValidateConfigResponse) {
	return
}

func (m *NotificationForwardingConfigurationMgmtAuditLogsModel) FromTfsdk(ctx context.Context, diags *diag.Diagnostics, config ITfsdkConfig) {
	(&m.Shared).FromTfsdk(ctx, diags, config)
	if diags.HasError() {
		return
	}

	diags.Append(config.GetAttribute(ctx, path.Root("email_config"), &m.EmailConfig)...)
	if diags.HasError() {
		return
	}

	diags.Append(config.GetAttribute(ctx, path.Root("syslog_config"), &m.SyslogConfig)...)
	if diags.HasError() {
		return
	}
}

// ToCreateOrUpdateRequest returns a new CreateOrUpdateNotificationForwardingConfigurationRequest using the values of the NotificationForwardingConfigurationMgmtAuditLogsModel's fields.
func (m *NotificationForwardingConfigurationMgmtAuditLogsModel) ToCreateOrUpdateRequest(ctx context.Context, diags *diag.Diagnostics) platformTypes.CreateOrUpdateNotificationForwardingConfigurationRequest {
	// Convert scope filter
	var scope filterTypes.FilterRoot
	if m.Shared.Scope != nil {
		scope = sharedModels.RootModelToSDKFilter(ctx, m.Shared.Scope)
	}

	// Convert integration forwarding configurations
	forwardSource := platformTypes.ForwardSource{}
	if m.EmailConfig != nil {
		emailForwardSource := m.EmailConfig.ToSDK(ctx, diags)
		if diags.HasError() {
			return platformTypes.CreateOrUpdateNotificationForwardingConfigurationRequest{}
		}
		forwardSource.Email = &emailForwardSource
	}
	if m.SyslogConfig != nil {
		syslogForwardSource := m.SyslogConfig.ToSDK(ctx, diags)
		if diags.HasError() {
			return platformTypes.CreateOrUpdateNotificationForwardingConfigurationRequest{}
		}
		forwardSource.Syslog = &syslogForwardSource
	}

	return platformTypes.CreateOrUpdateNotificationForwardingConfigurationRequest{
		Name:        m.Shared.Name.ValueString(),
		Description: m.Shared.Description.ValueString(),
		ForwardType: enums.NotificationForwardingConfigurationTypeManagementAuditLogs.String(),
		Filter: struct {
			Filter filterTypes.FilterRoot `json:"filter"`
		}{
			Filter: scope,
		},
		ForwardSource: forwardSource,
	}
}

// Equals compares two NotificationForwardingConfigurationMgmtAuditLogsModel
// structs and returns true if all of their fields are equal, false otherwise.
func (m *NotificationForwardingConfigurationMgmtAuditLogsModel) Equals(diags *diag.Diagnostics, other *NotificationForwardingConfigurationMgmtAuditLogsModel) (isEqual bool) {
	if m == nil && other == nil {
		return true
	}
	if m == nil || other == nil {
		return false
	}

	sharedFieldsEqual, err := m.Shared.Equals(&other.Shared)
	if err != nil {
		diags.AddError(
			"Error Comparing Shared Notification Forwarding Configuration Fields",
			fmt.Sprintf("Error occurred while comparing shared fields between model structs: %s"+
				"\nPlease report this issue to the provider developers.", err.Error()),
		)
		return false
	}

	if !sharedFieldsEqual ||
		!m.EmailConfig.Equals(other.EmailConfig) ||
		!m.SyslogConfig.Equals(other.SyslogConfig) {
		return false
	}

	return true
}

// RefreshFromRemote refreshes the model from the remote API response.
func (m *NotificationForwardingConfigurationMgmtAuditLogsModel) RefreshFromRemote(ctx context.Context, diags *diag.Diagnostics, resp platformTypes.NotificationForwardingConfiguration) {
	scope := sharedModels.SDKToModel(ctx, resp.Filter)
	if len(scope.And) == 0 && len(scope.Or) == 0 {
		scope = nil
	}

	if resp.ForwardSource != nil {
		if resp.ForwardSource.Email != nil {
			distributionList, convertDiags := types.ListValueFrom(ctx, types.StringType, resp.ForwardSource.Email.DistributionList)
			diags.Append(convertDiags...)
			if diags.HasError() {
				return
			}

			m.EmailConfig = &EmailConfigModel{
				GroupingTimeframe: types.Int32Value(int32(resp.ForwardSource.Email.Aggregation)),
				DistributionList:  distributionList,
				Subject:           types.StringValue(resp.ForwardSource.Email.CustomMailSubject),
			}
		}

		if resp.ForwardSource.Syslog != nil {
			m.SyslogConfig = &SyslogConfigModel{
				ServerID: types.Int64Value(int64(resp.ForwardSource.Syslog.ID)),
			}
		}
	}

	m.Shared.ID = types.StringValue(resp.ID)
	m.Shared.Name = types.StringValue(resp.Name)
	m.Shared.Description = types.StringValue(resp.Description)
	m.Shared.Enabled = types.BoolValue(resp.Enabled)
	m.Shared.Scope = scope
	m.Shared.Timezone = types.StringValue(resp.TimeZone)
}

// ----------------------------------------------------------------------------
// Issues
// ----------------------------------------------------------------------------

// NotificationForwardingConfigurationIssuesModel is the model for the notification_forwarding_config_issues resource.
type NotificationForwardingConfigurationIssuesModel struct {
	Shared       NotificationForwardingConfigurationSharedFields
	EmailConfig  *EmailConfigIssuesModel  `tfsdk:"email_config"`
	SyslogConfig *SyslogConfigIssuesModel `tfsdk:"syslog_config"`
}

// EmailConfigIssuesModel is the model for email notification forwarding settings as represented in the Issues notification forwarding configuration type.
type EmailConfigIssuesModel struct {
	DistributionList  types.List   `tfsdk:"distribution_list"`
	Subject           types.String `tfsdk:"subject"`
	Format            types.String `tfsdk:"format"`
	GroupingTimeframe types.Int32  `tfsdk:"grouping_timeframe"`
}

func (m *EmailConfigIssuesModel) ToSDK(ctx context.Context, diags *diag.Diagnostics) (platformTypes.EmailForwardSource, string) {
	distributionList := make([]string, len(m.DistributionList.Elements()))
	diags.Append(m.DistributionList.ElementsAs(ctx, &distributionList, false)...)
	if diags.HasError() {
		return platformTypes.EmailForwardSource{}, ""
	}

	return platformTypes.EmailForwardSource{
		Aggregation:       int(m.GroupingTimeframe.ValueInt32()),
		DistributionList:  distributionList,
		CustomMailSubject: m.Subject.ValueString(),
	}, m.Format.ValueString()
}

func (m *EmailConfigIssuesModel) Equals(other *EmailConfigIssuesModel) (isEqual bool) {
	if m == nil && other == nil {
		return true
	}
	if m == nil || other == nil {
		return false
	}

	if (m == nil && other != nil) ||
		(m != nil && other == nil) ||
		!m.DistributionList.Equal(other.DistributionList) ||
		!m.Subject.Equal(other.Subject) ||
		!m.GroupingTimeframe.Equal(other.GroupingTimeframe) ||
		!m.Format.Equal(other.Format) {
		return false
	}

	return true
}

// SyslogConfigIssuesModel is the model for syslog notification forwarding settings as represented in the Issues notification forwarding configuration type.
type SyslogConfigIssuesModel struct {
	ServerID types.Int64  `tfsdk:"server_id"`
	Format   types.String `tfsdk:"format"`
}

func (m *SyslogConfigIssuesModel) ToSDK(ctx context.Context, diags *diag.Diagnostics) (platformTypes.SyslogForwardSource, string) {
	return platformTypes.SyslogForwardSource{
		ID: int(m.ServerID.ValueInt64()),
	}, m.Format.ValueString()
}

func (m *SyslogConfigIssuesModel) Equals(other *SyslogConfigIssuesModel) (isEqual bool) {
	if m == nil && other == nil {
		return true
	}
	if m == nil || other == nil {
		return false
	}

	if (m == nil && other != nil) ||
		(m != nil && other == nil) ||
		!m.ServerID.Equal(other.ServerID) ||
		!m.Format.Equal(other.Format) {
		return false
	}

	return true
}

func (m *NotificationForwardingConfigurationIssuesModel) FromTfsdk(ctx context.Context, diags *diag.Diagnostics, config ITfsdkConfig) {
	(&m.Shared).FromTfsdk(ctx, diags, config)
	if diags.HasError() {
		return
	}

	diags.Append(config.GetAttribute(ctx, path.Root("email_config"), &m.EmailConfig)...)
	if diags.HasError() {
		return
	}

	diags.Append(config.GetAttribute(ctx, path.Root("syslog_config"), &m.SyslogConfig)...)
	if diags.HasError() {
		return
	}
}

// ToCreateOrUpdateRequest returns a new CreateOrUpdateNotificationForwardingConfigurationRequest using the values of the NotificationForwardingConfigIssuesModel's fields.
func (m *NotificationForwardingConfigurationIssuesModel) ToCreateOrUpdateRequest(ctx context.Context, diags *diag.Diagnostics) platformTypes.CreateOrUpdateNotificationForwardingConfigurationRequest {
	// Convert scope filter
	var scope filterTypes.FilterRoot
	if m.Shared.Scope != nil {
		scope = sharedModels.RootModelToSDKFilter(ctx, m.Shared.Scope)
	}

	// Convert integration forwarding configurations
	forwardSource := platformTypes.ForwardSource{}

	// Email
	var (
		emailForwardSource platformTypes.EmailForwardSource = platformTypes.EmailForwardSource{}
		emailFormat        string                           = EmailFormatIssue
	)
	if m.EmailConfig != nil {
		emailForwardSource, emailFormat = m.EmailConfig.ToSDK(ctx, diags)
		if diags.HasError() {
			return platformTypes.CreateOrUpdateNotificationForwardingConfigurationRequest{}
		}
		forwardSource.Email = &emailForwardSource
	}

	// Syslog
	var (
		syslogForwardSource platformTypes.SyslogForwardSource = platformTypes.SyslogForwardSource{}
		syslogFormat        string                            = EmailFormatIssue
	)
	if m.SyslogConfig != nil {
		syslogForwardSource, syslogFormat = m.SyslogConfig.ToSDK(ctx, diags)
		if diags.HasError() {
			return platformTypes.CreateOrUpdateNotificationForwardingConfigurationRequest{}
		}
		forwardSource.Syslog = &syslogForwardSource
	}

	return platformTypes.CreateOrUpdateNotificationForwardingConfigurationRequest{
		Name:        m.Shared.Name.ValueString(),
		Description: m.Shared.Description.ValueString(),
		ForwardType: enums.NotificationForwardingConfigurationTypeIssues.String(),
		Filter: struct {
			Filter filterTypes.FilterRoot `json:"filter"`
		}{
			Filter: scope,
		},
		ForwardSource: forwardSource,
		MailFormat:    strings.ToLower(emailFormat),
		SyslogFormat:  strings.ToLower(syslogFormat),
	}
}

// Equals compares two NotificationForwardingConfigurationIssuesModel
// structs and returns true if all of their fields are equal, false otherwise.
func (m *NotificationForwardingConfigurationIssuesModel) Equals(diags *diag.Diagnostics, other *NotificationForwardingConfigurationIssuesModel) (isEqual bool) {
	if m == nil && other == nil {
		return true
	}
	if m == nil || other == nil {
		return false
	}

	sharedFieldsEqual, err := m.Shared.Equals(&other.Shared)
	if err != nil {
		diags.AddError(
			"Error Comparing Shared Notification Forwarding Configuration Fields",
			fmt.Sprintf("Error occurred while comparing shared fields between model structs: %s"+
				"\nPlease report this issue to the provider developers.", err.Error()),
		)
		return false
	}

	if !sharedFieldsEqual ||
		!m.EmailConfig.Equals(other.EmailConfig) ||
		!m.SyslogConfig.Equals(other.SyslogConfig) {
		return false
	}

	return true
}

// RefreshFromRemote refreshes the model from the remote API response.
func (m *NotificationForwardingConfigurationIssuesModel) RefreshFromRemote(ctx context.Context, diags *diag.Diagnostics, resp platformTypes.NotificationForwardingConfiguration) {
	scope := sharedModels.SDKToModel(ctx, resp.Filter)
	if len(scope.And) == 0 && len(scope.Or) == 0 {
		scope = nil
	}

	if resp.ForwardSource != nil {
		if resp.ForwardSource.Email != nil {
			distributionList, convertDiags := types.ListValueFrom(ctx, types.StringType, resp.ForwardSource.Email.DistributionList)
			diags.Append(convertDiags...)
			if diags.HasError() {
				return
			}

			m.EmailConfig = &EmailConfigIssuesModel{
				GroupingTimeframe: types.Int32Value(int32(resp.ForwardSource.Email.Aggregation)),
				DistributionList:  distributionList,
				Subject:           types.StringValue(resp.ForwardSource.Email.CustomMailSubject),
				Format:            types.StringValue(strings.ToLower(resp.MailFormat)),
			}
		}

		if resp.ForwardSource.Syslog != nil {
			m.SyslogConfig = &SyslogConfigIssuesModel{
				ServerID: types.Int64Value(int64(resp.ForwardSource.Syslog.ID)),
				Format:   types.StringValue(strings.ToLower(resp.SyslogFormat)),
			}
		}
	}

	m.Shared.ID = types.StringValue(resp.ID)
	m.Shared.Name = types.StringValue(resp.Name)
	m.Shared.Description = types.StringValue(resp.Description)
	m.Shared.Enabled = types.BoolValue(resp.Enabled)
	m.Shared.Scope = scope
	m.Shared.Timezone = types.StringValue(resp.TimeZone)
}

// ----------------------------------------------------------------------------
// Cases
// ----------------------------------------------------------------------------

// NotificationForwardingConfigurationCasesModel is the model for the notification_forwarding_config_cases resource.
type NotificationForwardingConfigurationCasesModel struct {
	Shared      NotificationForwardingConfigurationSharedFields
	EmailConfig *EmailConfigModel `tfsdk:"email_config"`
}

func (m *NotificationForwardingConfigurationCasesModel) FromTfsdk(ctx context.Context, diags *diag.Diagnostics, config ITfsdkConfig) {
	(&m.Shared).FromTfsdk(ctx, diags, config)
	if diags.HasError() {
		return
	}

	diags.Append(config.GetAttribute(ctx, path.Root("email_config"), &m.EmailConfig)...)
	if diags.HasError() {
		return
	}
}

// ToCreateOrUpdateRequest returns a new CreateOrUpdateNotificationForwardingConfigurationRequest using the values of the NotificationForwardingConfigurationCasesModel struct's fields.
func (m *NotificationForwardingConfigurationCasesModel) ToCreateOrUpdateRequest(ctx context.Context, diags *diag.Diagnostics) platformTypes.CreateOrUpdateNotificationForwardingConfigurationRequest {
	// Convert scope filter
	var scope filterTypes.FilterRoot
	if m.Shared.Scope != nil {
		scope = sharedModels.RootModelToSDKFilter(ctx, m.Shared.Scope)
	}

	// Convert integration forwarding configurations
	forwardSource := platformTypes.ForwardSource{}
	if m.EmailConfig != nil {
		emailForwardSource := m.EmailConfig.ToSDK(ctx, diags)
		if diags.HasError() {
			return platformTypes.CreateOrUpdateNotificationForwardingConfigurationRequest{}
		}
		forwardSource.Email = &emailForwardSource
	}

	return platformTypes.CreateOrUpdateNotificationForwardingConfigurationRequest{
		Name:        m.Shared.Name.ValueString(),
		Description: m.Shared.Description.ValueString(),
		ForwardType: enums.NotificationForwardingConfigurationTypeCases.String(),
		Filter: struct {
			Filter filterTypes.FilterRoot `json:"filter"`
		}{
			Filter: scope,
		},
		ForwardSource: forwardSource,
	}
}

// Equals compares two NotificationForwardingConfigurationCasesModel
// structs and returns true if all of their fields are equal, false otherwise.
func (m *NotificationForwardingConfigurationCasesModel) Equals(diags *diag.Diagnostics, other *NotificationForwardingConfigurationCasesModel) (isEqual bool) {
	if m == nil && other == nil {
		return true
	}
	if m == nil || other == nil {
		return false
	}

	sharedFieldsEqual, err := m.Shared.Equals(&other.Shared)
	if err != nil {
		diags.AddError(
			"Error Comparing Shared Notification Forwarding Configuration Fields",
			fmt.Sprintf("Error occurred while comparing shared fields between model structs: %s"+
				"\nPlease report this issue to the provider developers.", err.Error()),
		)
		return false
	}

	if !sharedFieldsEqual ||
		!m.EmailConfig.Equals(other.EmailConfig) {
		return false
	}

	return true
}

// RefreshFromRemote refreshes the model from the remote API response.
func (m *NotificationForwardingConfigurationCasesModel) RefreshFromRemote(ctx context.Context, diags *diag.Diagnostics, resp platformTypes.NotificationForwardingConfiguration) {
	scope := sharedModels.SDKToModel(ctx, resp.Filter)
	if len(scope.And) == 0 && len(scope.Or) == 0 {
		scope = nil
	}

	if resp.ForwardSource != nil {
		if resp.ForwardSource.Email != nil {
			distributionList, convertDiags := types.ListValueFrom(ctx, types.StringType, resp.ForwardSource.Email.DistributionList)
			diags.Append(convertDiags...)
			if diags.HasError() {
				return
			}

			m.EmailConfig = &EmailConfigModel{
				GroupingTimeframe: types.Int32Value(int32(resp.ForwardSource.Email.Aggregation)),
				DistributionList:  distributionList,
				Subject:           types.StringValue(resp.ForwardSource.Email.CustomMailSubject),
			}
		}
	}

	m.Shared.ID = types.StringValue(resp.ID)
	m.Shared.Name = types.StringValue(resp.Name)
	m.Shared.Description = types.StringValue(resp.Description)
	m.Shared.Enabled = types.BoolValue(resp.Enabled)
	m.Shared.Scope = scope
	m.Shared.Timezone = types.StringValue(resp.TimeZone)
}

// ----------------------------------------------------------------------------
// Validation
// ----------------------------------------------------------------------------
