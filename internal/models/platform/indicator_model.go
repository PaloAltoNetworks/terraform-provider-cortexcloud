// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package models

import (
	"context"

	"github.com/PaloAltoNetworks/cortex-cloud-go/enums"
	platformTypes "github.com/PaloAltoNetworks/cortex-cloud-go/types/platform"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// IndicatorModel is the Terraform model for the cortexcloud_indicator
// resource and data source. The `indicator` string is the resource identity
// (mirrored into ID for plugin-framework compatibility); `rule_id` is the
// server-assigned numeric ID surfaced as a read-only attribute.
//
// The last five fields are populated only by the server (creation time,
// modification time, status, source, number of issues). They are read-only
// and never carried into the SDK insert payload.
type IndicatorModel struct {
	ID                       types.String `tfsdk:"id"`
	Indicator                types.String `tfsdk:"indicator"`
	Type                     types.String `tfsdk:"type"`
	Severity                 types.String `tfsdk:"severity"`
	ExpirationDate           types.Int64  `tfsdk:"expiration_date"`
	DefaultExpirationEnabled types.Bool   `tfsdk:"default_expiration_enabled"`
	Comment                  types.String `tfsdk:"comment"`
	Reputation               types.String `tfsdk:"reputation"`
	Reliability              types.String `tfsdk:"reliability"`
	RuleID                   types.Int64  `tfsdk:"rule_id"`

	CreationTime     types.Int64  `tfsdk:"creation_time"`
	ModificationTime types.Int64  `tfsdk:"modification_time"`
	Status           types.String `tfsdk:"status"`
	Source           types.String `tfsdk:"source"`
	NumberOfIssues   types.Int64  `tfsdk:"number_of_issues"`
}

// RefreshFromRemote updates the model in place with the latest fields from
// the API response.
func (m *IndicatorModel) RefreshFromRemote(ctx context.Context, diags *diag.Diagnostics, remote *platformTypes.Indicator) {
	tflog.Debug(ctx, "Refreshing indicator model from remote")

	m.ID = types.StringValue(remote.Indicator)
	m.Indicator = types.StringValue(remote.Indicator)
	m.Type = types.StringValue(string(remote.Type))
	m.Severity = types.StringValue(string(remote.Severity))
	m.ExpirationDate = types.Int64Value(remote.ExpirationDate)
	m.DefaultExpirationEnabled = types.BoolValue(remote.DefaultExpirationEnabled)
	m.Comment = types.StringValue(remote.Comment)
	m.Reputation = types.StringValue(string(remote.Reputation))
	m.Reliability = types.StringValue(string(remote.Reliability))
	m.RuleID = types.Int64Value(int64(remote.RuleID))

	m.CreationTime = types.Int64Value(remote.CreationTime)
	m.ModificationTime = types.Int64Value(remote.ModificationTime)
	m.Status = types.StringValue(remote.Status)
	m.Source = types.StringValue(remote.Source)
	m.NumberOfIssues = types.Int64Value(int64(remote.NumberOfIssues))
}

// ToSDKIndicator converts the Terraform model into the SDK Indicator type
// used as the insert payload. Null/unknown values flatten to their zero
// values; the SDK type uses omitempty so optional fields drop out of the
// serialized request. Read-only fields are not threaded into the payload.
func (m *IndicatorModel) ToSDKIndicator() platformTypes.Indicator {
	return platformTypes.Indicator{
		Indicator:                m.Indicator.ValueString(),
		Type:                     enums.IndicatorType(m.Type.ValueString()),
		Severity:                 enums.IndicatorSeverity(m.Severity.ValueString()),
		ExpirationDate:           m.ExpirationDate.ValueInt64(),
		DefaultExpirationEnabled: m.DefaultExpirationEnabled.ValueBool(),
		Comment:                  m.Comment.ValueString(),
		Reputation:               enums.IndicatorReputation(m.Reputation.ValueString()),
		Reliability:              enums.IndicatorReliability(m.Reliability.ValueString()),
	}
}
