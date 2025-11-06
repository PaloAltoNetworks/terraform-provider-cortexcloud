// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package models

import (
	cloudOnboardingTypes "github.com/PaloAltoNetworks/cortex-cloud-go/types/cloudonboarding"
)

type scopeModificationRegions struct {
	Enabled bool     `json:"enabled" tfsdk:"enabled"`
	Type    *string   `json:"type,omitempty" tfsdk:"type"`
	Regions *[]string `json:"regions,omitempty" tfsdk:"regions"`
}

var managedByPANWTag = cloudOnboardingTypes.Tag{
	Key: "managed_by",
	Value: "paloaltonetworks",
}

type CollectionConfigurationModel struct {
	AuditLogs AuditLogsModel `tfsdk:"audit_logs"`
}

type AuditLogsModel struct {
	Enabled types.Bool `tfsdk:"enabled"`
}

type TagModel struct {
	Key   types.String `tfsdk:"key"`
	Value types.String `tfsdk:"value"`
}

type ScopeModificationsModel struct {
	Regions ScopeModificationsRegionsModel `tfsdk:"regions"`
}

type ScopeModificationsRegionsModel struct {
	Enabled types.Bool `tfsdk:"enabled"`
}

type scopeModificationRegions struct {
	Enabled bool     `json:"enabled" tfsdk:"enabled"`
	Type    *string   `json:"type,omitempty" tfsdk:"type"`
	Regions *[]string `json:"regions,omitempty" tfsdk:"regions"`
}
