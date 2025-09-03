// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package models

import (
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type AdditionalCapabilitiesModel struct {
	XsiamAnalytics                types.Bool                   `tfsdk:"xsiam_analytics"`
	DataSecurityPostureManagement types.Bool                   `tfsdk:"data_security_posture_management"`
	RegistryScanning              types.Bool                   `tfsdk:"registry_scanning"`
	RegistryScanningOptions       RegistryScanningOptionsModel `tfsdk:"registry_scanning_options"`
}

type RegistryScanningOptionsModel struct {
	Type types.String `tfsdk:"type"`
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
