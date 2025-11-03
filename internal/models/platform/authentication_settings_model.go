// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package models

import (
	"context"

	platformTypes "github.com/PaloAltoNetworks/cortex-cloud-go/types/platform"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// AuthenticationSettingsModel is the model for the authentication_settings resource.
type AuthenticationSettingsModel struct {
	Name             types.String           `tfsdk:"name"`
	DefaultRole      types.String           `tfsdk:"default_role"`
	IsAccountRole    types.Bool             `tfsdk:"is_account_role"`
	Domain           types.String           `tfsdk:"domain"`
	Mappings         *MappingsModel         `tfsdk:"mappings"`
	AdvancedSettings *AdvancedSettingsModel `tfsdk:"advanced_settings"`
	TenantID         types.String           `tfsdk:"tenant_id"`
	IdpEnabled       types.Bool             `tfsdk:"idp_enabled"`
	IdpSsoUrl        types.String           `tfsdk:"idp_sso_url"`
	IdpCertificate   types.String           `tfsdk:"idp_certificate"`
	IdpIssuer        types.String           `tfsdk:"idp_issuer"`
	MetadataURL      types.String           `tfsdk:"metadata_url"`
	SpEntityID       types.String           `tfsdk:"sp_entity_id"`
	SpLogoutURL      types.String           `tfsdk:"sp_logout_url"`
	SpURL            types.String           `tfsdk:"sp_url"`
}

// MappingsModel is the model for the mappings nested attribute.
type MappingsModel struct {
	Email     types.String `tfsdk:"email"`
	FirstName types.String `tfsdk:"first_name"`
	LastName  types.String `tfsdk:"last_name"`
	GroupName types.String `tfsdk:"group_name"`
}

// AdvancedSettingsModel is the model for the advanced_settings nested attribute.
type AdvancedSettingsModel struct {
	RelayState                types.String `tfsdk:"relay_state"`
	IdpSingleLogoutURL        types.String `tfsdk:"idp_single_logout_url"`
	ServiceProviderPublicCert types.String `tfsdk:"service_provider_public_cert"`
	ServiceProviderPrivateKey types.String `tfsdk:"service_provider_private_key"`
	AuthnContextEnabled       types.Bool   `tfsdk:"authn_context_enabled"`
	ForceAuthn                types.Bool   `tfsdk:"force_authn"`
}

// RefreshFromRemote refreshes the model from the remote API response.
func (m *AuthenticationSettingsModel) RefreshFromRemote(ctx context.Context, diags *diag.Diagnostics, remote *platformTypes.AuthSettings) {
	tflog.Debug(ctx, "Refreshing authentication settings model from remote")

	tflog.Trace(ctx, "Setting authentication settings attributes")
	m.Name = types.StringValue(remote.Name)
	m.DefaultRole = types.StringValue(remote.DefaultRole)
	m.IsAccountRole = types.BoolValue(remote.IsAccountRole)
	m.Domain = types.StringValue(remote.Domain)
	m.TenantID = types.StringValue(remote.TenantID)
	m.IdpEnabled = types.BoolValue(remote.IDPEnabled)
	m.IdpSsoUrl = types.StringValue(remote.IDPSingleSignOnURL)
	m.IdpCertificate = types.StringValue(remote.IDPCertificate)
	m.IdpIssuer = types.StringValue(remote.IDPIssuer)
	m.MetadataURL = types.StringValue(remote.MetadataURL)
	m.SpEntityID = types.StringValue(remote.SpEntityID)
	m.SpLogoutURL = types.StringValue(remote.SpLogoutURL)
	m.SpURL = types.StringValue(remote.SpURL)

	tflog.Trace(ctx, "Initializing mappings model if nil")
	if m.Mappings == nil {
		m.Mappings = &MappingsModel{}
	}
	tflog.Trace(ctx, "Setting mappings attributes")
	m.Mappings.Email = types.StringValue(remote.Mappings.Email)
	m.Mappings.FirstName = types.StringValue(remote.Mappings.FirstName)
	m.Mappings.LastName = types.StringValue(remote.Mappings.LastName)
	m.Mappings.GroupName = types.StringValue(remote.Mappings.GroupName)

	tflog.Trace(ctx, "Initializing advanced settings model if nil")
	if m.AdvancedSettings == nil {
		m.AdvancedSettings = &AdvancedSettingsModel{}
	}
	tflog.Trace(ctx, "Setting advanced settings attributes")
	m.AdvancedSettings.RelayState = types.StringValue(remote.AdvancedSettings.RelayState)
	m.AdvancedSettings.IdpSingleLogoutURL = types.StringValue(remote.AdvancedSettings.IDPSingleLogoutURL)
	m.AdvancedSettings.ServiceProviderPublicCert = types.StringValue(remote.AdvancedSettings.ServiceProviderPublicCert)
	m.AdvancedSettings.ServiceProviderPrivateKey = types.StringValue(remote.AdvancedSettings.ServiceProviderPrivateKey)
	m.AdvancedSettings.AuthnContextEnabled = types.BoolValue(remote.AdvancedSettings.AuthnContextEnabled)
	m.AdvancedSettings.ForceAuthn = types.BoolValue(remote.AdvancedSettings.ForceAuthn)
}
