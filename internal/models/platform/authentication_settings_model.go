// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package models

import (
	"github.com/hashicorp/terraform-plugin-framework/types"
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
