// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package types

type AuthSettings struct {
	TenantID           string           `json:"tenant_id"`
	Name               string           `json:"name"`
	Domain             string           `json:"domain"`
	IDPEnabled         bool             `json:"idp_enabled"`
	DefaultRole        string           `json:"default_role"`
	IsAccountRole      bool             `json:"is_account_role"`
	IDPCertificate     string           `json:"idp_certificate,omitempty"`
	IDPIssuer          string           `json:"idp_issuer,omitempty"`
	IDPSingleSignOnURL string           `json:"idp_sso_url,omitempty"`
	MetadataURL        string           `json:"metadata_url,omitempty"`
	Mappings           Mappings         `json:"mappings"`
	AdvancedSettings   AdvancedSettings `json:"advanced_settings"`
	SpEntityID         string           `json:"sp_entity_id"`
	SpLogoutURL        string           `json:"sp_logout_url"`
	SpURL              string           `json:"sp_url"`
}

type Mappings struct {
	Email     string `json:"email"`
	FirstName string `json:"firstname"`
	GroupName string `json:"group_name"`
	LastName  string `json:"lastname"`
}

type AdvancedSettings struct {
	AuthnContextEnabled       bool   `json:"authn_context_enabled,omitempty"`
	IDPSingleLogoutURL        string `json:"idp_single_logout_url,omitempty"`
	RelayState                string `json:"relay_state,omitempty"`
	ServiceProviderPrivateKey string `json:"service_provider_private_key,omitempty"`
	ServiceProviderPublicCert string `json:"service_provider_public_cert,omitempty"`
	ForceAuthn                bool   `json:"force_authn,omitempty"`
}

// ListIDPMetadataRequest is the request for listing IDP metadata.
type ListIDPMetadataRequest struct{}

// ListIDPMetadataResponse is the response for listing IDP metadata.
type ListIDPMetadataResponse struct {
	TenantID    string `json:"tenant_id"`
	SpEntityID  string `json:"sp_entity_id"`
	SpLogoutURL string `json:"sp_logout_url"`
	SpURL       string `json:"sp_url"`
}

// ListAuthSettingsRequest is the request for listing auth settings.
type ListAuthSettingsRequest struct{}

// CreateAuthSettingsRequest is the request for creating auth settings.
type CreateAuthSettingsRequest struct {
	Name               string           `json:"name"`
	DefaultRole        string           `json:"default_role"`
	IsAccountRole      bool             `json:"is_account_role"`
	Domain             string           `json:"domain"`
	Mappings           Mappings         `json:"mappings"`
	AdvancedSettings   AdvancedSettings `json:"advanced_settings"`
	IDPSingleSignOnURL string           `json:"idp_sso_url,omitempty"`
	IDPCertificate     string           `json:"idp_certificate,omitempty"`
	IDPIssuer          string           `json:"idp_issuer,omitempty"`
	MetadataURL        string           `json:"metadata_url,omitempty"`
}

// UpdateAuthSettingsRequest is the request for updating auth settings.
type UpdateAuthSettingsRequest struct {
	Name               string           `json:"name"`
	DefaultRole        string           `json:"default_role"`
	IsAccountRole      bool             `json:"is_account_role"`
	CurrentDomain      string           `json:"current_domain_value"`
	NewDomain          string           `json:"new_domain_value"`
	Mappings           Mappings         `json:"mappings"`
	AdvancedSettings   AdvancedSettings `json:"advanced_settings"`
	IDPSingleSignOnURL string           `json:"idp_sso_url,omitempty"`
	IDPCertificate     string           `json:"idp_certificate,omitempty"`
	IDPIssuer          string           `json:"idp_issuer,omitempty"`
	MetadataURL        string           `json:"metadata_url,omitempty"`
}

// DeleteAuthSettingsRequest is the request for deleting auth settings.
type DeleteAuthSettingsRequest struct {
	Domain string `json:"domain"`
}
