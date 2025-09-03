package platform

import (
	"context"
	"net/http"
)

type AuthSettings struct {
	TenantID string   `json:"tenant_id"`
	Name string   `json:"name"`
	Domain string   `json:"domain"`
	IDPEnabled bool `json:"idp_enabled"`
	DefaultRole string   `json:"default_role"`
	IsAccountRole bool `json:"is_account_role"`
	IDPCertificate string `json:"idp_certificate"`
	IDPIssuer string `json:"idp_issuer"`
	IDPSingleSignOnURL string `json:"idp_sso_url"`
	MetadataURL string `json:"metadata_url"`
	Mappings Mappings `json:"mappings"`
	AdvancedSettings AdvancedSettings `json:"advanced_settings"`
	SpEntityID string `json:"sp_entity_id"`
	SpLogoutURL string `json:"sp_logout_url"`
	SpURL string `json:"sp_url"`
}

type Mappings struct {
	Email string `json:"email"`
	FirstName string `json:"firstname"`
	GroupName string `json:"group_name"`
	LastName string `json:"lastname"`
}

type AdvancedSettings struct {
	AuthnContextEnabled bool `json:"authn_context_enabled"`
	//ForceAuthn bool `json:"authn_context_enabled"`
	IDPSingleLogoutURL string `json:"idp_single_logout_url"`
	RelayState string `json:"relay_state"`
	ServiceProviderPrivateKey string `json:"service_provider_private_key"`
	ServiceProviderPublicCert string `json:"service_provider_public_cert"`
}


// ---------------------------
// Request/Response structs
// ---------------------------

// ListIDPMetadata

type ListIDPMetadataRequest struct {
	Data ListIDPMetadataRequestData `json:"request_data"`
}

type ListIDPMetadataRequestData struct {}

type ListIDPMetadataResponse struct {
	TenantID string   `json:"tenant_id"`
	SpEntityID string `json:"sp_entity_id"`
	SpLogoutURL string `json:"sp_logout_url"`
	SpURL string `json:"sp_url"`
}

// ListAuthSettings

type ListAuthSettingsRequest struct {
	Data ListAuthSettingsRequestData `json:"request_data"`
}

type ListAuthSettingsRequestData struct {}

type ListAuthSettingsResponse struct {
	Reply []AuthSettings `json:"reply"`
}

// CreateAuthSettings

type CreateAuthSettingsRequest struct {
	Data CreateAuthSettingsRequestData `json:"request_data"`
}

type CreateAuthSettingsRequestData struct {
	Name string `json:"name"`
	DefaultRole string `json:"default_role"`
	IsAccountRole bool `json:"is_account_role"`
	Domain string `json:"domain"`
	Mappings Mappings `json:"mappings"`
	AdvancedSettings AdvancedSettings `json:"advanced_settings"`
	IDPSingleSignOnURL string `json:"idp_sso_url"`
	IDPCertificate string `json:"idp_certificate"`
	IDPIssuer string `json:"idp_issuer"`
	MetadataURL string `json:"metadata_url"`
}

type CreateAuthSettingsResponse struct {
	Reply bool `json:"reply"`
}

// UpdateAuthSettings

type UpdateAuthSettingsRequest struct {
	Data UpdateAuthSettingsRequestData `json:"request_data"`
}

type UpdateAuthSettingsRequestData struct {
	Name string `json:"name"`
	DefaultRole string `json:"default_role"`
	IsAccountRole bool `json:"is_account_role"`
	CurrentDomain string `json:"current_domain_value"`
	NewDomain string `json:"new_domain_value"`
	Mappings Mappings `json:"mappings"`
	AdvancedSettings AdvancedSettings `json:"advanced_settings"`
	IDPSingleSignOnURL string `json:"idp_sso_url"`
	IDPCertificate string `json:"idp_certificate"`
	IDPIssuer string `json:"idp_issuer"`
	MetadataURL string `json:"metadata_url"`
}

type UpdateAuthSettingsResponse struct {
	Reply bool `json:"reply"`
}

// DeleteAuthSettings

type DeleteAuthSettingsRequest struct {
	Data DeleteAuthSettingsRequestData `json:"request_data"`
}

type DeleteAuthSettingsRequestData struct {
	Domain string `json:"domain"`
}

type DeleteAuthSettingsResponse struct {
	Reply bool `json:"reply"`
}

// ---------------------------
// Request functions
// ---------------------------

// ListIDPMetadata returns the metadata for all IDPs.
//
// This endpoint requires Instance Administrator permissions.
func (c *Client) ListIDPMetadata(ctx context.Context) (ListIDPMetadataResponse, error) {

	var ans ListIDPMetadataResponse
	_, err := c.internalClient.Do(ctx, http.MethodPost, ListIDPMetadataEndpoint, nil, nil, ListIDPMetadataRequest{}, &ans)

	return ans, err
}

// ListAuthSettings returns the authentication settings for all configured 
// domains in the tenant.
//
// This endpoint requires Instance Administrator permissions.
func (c *Client) ListAuthSettings(ctx context.Context) (ListAuthSettingsResponse, error) {

	var ans ListAuthSettingsResponse
	_, err := c.internalClient.Do(ctx, http.MethodPost, ListAuthSettingsEndpoint, nil, nil, ListAuthSettingsRequest{}, &ans)

	return ans, err
}

// CreateAuthSettings creates authentication settings for the specified domain 
// using the provided IDP SSO or metadata URL.
//
// To configure IDP SSO, the `idp_sso_url`, `idp_issuer` and `idp_certificate`
// fields are required. To configure via metadata URL, the `metadata_url` is
// the only required field.
//
// This endpoint requires Instance Administrator permissions.
func (c *Client) CreateAuthSettings(ctx context.Context, req CreateAuthSettingsRequest) (CreateAuthSettingsResponse, error) {

	var resp CreateAuthSettingsResponse
	_, err := c.internalClient.Do(ctx, http.MethodPost, CreateAuthSettingsEndpoint, nil, nil, req, &resp)

	return resp, err
}

// UpdateAuthSettings updates the existing authentication settings for the
// specified domain.
//
// To update the default domain, provide empty strings for the 
// `current_domain_value` and `new_domain_value` fields.
//
// This endpoint requires Instance Administrator permissions.
func (c *Client) UpdateAuthSettings(ctx context.Context, req UpdateAuthSettingsRequest) (UpdateAuthSettingsResponse, error) {

	var resp UpdateAuthSettingsResponse
	_, err := c.internalClient.Do(ctx, http.MethodPost, UpdateAuthSettingsEndpoint, nil, nil, req, &resp)

	return resp, err
}

// DeleteAuthSettings deletes all authentication settings for the specified
// domain.
//
// This endpoint requires Instance Administrator permissions.
func (c *Client) DeleteAuthSettings(ctx context.Context, domain string) (DeleteAuthSettingsResponse, error) {
	req := DeleteAuthSettingsRequest{
		Data: DeleteAuthSettingsRequestData{
			Domain: domain,
		},
	}

	var resp DeleteAuthSettingsResponse
	_, err := c.internalClient.Do(ctx, http.MethodPost, DeleteAuthSettingsEndpoint, nil, nil, req, &resp)

	return resp, err
}
