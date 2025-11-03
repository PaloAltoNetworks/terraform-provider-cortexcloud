// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package platform

import (
	"context"
	"fmt"

	models "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/platform"
	providerModels "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/provider"
	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/util"

	"github.com/PaloAltoNetworks/cortex-cloud-go/platform"
	platformTypes "github.com/PaloAltoNetworks/cortex-cloud-go/types/platform"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/objectdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ resource.Resource = &AuthenticationSettingsResource{}
)

// NewAuthenticationSettingsResource is a helper function to simplify the provider implementation.
func NewAuthenticationSettingsResource() resource.Resource {
	return &AuthenticationSettingsResource{}
}

// AuthenticationSettingsResource is the resource implementation.
type AuthenticationSettingsResource struct {
	client *platform.Client
}

// Metadata returns the resource type name.
func (r *AuthenticationSettingsResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_authentication_settings"
}

// Schema defines the schema for the resource.
func (r *AuthenticationSettingsResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages an Authentication Settings configuration.",
		Attributes: map[string]schema.Attribute{
			"name": schema.StringAttribute{
				Description:         "The name of the SSO integration.",
				MarkdownDescription: "The name of the SSO integration.",
				Required:            true,
			},
			"default_role": schema.StringAttribute{
				Description:         "The default role automatically assigned to every user who authenticates to Cortex using SAML. This is an inherited role and is not the same as a direct role assigned to the user.\n\nIf a role with the same name exists on both Cortex Gateway and the tenant, the role will mapped to the role from the tenant. If you want to specifically use the role from Cortex Gateway, set the \"is_account_role\" parameter to \"true\".",
				MarkdownDescription: "The default role automatically assigned to every user who authenticates to Cortex using SAML. This is an inherited role and is not the same as a direct role assigned to the user.\n\nIf a role with the same name exists on both Cortex Gateway and the tenant, the role will mapped to the role from the tenant. If you want to specifically use the role from Cortex Gateway, set the `is_account_role` parameter to `true`.",
				Optional:            true,
				Computed:            true,
				Default:             stringdefault.StaticString(""),
			},
			"is_account_role": schema.BoolAttribute{
				Description:         "Whether the specified default role exists in Cortex Gateway or in the tenant. Set to \"true\" if the role was created in Cortex Gateway or \"false\" if the role was created in the tenant. Defaults to false.",
				MarkdownDescription: "Whether the specified default role exists in Cortex Gateway or in the tenant. Set to `true` if the role was created in Cortex Gateway or `false` if the role was created in the tenant. Defaults to false.",
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
			},
			"domain": schema.StringAttribute{
				Description:         "The email domain to associate with this IDP.\n\nWhen configuring the very first SSO integration, this value should be empty as it will be used as the default SSO with a fixed, read-only value. \n\nWhen logging in, users are redirected to the IdP associated with this domain, or to the default IdP if no association exists.",
				MarkdownDescription: "The email domain to associate with this IDP.\n\nWhen configuring the very first SSO integration, this value should be empty as it will be used as the default SSO with a fixed, read-only value. \n\nWhen logging in, users are redirected to the IdP associated with this domain, or to the default IdP if no association exists.",
				Required:            true,
			},
			"mappings": schema.SingleNestedAttribute{
				Description:         "Attribute mappings dictated by your organization's IdP.",
				MarkdownDescription: "Attribute mappings dictated by your organization's IdP.",
				Required:            true,
				Attributes: map[string]schema.Attribute{
					"email": schema.StringAttribute{
						Description:         "The IdP attribute mapped to the user's email address in the Syslog server.",
						MarkdownDescription: "The IdP attribute mapped to the user's email address in the Syslog server.",
						Required:            true,
					},
					"first_name": schema.StringAttribute{
						Description:         "The IdP attribute mapped to the user's first name.",
						MarkdownDescription: "The IdP attribute mapped to the user's first name.",
						Required:            true,
					},
					"last_name": schema.StringAttribute{
						Description:         "The IdP attribute mapped to the user's last name.",
						MarkdownDescription: "The IdP attribute mapped to the user's last name.",
						Required:            true,
					},
					"group_name": schema.StringAttribute{
						Description:         "The IdP attribute mapped to the user's group membership for authorization.\n\nCortex requires the IdP to send the group membership as part of the SAML token. Some IdPs send values in a format that include a comma, which is not compatible with Cortex. To resolve this, you must configure your IdP to send a single value without a comma for each group membership. For example, if your IdP sends the Group DN (a comma-separated list) by default, you must configure the IdP to send the Group CN (Common Name) instead.",
						MarkdownDescription: "The IdP attribute mapped to the user's group membership for authorization.\n\nCortex requires the IdP to send the group membership as part of the SAML token. Some IdPs send values in a format that include a comma, which is not compatible with Cortex. To resolve this, you must configure your IdP to send a single value without a comma for each group membership. For example, if your IdP sends the Group DN (a comma-separated list) by default, you must configure the IdP to send the Group CN (Common Name) instead.",
						Required:            true,
					},
				},
			},
			"advanced_settings": schema.SingleNestedAttribute{
				Description: "Optional advanced settings that may be relevant for a specific IdP.",
				Optional:    true,
				Computed:    true,
				Attributes: map[string]schema.Attribute{
					"relay_state": schema.StringAttribute{
						Description:         "The URL that users will be directed to after they've been authenticated by your organization's IdP and log into Cortex.",
						MarkdownDescription: "The URL that users will be directed to after they've been authenticated by your organization's IdP and log into Cortex.",
						Optional:            true,
						Computed:            true,
						Default:             stringdefault.StaticString(""),
					},
					"idp_single_logout_url": schema.StringAttribute{
						Description:         "The URL of the IdP's Single Logout endpoint. Configuring this ensures that when a user logs out of Cortex, the IdP logs the user out of all applications in the current identity provider login session.",
						MarkdownDescription: "The URL of the IdP's Single Logout endpoint. Configuring this ensures that when a user logs out of Cortex, the IdP logs the user out of all applications in the current identity provider login session.",
						Optional:            true,
						Computed:            true,
						Default:             stringdefault.StaticString(""),
					},
					"service_provider_public_cert": schema.StringAttribute{
						Description:         "The syslog server's public X.509 certificate in PEM format for IdP validation.",
						MarkdownDescription: "The syslog server's public X.509 certificate in PEM format for IdP validation.",
						Optional:            true,
						Computed:            true,
						Default:             stringdefault.StaticString(""),
					},
					"service_provider_private_key": schema.StringAttribute{
						Description:         "The syslog server's private key in PEM format for signing SAML responses. This is most relevant for the integration of Azure Directory Federation Services (ADFS).",
						MarkdownDescription: "The syslog server's private key in PEM format for signing SAML responses. This is most relevant for the integration of Azure Directory Federation Services (ADFS).",
						Optional:            true,
						Computed:            true,
						Default:             stringdefault.StaticString(""),
					},
					"authn_context_enabled": schema.BoolAttribute{
						Description:         "Whether to remove the \"RequestedAuthnContext\" parameter from SAML requests.\n\nIf set to \"true\", users will be able to log in using additional authentication methods.",
						MarkdownDescription: "Whether to remove the `RequestedAuthnContext` parameter from SAML requests.\n\nIf set to `true`, users will be able to log in using additional authentication methods.",
						Optional:            true,
						Computed:            true,
						Default:             booldefault.StaticBool(false),
					},
					"force_authn": schema.BoolAttribute{
						Description:         "Whether to force users to re-authenticate in order to access the Cortex tenant if requested by the IdP (even if they already authenticated to access other applications).",
						MarkdownDescription: "Whether to force users to re-authenticate in order to access the Cortex tenant if requested by the IdP (even if they already authenticated to access other applications).",
						Optional:            true,
						Computed:            true,
						Default:             booldefault.StaticBool(false),
					},
				},
				Default: objectdefault.StaticValue(
					types.ObjectValueMust(
						map[string]attr.Type{
							"relay_state":                  types.StringType,
							"idp_single_logout_url":        types.StringType,
							"service_provider_public_cert": types.StringType,
							"service_provider_private_key": types.StringType,
							"authn_context_enabled":        types.BoolType,
							"force_authn":                  types.BoolType,
						},
						map[string]attr.Value{
							"relay_state":                  types.StringValue(""),
							"idp_single_logout_url":        types.StringValue(""),
							"service_provider_public_cert": types.StringValue(""),
							"service_provider_private_key": types.StringValue(""),
							"authn_context_enabled":        types.BoolValue(false),
							"force_authn":                  types.BoolValue(false),
						},
					),
				),
			},
			"tenant_id": schema.StringAttribute{
				Description:         "The UUID of the tenant.",
				MarkdownDescription: "The UUID of the tenant.",
				Computed:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"idp_enabled": schema.BoolAttribute{
				Description:         "Whether the IdP is enabled. Defaults to \"true\".",
				MarkdownDescription: "Whether the IdP is enabled. Defaults to `true`.",
				Computed:            true,
				Default:             booldefault.StaticBool(true),
			},
			"idp_sso_url": schema.StringAttribute{
				Description:         "The login URL of your IdP. This should be copied from the SAML integration configuration on the IdP.\n\nExample values:\n- Okta: \"https://cortex-test.okta.com/app/cortex-test/eacbt6b2jj08CasdUQ7sdf15d7/sso/SAML\"\n- Microsoft Azure: \"https://login.microsoftonline.com/6a5a9780-96a4-41ef-bf45-0535d8a70025/saml2\"",
				MarkdownDescription: "The login URL of your IdP. This should be copied from the SAML integration configuration on the IdP.\n\nExample values:\n- Okta: `https://cortex-test.okta.com/app/cortex-test/eacbt6b2jj08CasdUQ7sdf15d7/sso/SAML`\n- Microsoft Azure: `https://login.microsoftonline.com/6a5a9780-96a4-41ef-bf45-0535d8a70025/saml2`",
				Optional:            true,
				Computed:            true,
				Default:             stringdefault.StaticString(""),
			},
			"idp_certificate": schema.StringAttribute{
				Description:         "The Idp's public X.509 digital certificate in PEM format for verification, which is copied from your organization's IdP.",
				MarkdownDescription: "The Idp's public X.509 digital certificate in PEM format for verification, which is copied from your organization's IdP.",
				Optional:            true,
				Computed:            true,
				Default:             stringdefault.StaticString(""),
			},
			"idp_issuer": schema.StringAttribute{
				Description:         "The unique identifier of the IdP issuing SAML assertions, which is copied from your organization's IdP.",
				MarkdownDescription: "The unique identifier of the IdP issuing SAML assertions, which is copied from your organization's IdP.",
				Optional:            true,
				Computed:            true,
				Default:             stringdefault.StaticString(""),
			},
			"metadata_url": schema.StringAttribute{
				Description:         "The metadata URL provides information about hte IdP's capabilities, endpoints, keys, and more. \n\nExample values: \n- Okta: \"https://cortex-test.okta.com/app/exkbuuzw77Bh04V6M6b8/sso/saml/metadata\"\n- Microsoft Azure: \"https://login.microsoftonline.com/6a5a9780-96a4-41ef-bf45-0535d8a70025/saml2/metadata\"",
				MarkdownDescription: "The metadata URL provides information about hte IdP's capabilities, endpoints, keys, and more. \n\nExample values: \n- Okta: `https://cortex-test.okta.com/app/exkbuuzw77Bh04V6M6b8/sso/saml/metadata`\n- Microsoft Azure: `https://login.microsoftonline.com/6a5a9780-96a4-41ef-bf45-0535d8a70025/saml2/metadata`",
				Optional:            true,
				Computed:            true,
			},
			"sp_entity_id": schema.StringAttribute{
				Description:         "The service provider entity ID.",
				MarkdownDescription: "The service provider entity ID.",
				Computed:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"sp_logout_url": schema.StringAttribute{
				Description:         "The service provider logout URL.",
				MarkdownDescription: "The service provider logout URL.",
				Computed:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"sp_url": schema.StringAttribute{
				Description:         "The service provider URL.",
				MarkdownDescription: "The service provider URL.",
				Computed:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
		},
	}
}

// Configure adds the provider-configured client to the resource.
func (r *AuthenticationSettingsResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(*providerModels.CortexCloudSDKClients)

	if !ok {
		util.AddUnexpectedResourceConfigureTypeError(&resp.Diagnostics, "*providerModels.CortexCloudSDKClients", req.ProviderData)
		return
	}

	r.client = client.Platform
}

func (r *AuthenticationSettingsResource) findAuthSettings(ctx context.Context, name, domain string) (*platformTypes.AuthSettings, error) {
	allAuthSettings, err := r.client.ListAuthSettings(ctx)
	if err != nil {
		return nil, err
	}

	for i, as := range allAuthSettings {
		if as.Name == name && as.Domain == domain {
			return &allAuthSettings[i], nil
		}
	}

	return nil, nil
}

func (r *AuthenticationSettingsResource) refreshModelFromAPI(authSettings *platformTypes.AuthSettings, model *models.AuthenticationSettingsModel) {
	model.Name = types.StringValue(authSettings.Name)
	model.DefaultRole = types.StringValue(authSettings.DefaultRole)
	model.IsAccountRole = types.BoolValue(authSettings.IsAccountRole)
	model.Domain = types.StringValue(authSettings.Domain)
	model.TenantID = types.StringValue(authSettings.TenantID)
	model.IdpEnabled = types.BoolValue(authSettings.IDPEnabled)
	model.IdpSsoUrl = types.StringValue(authSettings.IDPSingleSignOnURL)
	model.IdpCertificate = types.StringValue(authSettings.IDPCertificate)
	model.IdpIssuer = types.StringValue(authSettings.IDPIssuer)
	model.MetadataURL = types.StringValue(authSettings.MetadataURL)
	model.SpEntityID = types.StringValue(authSettings.SpEntityID)
	model.SpLogoutURL = types.StringValue(authSettings.SpLogoutURL)
	model.SpURL = types.StringValue(authSettings.SpURL)

	if model.Mappings == nil {
		model.Mappings = &models.MappingsModel{}
	}
	model.Mappings.Email = types.StringValue(authSettings.Mappings.Email)
	model.Mappings.FirstName = types.StringValue(authSettings.Mappings.FirstName)
	model.Mappings.LastName = types.StringValue(authSettings.Mappings.LastName)
	model.Mappings.GroupName = types.StringValue(authSettings.Mappings.GroupName)

	if model.AdvancedSettings == nil {
		model.AdvancedSettings = &models.AdvancedSettingsModel{}
	}
	model.AdvancedSettings.RelayState = types.StringValue(authSettings.AdvancedSettings.RelayState)
	model.AdvancedSettings.IdpSingleLogoutURL = types.StringValue(authSettings.AdvancedSettings.IDPSingleLogoutURL)
	model.AdvancedSettings.ServiceProviderPublicCert = types.StringValue(authSettings.AdvancedSettings.ServiceProviderPublicCert)
	model.AdvancedSettings.ServiceProviderPrivateKey = types.StringValue(authSettings.AdvancedSettings.ServiceProviderPrivateKey)
	model.AdvancedSettings.AuthnContextEnabled = types.BoolValue(authSettings.AdvancedSettings.AuthnContextEnabled)
	model.AdvancedSettings.ForceAuthn = types.BoolValue(authSettings.AdvancedSettings.ForceAuthn)
}

// Create creates the resource and sets the initial Terraform state.
func (r *AuthenticationSettingsResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	// Read Terraform plan data into model
	var plan models.AuthenticationSettingsModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Create new resource
	createRequest := platformTypes.CreateAuthSettingsRequest{
		Name:               plan.Name.ValueString(),
		DefaultRole:        plan.DefaultRole.ValueString(),
		IsAccountRole:      plan.IsAccountRole.ValueBool(),
		Domain:             plan.Domain.ValueString(),
		IDPSingleSignOnURL: plan.IdpSsoUrl.ValueString(),
		IDPCertificate:     plan.IdpCertificate.ValueString(),
		IDPIssuer:          plan.IdpIssuer.ValueString(),
		MetadataURL:        plan.MetadataURL.ValueString(),
	}
	if plan.Mappings != nil {
		createRequest.Mappings = platformTypes.Mappings{
			Email:     plan.Mappings.Email.ValueString(),
			FirstName: plan.Mappings.FirstName.ValueString(),
			LastName:  plan.Mappings.LastName.ValueString(),
			GroupName: plan.Mappings.GroupName.ValueString(),
		}
	}
	if plan.AdvancedSettings != nil {
		createRequest.AdvancedSettings = platformTypes.AdvancedSettings{
			RelayState:                plan.AdvancedSettings.RelayState.ValueString(),
			IDPSingleLogoutURL:        plan.AdvancedSettings.IdpSingleLogoutURL.ValueString(),
			ServiceProviderPublicCert: plan.AdvancedSettings.ServiceProviderPublicCert.ValueString(),
			ServiceProviderPrivateKey: plan.AdvancedSettings.ServiceProviderPrivateKey.ValueString(),
			AuthnContextEnabled:       plan.AdvancedSettings.AuthnContextEnabled.ValueBool(),
			ForceAuthn:                plan.AdvancedSettings.ForceAuthn.ValueBool(),
		}
	}

	_, err := r.client.CreateAuthSettings(ctx, createRequest)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Creating Authentication Settings",
			err.Error(),
		)
		return
	}

	authSettings, err := r.findAuthSettings(ctx, plan.Name.ValueString(), plan.Domain.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Creating Authentication Settings",
			fmt.Sprintf("Error reading authentication settings after creation: %s", err.Error()),
		)
		return
	}

	if authSettings == nil {
		resp.Diagnostics.AddError(
			"Error Creating Authentication Settings",
			"Could not find the authentication settings after creation.",
		)
		return
	}

	// Populate values from the read response
	r.refreshModelFromAPI(authSettings, &plan)

	// Set state to fully populated data
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Read refreshes the Terraform state with the latest data.
func (r *AuthenticationSettingsResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	// Get current state
	var state models.AuthenticationSettingsModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Retrieve resource from API
	authSettings, err := r.findAuthSettings(ctx, state.Name.ValueString(), state.Domain.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Reading Authentication Settings",
			err.Error(),
		)
		return
	}

	if authSettings == nil {
		resp.Diagnostics.AddWarning(
			"Authentication Settings not found",
			fmt.Sprintf(`No authentication settings found with name "%s" and domain "%s", removing from state.`, state.Name.ValueString(), state.Domain.ValueString()),
		)
		resp.State.RemoveResource(ctx)
		return
	}

	// Refresh state values
	r.refreshModelFromAPI(authSettings, &state)

	// Set refreshed state
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *AuthenticationSettingsResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	// Read Terraform plan data into model
	var plan models.AuthenticationSettingsModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Get current state
	var state models.AuthenticationSettingsModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Update resource
	updateRequest := platformTypes.UpdateAuthSettingsRequest{
		Name:               plan.Name.ValueString(),
		DefaultRole:        plan.DefaultRole.ValueString(),
		IsAccountRole:      plan.IsAccountRole.ValueBool(),
		CurrentDomain:      state.Domain.ValueString(),
		NewDomain:          plan.Domain.ValueString(),
		IDPSingleSignOnURL: plan.IdpSsoUrl.ValueString(),
		IDPCertificate:     plan.IdpCertificate.ValueString(),
		IDPIssuer:          plan.IdpIssuer.ValueString(),
		MetadataURL:        plan.MetadataURL.ValueString(),
	}
	if plan.Mappings != nil {
		updateRequest.Mappings = platformTypes.Mappings{
			Email:     plan.Mappings.Email.ValueString(),
			FirstName: plan.Mappings.FirstName.ValueString(),
			LastName:  plan.Mappings.LastName.ValueString(),
			GroupName: plan.Mappings.GroupName.ValueString(),
		}
	}
	if plan.AdvancedSettings != nil {
		updateRequest.AdvancedSettings = platformTypes.AdvancedSettings{
			RelayState:                plan.AdvancedSettings.RelayState.ValueString(),
			IDPSingleLogoutURL:        plan.AdvancedSettings.IdpSingleLogoutURL.ValueString(),
			ServiceProviderPublicCert: plan.AdvancedSettings.ServiceProviderPublicCert.ValueString(),
			ServiceProviderPrivateKey: plan.AdvancedSettings.ServiceProviderPrivateKey.ValueString(),
			AuthnContextEnabled:       plan.AdvancedSettings.AuthnContextEnabled.ValueBool(),
			ForceAuthn:                plan.AdvancedSettings.ForceAuthn.ValueBool(),
		}
	}

	_, err := r.client.UpdateAuthSettings(ctx, updateRequest)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Updating Authentication Settings",
			err.Error(),
		)
		return
	}

	authSettings, err := r.findAuthSettings(ctx, plan.Name.ValueString(), plan.Domain.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Updating Authentication Settings",
			fmt.Sprintf("Error reading authentication settings after update: %s", err.Error()),
		)
		return
	}

	if authSettings == nil {
		resp.Diagnostics.AddError(
			"Error Updating Authentication Settings",
			"Could not find the authentication settings after update.",
		)
		return
	}

	// Populate values from the read response
	r.refreshModelFromAPI(authSettings, &plan)

	// Set refreshed state
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Delete deletes the resource and removes it from the Terraform state on success.
func (r *AuthenticationSettingsResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	// Get current state
	var state models.AuthenticationSettingsModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Delete resource
	_, err := r.client.DeleteAuthSettings(ctx, state.Domain.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Deleting Authentication Settings",
			err.Error(),
		)
		return
	}
}
