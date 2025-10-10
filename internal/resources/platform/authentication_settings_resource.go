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
		Description: "TODO",
		Attributes: map[string]schema.Attribute{
			"name": schema.StringAttribute{
				Description: "TODO",
				Required:    true,
			},
			"default_role": schema.StringAttribute{
				Description: "TODO",
				Optional:    true,
				Computed:    true,
				Default:     stringdefault.StaticString(""),
			},
			"is_account_role": schema.BoolAttribute{
				Description: "TODO",
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(false),
			},
			"domain": schema.StringAttribute{
				Description: "TODO", // Make sure to mention the mapping of empty string to the default/first SSO
				Required:    true,
			},
			"mappings": schema.SingleNestedAttribute{
				Description: "TODO",
				Required:    true,
				Attributes: map[string]schema.Attribute{
					"email": schema.StringAttribute{
						Description: "TODO",
						Required:    true,
					},
					"first_name": schema.StringAttribute{
						Description: "TODO",
						Required:    true,
					},
					"last_name": schema.StringAttribute{
						Description: "TODO",
						Required:    true,
					},
					"group_name": schema.StringAttribute{
						Description: "TODO",
						Required:    true,
					},
				},
			},
			"advanced_settings": schema.SingleNestedAttribute{
				Description: "TODO",
				Optional:    true,
				Computed:    true,
				Attributes: map[string]schema.Attribute{
					"relay_state": schema.StringAttribute{
						Description: "TODO",
						Optional:    true,
						Computed:    true,
						Default:     stringdefault.StaticString(""),
					},
					"idp_single_logout_url": schema.StringAttribute{
						Description: "TODO",
						Optional:    true,
						Computed:    true,
						Default:     stringdefault.StaticString(""),
					},
					"service_provider_public_cert": schema.StringAttribute{
						Description: "TODO",
						Optional:    true,
						Computed:    true,
						Default:     stringdefault.StaticString(""),
					},
					"service_provider_private_key": schema.StringAttribute{
						Description: "TODO",
						Optional:    true,
						Computed:    true,
						Default:     stringdefault.StaticString(""),
					},
					"authn_context_enabled": schema.BoolAttribute{
						Description: "TODO",
						Optional:    true,
						Computed:    true,
						Default:     booldefault.StaticBool(false),
					},
					"force_authn": schema.BoolAttribute{
						Description: "TODO",
						Optional:    true,
						Computed:    true,
						Default:     booldefault.StaticBool(false),
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
				Description: "TODO",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"idp_enabled": schema.BoolAttribute{
				Description: "TODO",
				Computed:    true,
				Default:     booldefault.StaticBool(true),
			},
			"idp_sso_url": schema.StringAttribute{
				Description: "TODO",
				Optional:    true,
				Computed:    true,
				Default:     stringdefault.StaticString(""),
			},
			"idp_certificate": schema.StringAttribute{
				Description: "TODO",
				Optional:    true,
				Computed:    true,
				Default:     stringdefault.StaticString(""),
			},
			"idp_issuer": schema.StringAttribute{
				Description: "TODO",
				Optional:    true,
				Computed:    true,
				Default:     stringdefault.StaticString(""),
			},
			"metadata_url": schema.StringAttribute{
				Description: "TODO",
				Optional:    true,
				Computed:    true,
			},
			"sp_entity_id": schema.StringAttribute{
				Description: "TODO",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"sp_logout_url": schema.StringAttribute{
				Description: "TODO",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"sp_url": schema.StringAttribute{
				Description: "TODO",
				Computed:    true,
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

	//for i, as := range allAuthSettings.Reply {
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
	//model.AdvancedSettings.ForceAuthn = types.BoolValue(authSettings.AdvancedSettings.ForceAuthn)
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
			//ForceAuthn:                plan.AdvancedSettings.ForceAuthn.ValueBool(),
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
			//ForceAuthn:                plan.AdvancedSettings.ForceAuthn.ValueBool(),
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
