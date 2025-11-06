// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package platform

import (
	"context"

	models "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/platform"
	providerModels "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/provider"
	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/util"

	platformsdk "github.com/PaloAltoNetworks/cortex-cloud-go/platform"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ resource.Resource                = &userResource{}
	_ resource.ResourceWithConfigure   = &userResource{}
	_ resource.ResourceWithImportState = &userResource{}
)

// NewUserResource is a helper function to simplify the provider implementation.
func NewUserResource() resource.Resource {
	return &userResource{}
}

// userResource is the resource implementation.
type userResource struct {
	client *platformsdk.Client
}

// Metadata returns the resource type name.
func (r *userResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_user"
}

// Schema defines the schema for the resource.
func (r *userResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a Cortex Cloud user.",
		Attributes: map[string]schema.Attribute{
			"user_email": schema.StringAttribute{
				Description: "The email of the user.",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"user_first_name": schema.StringAttribute{
				Description: "The first name of the user.",
				Optional:    true,
			},
			"user_last_name": schema.StringAttribute{
				Description: "The last name of the user.",
				Optional:    true,
			},
			"phone_number": schema.StringAttribute{
				Description: "The phone number of the user.",
				Optional:    true,
			},
			"status": schema.StringAttribute{
				Description: "The status of the user.",
				Optional:    true,
			},
			"role_name": schema.StringAttribute{
				Description: "The role name of the user.",
				Computed:    true,
			},
			"last_logged_in": schema.Int64Attribute{
				Description: "The last logged in timestamp of the user.",
				Computed:    true,
			},
			"hidden": schema.BoolAttribute{
				Description: "The hidden status of the user.",
				Optional:    true,
			},
			"user_type": schema.StringAttribute{
				Description: "The user type of the user.",
				Computed:    true,
			},
			"groups": schema.ListNestedAttribute{
				Description: "The groups of the user.",
				Optional:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"group_id": schema.StringAttribute{
							Description: "The ID of the nested group.",
							Required:    true,
						},
						"group_name": schema.StringAttribute{
							Description: "The name of the nested group.",
							Computed:    true,
						},
					},
				},
			},
		},
	}
}

// Configure adds the provider-configured client to the resource.
func (r *userResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

// Read refreshes the Terraform state with the latest data.
func (r *userResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state models.UserModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	user, err := r.client.GetIAMUser(ctx, state.Email.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Error getting user", err.Error())
		return
	}

	state.RefreshFromRemote(ctx, &resp.Diagnostics, user)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *userResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan models.UserModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	request := plan.ToEditRequest()
	_, err := r.client.EditIAMUser(ctx, plan.Email.ValueString(), request)
	if err != nil {
		resp.Diagnostics.AddError("Error updating user", err.Error())
		return
	}

	user, err := r.client.GetIAMUser(ctx, plan.Email.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Error getting user after update", err.Error())
		return
	}

	plan.RefreshFromRemote(ctx, &resp.Diagnostics, user)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Create: fake
func (r *userResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan models.UserModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	email := plan.Email.ValueString()

	if _, err := r.client.GetIAMUser(ctx, email); err != nil {
		resp.Diagnostics.AddError(
			"Create not supported for user",
			"User does not exist remotely or API returned error: "+err.Error(),
		)
		return
	}

	editReq := plan.ToEditRequest()
	if _, err := r.client.EditIAMUser(ctx, email, editReq); err != nil {
		resp.Diagnostics.AddError("Error updating user during create", err.Error())
		return
	}

	user, err := r.client.GetIAMUser(ctx, email)
	if err != nil {
		resp.Diagnostics.AddError("Error getting user after create", err.Error())
		return
	}
	plan.RefreshFromRemote(ctx, &resp.Diagnostics, user)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Delete: not implemented
func (r *userResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	// no-op: allow discard
}

func (r *userResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("user_email"), req, resp)
}
