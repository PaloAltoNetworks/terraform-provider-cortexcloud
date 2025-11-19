// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package platform

import (
	"context"
	_ "strings"

	models "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/platform"
	providerModels "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/provider"
	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/util"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/setplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"

	platformsdk "github.com/PaloAltoNetworks/cortex-cloud-go/platform"
	platformtypes "github.com/PaloAltoNetworks/cortex-cloud-go/types/platform"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ resource.Resource                = &userGroupResource{}
	_ resource.ResourceWithConfigure   = &userGroupResource{}
	_ resource.ResourceWithImportState = &userGroupResource{}
)

// NewUserGroupResource is a helper function to simplify the provider implementation.
func NewUserGroupResource() resource.Resource {
	return &userGroupResource{}
}

// userGroupResource is the resource implementation.
type userGroupResource struct {
	client *platformsdk.Client
}

// Metadata returns the resource type name.
func (r *userGroupResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_user_group"
}

// Schema defines the schema for the resource.
func (r *userGroupResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a Cortex Cloud user group.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "The ID of the user group.",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"group_name": schema.StringAttribute{
				Description: "The name of the user group.",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"description": schema.StringAttribute{
				Description: "The description of the user group.",
				Optional:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"role_id": schema.StringAttribute{
				Description: "The role id associated with the user group.",
				Optional:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"pretty_role_name": schema.StringAttribute{
				Description: "The pretty name of the role associated with the user group.",
				Computed:    true,
			},
			"created_by": schema.StringAttribute{
				Description: "The user who created the user group.",
				Computed:    true,
			},
			"created_ts": schema.Int64Attribute{
				Description: "The timestamp of when the user group was created.",
				Computed:    true,
			},
			"updated_ts": schema.Int64Attribute{
				Description: "The timestamp of when the user group was last updated.",
				Computed:    true,
			},
			"users": schema.SetAttribute{
				Description: "The users in the user group.",
				ElementType: types.StringType,
				Optional:    true,
				PlanModifiers: []planmodifier.Set{
					setplanmodifier.UseStateForUnknown(),
				},
			},
			"group_type": schema.StringAttribute{
				Description: "The type of the user group.",
				Computed:    true,
			},
			"nested_groups": schema.SetNestedAttribute{
				Description: "The nested groups in the user group.",
				Optional:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"group_id": schema.StringAttribute{
							Description: "The ID of the nested group.",
							Required:    true,
							PlanModifiers: []planmodifier.String{
								stringplanmodifier.UseStateForUnknown(),
							},
						},
						"group_name": schema.StringAttribute{
							Description: "The name of the nested group.",
							Computed:    true,
							Optional:    true,
						},
					},
				},
			},
			"idp_groups": schema.SetAttribute{
				Description: "The IDP groups in the user group.",
				ElementType: types.StringType,
				Optional:    true,
				PlanModifiers: []planmodifier.Set{
					setplanmodifier.UseStateForUnknown(),
				},
			},
		},
	}
}

// Configure adds the provider-configured client to the resource.
func (r *userGroupResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

// Create creates the resource and sets the initial Terraform state.
// user_group_resource.go
func (r *userGroupResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan models.UserGroupModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	request := plan.ToCreateRequest()
	groupID, err := r.client.CreateUserGroup(ctx, request)
	if err != nil {
		resp.Diagnostics.AddError("Error creating user group", err.Error())
		return
	}

	plan.ID = types.StringValue(groupID)

	groups, err := r.client.ListUserGroups(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Error reading user groups after creation", err.Error())
		return
	}

	var remote *platformtypes.UserGroup
	for i := range groups {
		if groups[i].GroupID == groupID {
			remote = &groups[i]
			break
		}
	}

	if remote == nil {
		resp.Diagnostics.AddError("Error locating newly created user group",
			"The user group was created successfully, but could not be found in the list.")
		return
	}

	plan.RefreshFromRemote(ctx, &resp.Diagnostics, remote)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Read refreshes the Terraform state with the latest data.
func (r *userGroupResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state models.UserGroupModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	groups, err := r.client.ListUserGroups(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Error reading user groups", err.Error())
		return
	}

	var remote *platformtypes.UserGroup
	for i := range groups {
		if groups[i].GroupID == state.ID.ValueString() {
			remote = &groups[i]
			break
		}
	}

	if remote == nil {
		// deleted
		resp.State.RemoveResource(ctx)
		return
	}

	state.RefreshFromRemote(ctx, &resp.Diagnostics, remote)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *userGroupResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan models.UserGroupModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var state models.UserGroupModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	request := plan.ToEditRequest()
	if _, err := r.client.EditUserGroup(ctx, state.ID.ValueString(), request); err != nil {
		resp.Diagnostics.AddError("Error updating user group", err.Error())
		return
	}

	groups, err := r.client.ListUserGroups(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Error reading user groups after update", err.Error())
		return
	}

	var remote *platformtypes.UserGroup
	for i := range groups {
		if groups[i].GroupID == state.ID.ValueString() {
			remote = &groups[i]
			break
		}
	}

	if remote == nil {
		resp.State.RemoveResource(ctx)
		return
	}

	plan.RefreshFromRemote(ctx, &resp.Diagnostics, remote)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Delete deletes the resource and removes it from the Terraform state on success.
func (r *userGroupResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state models.UserGroupModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	_, err := r.client.DeleteUserGroup(ctx, state.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Error deleting user group", err.Error())
		return
	}
}

// ImportState imports the resource into the Terraform state.
func (r *userGroupResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
