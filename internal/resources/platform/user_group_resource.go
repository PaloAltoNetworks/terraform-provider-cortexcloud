// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package platform

import (
	"context"
	"fmt"

	models "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/platform"
	providerModels "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/provider"
	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/util"
	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/validators"

	platformsdk "github.com/PaloAltoNetworks/cortex-cloud-go/platform"
	platformtypes "github.com/PaloAltoNetworks/cortex-cloud-go/types/platform"

	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/setdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
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
				Description: "The unique identifier of the user group.",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"group_name": schema.StringAttribute{
				Description: "The unique name for the user group.",
				Required:    true,
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			"description": schema.StringAttribute{
				Description: "A brief description of the user group's purpose.",
				Optional:    true,
				Computed:    true,
				Default:     stringdefault.StaticString(""),
			},
			"role_id": schema.StringAttribute{
				Description: "The unique identifier of the role to assign to this group.",
				Optional:    true,
			},
			"pretty_role_name": schema.StringAttribute{
				Description: "The display name of the role assigned to this group.",
				Computed:    true,
			},
			"created_by": schema.StringAttribute{
				Description: "The user or system that created the user group.",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"created_ts": schema.Int64Attribute{
				Description: "Unix timestamp (milliseconds) of when the user group was created.",
				Computed:    true,
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.UseStateForUnknown(),
				},
			},
			"updated_ts": schema.Int64Attribute{
				Description: "Unix timestamp (milliseconds) of when the user group was last updated.",
				Computed:    true,
			},
			"users": schema.SetAttribute{
				Description: "A list of email addresses corresponding to the users directly configured in this group.\n\nWhen this resource is refreshed, any additional users configured in this group outside of Terraform will appear in the `all_users` attribute, along with users associated with the group via SAML claim. To keep this attribute aligned with the directly-configured users, you must manually update it with any out-of-band changes from the console/API, then apply those changes.",
				ElementType: types.StringType,
				Optional:    true,
				Validators: []validator.Set{
					setvalidator.ValueStringsAre(
						validators.StringIsValidEmailAddress(),
					),
				},
			},
			"all_users": schema.SetAttribute{
				Description: "Read-only. A list of email address corresponding to the users with effective membership for this group. \n\nThis list represents the union of users that have been directly configured in this group and any users that are a member of an IDP group configured in the `idp_groups` attribute that have logged in via SSO/JIT authentication.\n\nDue to API limitations, it is currently not possible to determine which users were added from direct configuration versus SSO/JIT authentication.",
				ElementType: types.StringType,
				Computed:    true,
			},
			"group_type": schema.StringAttribute{
				Description: "The type of the user group. Possible values: `custom` (created directly in the UI), `ad_type` (imported and synchronized from Azure Active Directory).",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"nested_groups": schema.SetNestedAttribute{
				Description: "A list of unique identifiers for groups to be nested within this group.",
				Optional:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"group_id": schema.StringAttribute{
							Description: "The unique identifier of the nested group.",
							Required:    true,
							PlanModifiers: []planmodifier.String{
								stringplanmodifier.UseStateForUnknown(),
							},
						},
						"group_name": schema.StringAttribute{
							Description: "The display name of the nested group.",
							Computed:    true,
						},
					},
				},
			},
			"idp_groups": schema.SetAttribute{
				Description: "A list of identity provider (IdP) group names to associate with this group. Members of these IdP groups are added to this user group automatically via SSO/JIT and appear in `idp_users`.",
				ElementType: types.StringType,
				Optional:    true,
				Computed:    true,
				Default:     setdefault.StaticValue(types.SetNull(types.StringType)),
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
		util.AddUnexpectedResourceConfigurationTypeError(&resp.Diagnostics, "*providerModels.CortexCloudSDKClients", req.ProviderData)
		return
	}

	r.client = client.Platform
}

// Create creates the resource and sets the initial Terraform state.
func (r *userGroupResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	tflog.Trace(ctx, "Starting userGroupResource.Create()")

	var plan models.UserGroupModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	request := plan.ToCreateRequest(ctx, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

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
		resp.Diagnostics.AddError(
			"Error Fetching Created User Group",
			"User group was created successfully but could not be fetched. Please report this issue to the developers.")
		return
	}

	plan.RefreshFromRemote(ctx, &resp.Diagnostics, remote)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)

	tflog.Trace(ctx, "Finishing userGroupResource.Create()")
}

// Read refreshes the Terraform state with the latest data.
func (r *userGroupResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	tflog.Trace(ctx, "Starting userGroupResource.Read()")

	var state models.UserGroupModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	groups, err := r.client.ListUserGroups(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Error Reading User Group", err.Error())
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

	tflog.Trace(ctx, "Finishing userGroupResource.Read()")
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *userGroupResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	tflog.Trace(ctx, "Starting userGroupResource.Update()")

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

	request := plan.ToEditRequest(ctx, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	if _, err := r.client.EditUserGroup(ctx, state.ID.ValueString(), request); err != nil {
		resp.Diagnostics.AddError(
			"Error Updating User Group",
			err.Error(),
		)
		return
	}

	groups, err := r.client.ListUserGroups(ctx)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Fetching Updated User Group",
			fmt.Sprintf("Error occurred while fetching updated user group: %s", err.Error()),
		)
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
		resp.Diagnostics.AddError(
			"Error Fetching Updated User Group",
			"User group was updated successfully but could not be fetched. Please report this issue to the developers.")
		return
	}

	plan.RefreshFromRemote(ctx, &resp.Diagnostics, remote)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)

	tflog.Trace(ctx, "Finishing userGroupResource.Update()")
}

// Delete deletes the resource and removes it from the Terraform state on success.
func (r *userGroupResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	tflog.Trace(ctx, "Starting userGroupResource.Delete()")

	var state models.UserGroupModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	_, err := r.client.DeleteUserGroup(ctx, state.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Error Deleting User Group", err.Error())
		return
	}

	tflog.Trace(ctx, "Finishing userGroupResource.Delete()")
}

// ImportState imports the resource into the Terraform state.
func (r *userGroupResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
