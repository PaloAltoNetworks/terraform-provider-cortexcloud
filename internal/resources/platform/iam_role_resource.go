// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package platform

import (
	"context"

	models "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/platform"
	providerModels "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/provider"
	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/util"

	"github.com/PaloAltoNetworks/cortex-cloud-go/platform"
	platformTypes "github.com/PaloAltoNetworks/cortex-cloud-go/types/platform"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ resource.Resource = &iamRoleResource{}
)

// NewIamRoleResource is a helper function to simplify the provider implementation.
func NewIamRoleResource() resource.Resource {
	return &iamRoleResource{}
}

// iamRoleResource is the resource implementation.
type iamRoleResource struct {
	client *platform.Client
}

// Metadata returns the resource type name.
func (r *iamRoleResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_iam_role"
}

func (r *iamRoleResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages an IAM role.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "The ID of the role.",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"pretty_name": schema.StringAttribute{
				Description: "The name of the role.",
				Required:    true,
			},
			"description": schema.StringAttribute{
				Description: "The description of the role.",
				Optional:    true,
			},
			"component_permissions": schema.ListAttribute{
				Description: "The component permissions for the role.",
				Required:    true,
				ElementType: types.StringType,
			},
			"dataset_permissions": schema.ListNestedAttribute{
				Description: "The dataset permissions for the role.",
				Optional:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"category": schema.StringAttribute{
							Description: "The category of the dataset.",
							Required:    true,
						},
						"access_all": schema.BoolAttribute{
							Description: "Whether to grant access to all datasets in the category.",
							Required:    true,
						},
						"permissions": schema.ListAttribute{
							Description: "The permissions for the dataset.",
							Required:    true,
							ElementType: types.StringType,
						},
					},
				},
			},
			"is_custom": schema.BoolAttribute{
				Description: "Whether the role is a custom role.",
				Computed:    true,
			},
			"created_by": schema.StringAttribute{
				Description: "The user who created the role.",
				Computed:    true,
			},
			"created_ts": schema.Int64Attribute{
				Description: "The creation time of the role.",
				Computed:    true,
			},
			"updated_ts": schema.Int64Attribute{
				Description: "The last update time of the role.",
				Computed:    true,
			},
		},
	}
}

// Configure adds the provider-configured client to the resource.
func (r *iamRoleResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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
func (r *iamRoleResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	var plan models.IamRoleModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// 1) component_permissions
	var componentPermissions []string
	resp.Diagnostics.Append(plan.ComponentPermissions.ElementsAs(ctx, &componentPermissions, false)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// 2) dataset_permissions (optional)
	var datasetPermissions []platformTypes.DatasetPermission
	if !plan.DatasetPermissions.IsNull() && !plan.DatasetPermissions.IsUnknown() {
		var dsPermsModels []models.DatasetPermissionModel
		resp.Diagnostics.Append(plan.DatasetPermissions.ElementsAs(ctx, &dsPermsModels, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
		for _, m := range dsPermsModels {
			var perms []string
			resp.Diagnostics.Append(m.Permissions.ElementsAs(ctx, &perms, false)...)
			if resp.Diagnostics.HasError() {
				return
			}
			datasetPermissions = append(datasetPermissions, platformTypes.DatasetPermission{
				Category:    m.Category.ValueString(),
				AccessAll:   m.AccessAll.ValueBool(),
				Permissions: perms,
			})
		}
	}

	createReq := platformTypes.RoleCreateRequest{
		RequestData: platformTypes.RoleCreateRequestData{
			PrettyName:           plan.PrettyName.ValueString(),
			Description:          plan.Description.ValueString(),
			ComponentPermissions: componentPermissions,
			DatasetPermissions:   datasetPermissions,
		},
	}

	created, err := r.client.CreateRole(ctx, createReq)
	if err != nil {
		resp.Diagnostics.AddError("Error Creating IAM Role", err.Error())
		return
	}

	roleID := ""
	if created != nil {
		roleID = created.RoleID
	}

	listResp, listErr := r.client.ListAllRoles(ctx)
	if listErr != nil {
		if roleID == "" {
			resp.Diagnostics.AddError("Error Creating IAM Role", "empty role_id and ListAllRoles failed: "+listErr.Error())
			return
		}
		resp.Diagnostics.AddError("Error Reading IAM Role after Create", listErr.Error())
		return
	}

	var item *platformTypes.RoleListItem
	if roleID != "" {
		for i := range listResp.Data {
			if listResp.Data[i].RoleID == roleID {
				item = &listResp.Data[i]
				break
			}
		}
	}

	if item == nil {
		targetName := plan.PrettyName.ValueString()
		for i := range listResp.Data {
			it := &listResp.Data[i]
			if it.PrettyName == targetName {
				if item == nil || it.CreatedTs > item.CreatedTs {
					item = it
				}
			}
		}
	}

	if item == nil {
		if roleID == "" {
			resp.Diagnostics.AddError("Error Creating IAM Role", "empty role_id in create response and cannot locate the role by pretty_name")
		} else {
			resp.Diagnostics.AddError("Error Reading IAM Role after Create", "cannot locate role by role_id: "+roleID)
		}
		return
	}

	plan.RefreshFromRemote(ctx, &resp.Diagnostics, item)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Read refreshes the Terraform state with the latest data.
func (r *iamRoleResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	var state models.IamRoleModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	listResp, err := r.client.ListAllRoles(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Error Reading IAM Role", err.Error())
		return
	}

	var role *platformTypes.RoleListItem
	for _, r := range listResp.Data {
		if r.RoleID == state.ID.ValueString() {
			role = &r
			break
		}
	}

	if role == nil {
		resp.Diagnostics.AddWarning("IAM Role not found", "IAM Role not found, removing from state.")
		resp.State.RemoveResource(ctx)
		return
	}

	state.RefreshFromRemote(ctx, &resp.Diagnostics, role)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *iamRoleResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	// The IAM Role API does not support updates. Therefore, we delete the old role and create a new one.
	var state models.IamRoleModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	err := r.client.DeleteRole(ctx, state.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Error Deleting IAM Role for Update", err.Error())
		return
	}

	var plan models.IamRoleModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var componentPermissions []string
	resp.Diagnostics.Append(plan.ComponentPermissions.ElementsAs(ctx, &componentPermissions, false)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var datasetPermissions []platformTypes.DatasetPermission
	if !plan.DatasetPermissions.IsNull() && !plan.DatasetPermissions.IsUnknown() {
		var dsPermsModels []models.DatasetPermissionModel
		resp.Diagnostics.Append(plan.DatasetPermissions.ElementsAs(ctx, &dsPermsModels, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
		for _, dsPermsModel := range dsPermsModels {
			var permissions []string
			resp.Diagnostics.Append(dsPermsModel.Permissions.ElementsAs(ctx, &permissions, false)...)
			if resp.Diagnostics.HasError() {
				return
			}
			datasetPermissions = append(datasetPermissions, platformTypes.DatasetPermission{
				Category:    dsPermsModel.Category.ValueString(),
				AccessAll:   dsPermsModel.AccessAll.ValueBool(),
				Permissions: permissions,
			})
		}
	}

	createRequest := platformTypes.RoleCreateRequest{
		RequestData: platformTypes.RoleCreateRequestData{
			PrettyName:           plan.PrettyName.ValueString(),
			Description:          plan.Description.ValueString(),
			ComponentPermissions: componentPermissions,
			DatasetPermissions:   datasetPermissions,
		},
	}

	createdRole, err := r.client.CreateRole(ctx, createRequest)
	if err != nil {
		resp.Diagnostics.AddError("Error Creating IAM Role", err.Error())
		return
	}

	item := &platformTypes.RoleListItem{
		RoleID:      createdRole.RoleID,
		PrettyName:  createdRole.PrettyName,
		Description: createdRole.Description,
		IsCustom:    createdRole.IsCustom,
		CreatedBy:   createdRole.CreatedBy,
		CreatedTs:   createdRole.CreatedTs,
		UpdatedTs:   createdRole.UpdatedTs,
	}

	plan.RefreshFromRemote(ctx, &resp.Diagnostics, item)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Delete deletes the resource and removes it from the Terraform state on success.
func (r *iamRoleResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	var state models.IamRoleModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	err := r.client.DeleteRole(ctx, state.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Error Deleting IAM Role", err.Error())
		return
	}
}
