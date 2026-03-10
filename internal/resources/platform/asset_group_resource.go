// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package platform

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	models "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/platform"
	providerModels "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/provider"
	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/util"

	"github.com/PaloAltoNetworks/cortex-cloud-go/enums"
	cortexEnums "github.com/PaloAltoNetworks/cortex-cloud-go/enums"
	"github.com/PaloAltoNetworks/cortex-cloud-go/platform"
	filterTypes "github.com/PaloAltoNetworks/cortex-cloud-go/types/filter"
	platformTypes "github.com/PaloAltoNetworks/cortex-cloud-go/types/platform"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ resource.Resource = &AssetGroupResource{}
)

// NewAssetGroupResource is a helper function to simplify the provider implementation.
func NewAssetGroupResource() resource.Resource {
	return &AssetGroupResource{}
}

// AssetGroupResource is the resource implementation.
type AssetGroupResource struct {
	client *platform.Client
}

// Metadata returns the resource type name.
func (r *AssetGroupResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_asset_group"
}

func (r *AssetGroupResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	rootFilterAttributes := map[string]schema.Attribute{
		"and": schema.ListNestedAttribute{
			Optional: true,
			NestedObject: schema.NestedAttributeObject{
				Attributes: models.GetRecursiveFilterSchema(0, 10),
			},
		},
		"or": schema.ListNestedAttribute{
			Optional: true,
			NestedObject: schema.NestedAttributeObject{
				Attributes: models.GetRecursiveFilterSchema(0, 10),
			},
		},
	}

	resp.Schema = schema.Schema{
		Description: "Manages an asset group.",
		Attributes: map[string]schema.Attribute{
			"id": schema.Int64Attribute{
				Description: "The ID of the asset group.",
				Computed:    true,
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Description: "The name of the asset group.",
				Required:    true,
			},
			"type": schema.StringAttribute{
				Description: fmt.Sprintf("The type of the asset group. Possible values are: \"%s\".\n\nDynamic asset groups use criteria specified in the membership predicate to determine group membership.\n\nStatic asset groups use a set of assets specified by their unique identifier values.", strings.Join(enums.AllAssetGroupTypes(), "\", \"")),
				Required:    true,
				Validators: []validator.String{
					stringvalidator.OneOf(enums.AllAssetGroupTypes()...),
				},
			},
			"description": schema.StringAttribute{
				Description: "The description of the asset group.",
				Optional:    true,
			},
			"membership_predicate": schema.SingleNestedAttribute{
				Description: "The membership predicate for the asset group.",
				Optional:    true,
				Attributes:  rootFilterAttributes,
			},
			"creation_time": schema.Int64Attribute{
				Description: "The timestamp representing when the asset group was created.",
				Computed:    true,
			},
			"created_by": schema.StringAttribute{
				Description: "The user who created the asset group.",
				Computed:    true,
			},
			"last_update_time": schema.Int64Attribute{
				Description: "The timestamp representing when the asset group was last updated.",
				Computed:    true,
			},
			"modified_by": schema.StringAttribute{
				Description: "The user who last modified the asset group.",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
		},
	}
}

// Configure adds the provider-configured client to the resource.
func (r *AssetGroupResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *AssetGroupResource) findAssetGroup(ctx context.Context, id int) (*platformTypes.AssetGroup, error) {
	listReq := platformTypes.ListAssetGroupsRequest{
		Filters: filterTypes.NewSearchFilter(
			"XDM.ASSET_GROUP.ID",
			cortexEnums.SearchTypeEqualTo.String(),
			strconv.Itoa(id),
		),
	}
	assetGroups, err := r.client.ListAssetGroups(ctx, listReq)
	if err != nil {
		return nil, err
	}

	if len(assetGroups) == 1 {
		return &assetGroups[0], nil
	}

	return nil, nil
}

// Create creates the resource and sets the initial Terraform state.
func (r *AssetGroupResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	var plan models.AssetGroupModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	createRequest := plan.ToCreateOrUpdateRequest(ctx, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	success, assetGroupID, err := r.client.CreateAssetGroup(ctx, createRequest)
	if err != nil {
		resp.Diagnostics.AddError("Error Creating Asset Group", err.Error())
		return
	}
	if !success {
		resp.Diagnostics.AddError("Error Creating Asset Group", "API call was not successful")
		return
	}

	assetGroup, err := r.findAssetGroup(ctx, assetGroupID)
	if err != nil {
		resp.Diagnostics.AddError("Error Reading Asset Group", fmt.Sprintf("Error reading asset group after creation: %s", err.Error()))
		return
	}
	if assetGroup == nil {
		resp.Diagnostics.AddError("Error Creating Asset Group", "Could not find the asset group after creation.")
		return
	}

	plan.RefreshFromRemote(ctx, &resp.Diagnostics, assetGroup)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Read refreshes the Terraform state with the latest data.
func (r *AssetGroupResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	var state models.AssetGroupModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	assetGroup, err := r.findAssetGroup(ctx, int(state.ID.ValueInt64()))
	if err != nil {
		resp.Diagnostics.AddError("Error Reading Asset Group", err.Error())
		return
	}

	if assetGroup == nil {
		resp.Diagnostics.AddWarning("Asset Group not found", fmt.Sprintf("No asset group found with ID %d, removing from state.", state.ID.ValueInt64()))
		resp.State.RemoveResource(ctx)
		return
	}

	state.RefreshFromRemote(ctx, &resp.Diagnostics, assetGroup)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *AssetGroupResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	var state models.AssetGroupModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var plan models.AssetGroupModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	updateRequest := plan.ToCreateOrUpdateRequest(ctx, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	success, err := r.client.UpdateAssetGroup(ctx, int(state.ID.ValueInt64()), updateRequest)
	if err != nil {
		resp.Diagnostics.AddError("Error Updating Asset Group", err.Error())
		return
	}
	if !success {
		resp.Diagnostics.AddError("Error Updating Asset Group", "API call was not successful")
		return
	}

	assetGroup, err := r.findAssetGroup(ctx, int(state.ID.ValueInt64()))
	if err != nil {
		resp.Diagnostics.AddError("Error Reading Asset Group", fmt.Sprintf("Error reading asset group after update: %s", err.Error()))
		return
	}

	if assetGroup == nil {
		resp.Diagnostics.AddError("Error Updating Asset Group", "Could not find the asset group after update.")
		return
	}

	plan.RefreshFromRemote(ctx, &resp.Diagnostics, assetGroup)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Delete deletes the resource and removes it from the Terraform state on success.
func (r *AssetGroupResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	var state models.AssetGroupModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	success, err := r.client.DeleteAssetGroup(ctx, int(state.ID.ValueInt64()))
	if err != nil {
		resp.Diagnostics.AddError("Error Deleting Asset Group", err.Error())
		return
	}
	if !success {
		resp.Diagnostics.AddError("Error Deleting Asset Group", "API call was not successful")
		return
	}
}
