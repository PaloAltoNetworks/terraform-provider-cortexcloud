// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package platform

import (
	"context"

	platformtypes "github.com/PaloAltoNetworks/cortex-cloud-go/types/platform"
	models "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/platform"
	providerModels "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/provider"
	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/util"
	"github.com/hashicorp/terraform-plugin-framework/types"

	platformsdk "github.com/PaloAltoNetworks/cortex-cloud-go/platform"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ resource.Resource                = &scopeResource{}
	_ resource.ResourceWithConfigure   = &scopeResource{}
	_ resource.ResourceWithImportState = &scopeResource{}
)

// NewScopeResource is a helper function to simplify the provider implementation.
func NewScopeResource() resource.Resource {
	return &scopeResource{}
}

// scopeResource is the resource implementation.
type scopeResource struct {
	client *platformsdk.Client
}

// Metadata returns the resource type name.
func (r *scopeResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_scope"
}

// Schema defines the schema for the resource.
func (r *scopeResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a Cortex Cloud scope.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true,
			},
			"entity_type": schema.StringAttribute{
				Description: "The type of the entity.",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"entity_id": schema.StringAttribute{
				Description: "The ID of the entity.",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"assets": schema.SingleNestedAttribute{
				Description: "The assets scope.",
				Optional:    true,
				Attributes: map[string]schema.Attribute{
					"mode": schema.StringAttribute{
						Description: "The mode of the assets scope.",
						Required:    true,
					},
					"asset_groups": schema.ListNestedAttribute{
						Optional: true,
						NestedObject: schema.NestedAttributeObject{
							Attributes: map[string]schema.Attribute{
								"asset_group_id": schema.Int64Attribute{
									Required:    true,
									Description: "Asset group ID.",
								},
								"asset_group_name": schema.StringAttribute{
									Computed:    true,
									Description: "Asset group name (read-only).",
								},
							},
						},
					},
				},
			},
			"datasets_rows": schema.SingleNestedAttribute{
				Description: "The datasets rows scope.",
				Optional:    true,
				Attributes: map[string]schema.Attribute{
					"default_filter_mode": schema.StringAttribute{
						Description: "The default filter mode of the datasets rows scope.",
						Required:    true,
					},
					"filters": schema.ListNestedAttribute{
						Description: "The filters in the datasets rows scope.",
						Optional:    true,
						NestedObject: schema.NestedAttributeObject{
							Attributes: map[string]schema.Attribute{
								"dataset": schema.StringAttribute{
									Description: "The dataset of the filter.",
									Required:    true,
								},
								"filter": schema.StringAttribute{
									Description: "The filter expression.",
									Required:    true,
								},
							},
						},
					},
				},
			},
			"endpoints": schema.SingleNestedAttribute{
				Description: "The endpoints scope.",
				Optional:    true,
				Attributes: map[string]schema.Attribute{
					"endpoint_groups": schema.SingleNestedAttribute{
						Description: "The endpoint groups scope.",
						Optional:    true,
						Attributes: map[string]schema.Attribute{
							"mode": schema.StringAttribute{
								Description: "The mode of the endpoint groups scope.",
								Required:    true,
							},
							"tags": schema.ListNestedAttribute{
								Description: "The tags in the endpoint groups scope.",
								Optional:    true,
								NestedObject: schema.NestedAttributeObject{
									Attributes: map[string]schema.Attribute{
										"tag_id": schema.StringAttribute{
											Description: "The ID of the tag.",
											Computed:    true,
										},
										"tag_name": schema.StringAttribute{
											Description: "The name of the tag.",
											Required:    true,
										},
									},
								},
							},
						},
					},
					"endpoint_tags": schema.SingleNestedAttribute{
						Description: "The endpoint tags scope.",
						Optional:    true,
						Attributes: map[string]schema.Attribute{
							"mode": schema.StringAttribute{
								Description: "The mode of the endpoint tags scope.",
								Required:    true,
							},
							"tags": schema.ListNestedAttribute{
								Description: "The tags in the endpoint tags scope.",
								Optional:    true,
								NestedObject: schema.NestedAttributeObject{
									Attributes: map[string]schema.Attribute{
										"tag_id": schema.StringAttribute{
											Description: "The ID of the tag.",
											Computed:    true,
										},
										"tag_name": schema.StringAttribute{
											Description: "The name of the tag.",
											Required:    true,
										},
									},
								},
							},
						},
					},
				},
			},
			"cases_issues": schema.SingleNestedAttribute{
				Description: "The cases issues scope.",
				Optional:    true,
				Attributes: map[string]schema.Attribute{
					"mode": schema.StringAttribute{
						Description: "The mode of the cases issues scope.",
						Required:    true,
					},
					"tags": schema.ListNestedAttribute{
						Description: "The tags in the cases issues scope.",
						Optional:    true,
						NestedObject: schema.NestedAttributeObject{
							Attributes: map[string]schema.Attribute{
								"tag_id": schema.StringAttribute{
									Description: "The ID of the tag.",
									Computed:    true,
								},
								"tag_name": schema.StringAttribute{
									Description: "The name of the tag.",
									Required:    true,
								},
							},
						},
					},
				},
			},
		},
	}
}

// Configure adds the provider-configured client to the resource.
func (r *scopeResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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
func (r *scopeResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan models.ScopeModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Apply changes via PUT /scope
	request := plan.ToEditRequest()
	if err := r.client.EditScope(ctx, plan.EntityType.ValueString(), plan.EntityID.ValueString(), request); err != nil {
		resp.Diagnostics.AddError("Error creating scope", err.Error())
		return
	}

	// Read back from remote to populate Computed fields (e.g., asset_group_name)
	remote, err := r.client.GetScope(ctx, plan.EntityType.ValueString(), plan.EntityID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Error reading scope after create", err.Error())
		return
	}

	state := plan // start from plan, then hydrate computed fields from remote
	state.RefreshFromRemote(ctx, &resp.Diagnostics, remote)
	if resp.Diagnostics.HasError() {
		return
	}

	// Set Terraform ID as "entity_type:entity_id"
	state.ID = types.StringValue(state.EntityType.ValueString() + ":" + state.EntityID.ValueString())

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Read refreshes the Terraform state with the latest data.
func (r *scopeResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state models.ScopeModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	remote, err := r.client.GetScope(ctx, state.EntityType.ValueString(), state.EntityID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Error reading scope", err.Error())
		return
	}

	state.RefreshFromRemote(ctx, &resp.Diagnostics, remote)
	if resp.Diagnostics.HasError() {
		return
	}

	// Ensure ID is always set on Read as well
	state.ID = types.StringValue(state.EntityType.ValueString() + ":" + state.EntityID.ValueString())

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *scopeResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan models.ScopeModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	request := plan.ToEditRequest()
	if err := r.client.EditScope(ctx, plan.EntityType.ValueString(), plan.EntityID.ValueString(), request); err != nil {
		resp.Diagnostics.AddError("Error updating scope", err.Error())
		return
	}

	// Read back to resolve Computed fields and finalize state
	remote, err := r.client.GetScope(ctx, plan.EntityType.ValueString(), plan.EntityID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Error reading scope after update", err.Error())
		return
	}

	state := plan
	state.RefreshFromRemote(ctx, &resp.Diagnostics, remote)
	if resp.Diagnostics.HasError() {
		return
	}

	state.ID = types.StringValue(state.EntityType.ValueString() + ":" + state.EntityID.ValueString())

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Delete deletes the resource and removes it from the Terraform state on success.
func (r *scopeResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state models.ScopeModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	entityType := state.EntityType.ValueString()
	entityID := state.EntityID.ValueString()

	reset := platformtypes.EditScopeRequestData{
		Assets: &platformtypes.EditAssets{
			Mode:          "see_all",
			AssetGroupIDs: make([]int, 0),
		},
		DatasetsRows: &platformtypes.EditDatasetsRows{
			DefaultFilterMode: "see_all",
			Filters:           make([]platformtypes.Filter, 0),
		},
		Endpoints: &platformtypes.EditEndpoints{
			EndpointGroups: &platformtypes.EditEndpointGroups{
				Mode:  "see_all",
				Names: make([]string, 0),
			},
			EndpointTags: &platformtypes.EditEndpointTags{
				Mode:  "any",
				Names: make([]string, 0),
			},
		},
		CasesIssues: &platformtypes.EditCasesIssues{
			Mode:  "see_all",
			Names: make([]string, 0),
		},
	}

	if err := r.client.EditScope(ctx, entityType, entityID, reset); err != nil {
		resp.Diagnostics.AddError("Error deleting scope", err.Error())
		return
	}

	resp.State.RemoveResource(ctx)
}

// ImportState imports the resource into the Terraform state.
func (r *scopeResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
