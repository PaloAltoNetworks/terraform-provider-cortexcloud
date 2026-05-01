// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package compliance

import (
	"context"

	"github.com/PaloAltoNetworks/cortex-cloud-go/compliance"
	complianceTypes "github.com/PaloAltoNetworks/cortex-cloud-go/types/compliance"
	complianceModels "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/compliance"
	providerModels "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/provider"
	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/util"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ resource.Resource                = &standardResource{}
	_ resource.ResourceWithConfigure   = &standardResource{}
	_ resource.ResourceWithImportState = &standardResource{}
)

// NewStandardResource is a helper function to simplify the provider implementation.
func NewStandardResource() resource.Resource {
	return &standardResource{}
}

// standardResource is the resource implementation.
type standardResource struct {
	client *compliance.Client
}

// Metadata returns the resource type name.
func (r *standardResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_compliance_standard"
}

// Schema defines the schema for the resource.
func (r *standardResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a compliance standard.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "The ID of the compliance standard.",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Description: "The name of the compliance standard.",
				Required:    true,
			},
			"description": schema.StringAttribute{
				Description: "The description of the compliance standard.",
				Optional:    true,
			},
			"version": schema.StringAttribute{
				Description: "The version of the compliance standard.",
				Computed:    true,
			},
			"assessments_profiles_count": schema.Int64Attribute{
				Description: "The number of assessment profiles using this standard.",
				Computed:    true,
			},
			"controls_ids": schema.SetAttribute{
				Description: "The set of control IDs associated with this standard.",
				Optional:    true,
				ElementType: types.StringType,
			},
			"labels": schema.SetAttribute{
				Description: "The set of labels for this standard.",
				Optional:    true,
				ElementType: types.StringType,
			},
			"revision": schema.Int64Attribute{
				Description: "The revision number of the standard. This value increments on every update.",
				Computed:    true,
				// No plan modifiers - revision changes on update
			},
			"publisher": schema.StringAttribute{
				Description: "The publisher of the standard.",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"release_date": schema.StringAttribute{
				Description: "The release date of the standard.",
				Computed:    true,
			},
			"created_date": schema.StringAttribute{
				Description: "The creation date of the standard.",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"created_by": schema.StringAttribute{
				Description: "The user who created the standard.",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"insert_ts": schema.Int64Attribute{
				Description: "The insertion timestamp.",
				Computed:    true,
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.UseStateForUnknown(),
				},
			},
			"modify_ts": schema.Int64Attribute{
				Description: "The modification timestamp.",
				Computed:    true,
			},
			"is_custom": schema.BoolAttribute{
				Description: "Whether the standard is custom.",
				Computed:    true,
				PlanModifiers: []planmodifier.Bool{
					boolplanmodifier.UseStateForUnknown(),
				},
			},
		},
	}
}

// Configure adds the provider-configured client to the resource.
func (r *standardResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(*providerModels.CortexCloudSDKClients)
	if !ok {
		util.AddUnexpectedResourceConfigurationTypeError(&resp.Diagnostics, "*providerModels.CortexCloudSDKClients", req.ProviderData)
		return
	}

	r.client = client.Compliance
}

// Create creates the resource and sets the initial Terraform state.
func (r *standardResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	var plan complianceModels.StandardModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Convert plan to create request
	createReq := plan.ToCreateRequest(ctx, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	// Create the standard
	success, err := r.client.CreateStandard(ctx, createReq)
	if err != nil {
		resp.Diagnostics.AddError("Error Creating Compliance Standard", err.Error())
		return
	}
	if !success {
		resp.Diagnostics.AddError("Error Creating Compliance Standard", "API call was not successful")
		return
	}

	// The API doesn't return the ID, so we need to list standards to find it
	listReq := complianceTypes.ListStandardsRequest{
		Filters: []complianceTypes.Filter{
			{
				Field:    "name",
				Operator: "eq",
				Value:    plan.Name.ValueString(),
			},
		},
	}

	listResp, err := r.client.ListStandards(ctx, listReq)
	if err != nil {
		resp.Diagnostics.AddError("Error Reading Compliance Standard After Create", err.Error())
		return
	}

	if len(listResp.Standards) == 0 {
		resp.Diagnostics.AddError("Error Creating Compliance Standard", "Could not find the standard after creation.")
		return
	}

	// Get the most recently created standard
	remote := &listResp.Standards[0]

	// Update plan with remote data
	plan.RefreshFromRemote(ctx, &resp.Diagnostics, remote)
	if resp.Diagnostics.HasError() {
		return
	}

	// Set state
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Read refreshes the Terraform state with the latest data.
func (r *standardResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	var state complianceModels.StandardModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Get the standard from the API
	getReq := complianceTypes.GetStandardRequest{
		ID: state.ID.ValueString(),
	}

	remote, err := r.client.GetStandard(ctx, getReq)
	if err != nil {
		// If the standard doesn't exist, remove it from state
		resp.Diagnostics.AddWarning("Compliance Standard Not Found", "Removing from state.")
		resp.State.RemoveResource(ctx)
		return
	}

	// Update state with remote data
	state.RefreshFromRemote(ctx, &resp.Diagnostics, remote)
	if resp.Diagnostics.HasError() {
		return
	}

	// Set state
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *standardResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	var plan complianceModels.StandardModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Convert plan to update request
	updateReq := plan.ToUpdateRequest(ctx, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	// Update the standard
	success, err := r.client.UpdateStandard(ctx, updateReq)
	if err != nil {
		resp.Diagnostics.AddError("Error Updating Compliance Standard", err.Error())
		return
	}
	if !success {
		resp.Diagnostics.AddError("Error Updating Compliance Standard", "API call was not successful")
		return
	}

	// Read back the updated standard
	getReq := complianceTypes.GetStandardRequest{
		ID: plan.ID.ValueString(),
	}

	remote, err := r.client.GetStandard(ctx, getReq)
	if err != nil {
		resp.Diagnostics.AddError("Error Reading Compliance Standard After Update", err.Error())
		return
	}

	// Update plan with remote data
	plan.RefreshFromRemote(ctx, &resp.Diagnostics, remote)
	if resp.Diagnostics.HasError() {
		return
	}

	// Set state
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Delete deletes the resource and removes the Terraform state on success.
func (r *standardResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	var state complianceModels.StandardModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Delete the standard
	deleteReq := complianceTypes.DeleteStandardRequest{
		ID: state.ID.ValueString(),
	}

	success, err := r.client.DeleteStandard(ctx, deleteReq)
	if err != nil {
		resp.Diagnostics.AddError("Error Deleting Compliance Standard", err.Error())
		return
	}

	if !success {
		resp.Diagnostics.AddError("Error Deleting Compliance Standard", "API call was not successful")
		return
	}
}

// ImportState imports the resource into Terraform state.
func (r *standardResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// Use the ID from the import request
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
