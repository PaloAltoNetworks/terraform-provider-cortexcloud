// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package compliance

import (
	"context"
	"fmt"

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
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ resource.Resource                = &controlResource{}
	_ resource.ResourceWithConfigure   = &controlResource{}
	_ resource.ResourceWithImportState = &controlResource{}
)

// NewControlResource is a helper function to simplify the provider implementation.
func NewControlResource() resource.Resource {
	return &controlResource{}
}

// controlResource is the resource implementation.
type controlResource struct {
	client *compliance.Client
}

// Metadata returns the resource type name.
func (r *controlResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_compliance_control"
}

// Schema defines the schema for the resource.
func (r *controlResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a compliance control.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "The ID of the compliance control.",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Description: "The name of the compliance control.",
				Required:    true,
			},
			"description": schema.StringAttribute{
				Description: "The description of the compliance control.",
				Optional:    true,
			},
			"category": schema.StringAttribute{
				Description: "The category of the compliance control.",
				Required:    true,
			},
			"category_description": schema.StringAttribute{
				Description: "The description of the category.",
				Computed:    true,
			},
			"subcategory": schema.StringAttribute{
				Description: "The subcategory of the compliance control. Defaults to an empty string if not specified.",
				Optional:    true,
				Computed:    true,
				Default:     stringdefault.StaticString(""),
			},
			"subcategory_description": schema.StringAttribute{
				Description: "The description of the subcategory.",
				Computed:    true,
			},
			"standards": schema.ListAttribute{
				Description: "The list of standards this control belongs to.",
				Computed:    true,
				ElementType: types.StringType,
			},
			"severity": schema.StringAttribute{
				Description: "The severity level of the control.",
				Computed:    true,
			},
			"supported": schema.BoolAttribute{
				Description: "Whether the control is supported.",
				Computed:    true,
				PlanModifiers: []planmodifier.Bool{
					boolplanmodifier.UseStateForUnknown(),
				},
			},
			"insertion_time": schema.Int64Attribute{
				Description: "The insertion timestamp of the control.",
				Computed:    true,
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.UseStateForUnknown(),
				},
			},
			"modification_time": schema.Int64Attribute{
				Description: "The modification timestamp of the control.",
				Computed:    true,
			},
			"modified_by": schema.StringAttribute{
				Description: "The user who last modified the control.",
				Computed:    true,
			},
			"created_by": schema.StringAttribute{
				Description: "The user who created the control.",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"enabled": schema.BoolAttribute{
				Description: "Whether the control is enabled.",
				Computed:    true,
			},
			"is_custom": schema.BoolAttribute{
				Description: "Whether the control is custom.",
				Computed:    true,
				PlanModifiers: []planmodifier.Bool{
					boolplanmodifier.UseStateForUnknown(),
				},
			},
		},
	}
}

// Configure adds the provider-configured client to the resource.
func (r *controlResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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
func (r *controlResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	var plan complianceModels.ControlModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Convert plan to create request
	createReq := plan.ToCreateRequest(ctx, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	// Create the control
	result, err := r.client.CreateControl(ctx, createReq)
	if err != nil {
		resp.Diagnostics.AddError("Error Creating Compliance Control", err.Error())
		return
	}
	if !result.Success {
		resp.Diagnostics.AddError("Error Creating Compliance Control", "API call was not successful")
		return
	}

	// Read back the created control using the returned ID
	getReq := complianceTypes.GetControlRequest{
		ID: result.ControlID,
	}

	remote, err := r.client.GetControl(ctx, getReq)
	if err != nil {
		resp.Diagnostics.AddError("Error Reading Compliance Control After Create", err.Error())
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

// Read refreshes the Terraform state with the latest data.
func (r *controlResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	var state complianceModels.ControlModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Get the control from the API
	getReq := complianceTypes.GetControlRequest{
		ID: state.ID.ValueString(),
	}

	remote, err := r.client.GetControl(ctx, getReq)
	if err != nil {
		// If the control doesn't exist, remove it from state
		resp.Diagnostics.AddWarning("Compliance Control Not Found", "Removing from state.")
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
func (r *controlResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	var plan complianceModels.ControlModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Verify the control exists before attempting update.
	// The edit_control API silently creates a new control if the ID doesn't exist,
	// so we must check existence first to prevent phantom resource creation.
	existsReq := complianceTypes.GetControlRequest{
		ID: plan.ID.ValueString(),
	}
	_, err := r.client.GetControl(ctx, existsReq)
	if err != nil {
		resp.Diagnostics.AddError(
			"Compliance Control Not Found",
			fmt.Sprintf("Cannot update compliance control with ID %q: the resource no longer exists. %s", plan.ID.ValueString(), err.Error()),
		)
		return
	}

	// Convert plan to update request
	updateReq := plan.ToUpdateRequest(ctx, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	// Update the control
	success, err := r.client.UpdateControl(ctx, updateReq)
	if err != nil {
		resp.Diagnostics.AddError("Error Updating Compliance Control", err.Error())
		return
	}
	if !success {
		resp.Diagnostics.AddError("Error Updating Compliance Control", "API call was not successful")
		return
	}

	// Read back the updated control
	getReq := complianceTypes.GetControlRequest{
		ID: plan.ID.ValueString(),
	}

	remote, err := r.client.GetControl(ctx, getReq)
	if err != nil {
		resp.Diagnostics.AddError("Error Reading Compliance Control After Update", err.Error())
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
func (r *controlResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	var state complianceModels.ControlModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Delete the control
	deleteReq := complianceTypes.DeleteControlRequest{
		ID: state.ID.ValueString(),
	}

	success, err := r.client.DeleteControl(ctx, deleteReq)
	if err != nil {
		resp.Diagnostics.AddError("Error Deleting Compliance Control", err.Error())
		return
	}

	if !success {
		resp.Diagnostics.AddError("Error Deleting Compliance Control", "API call was not successful")
		return
	}
}

// ImportState imports the resource into Terraform state.
func (r *controlResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// Use the ID from the import request
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
