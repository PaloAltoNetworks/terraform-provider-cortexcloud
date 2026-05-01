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
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ resource.Resource                = &assessmentProfileResource{}
	_ resource.ResourceWithConfigure   = &assessmentProfileResource{}
	_ resource.ResourceWithImportState = &assessmentProfileResource{}
)

// NewAssessmentProfileResource is a helper function to simplify the provider implementation.
func NewAssessmentProfileResource() resource.Resource {
	return &assessmentProfileResource{}
}

// assessmentProfileResource is the resource implementation.
type assessmentProfileResource struct {
	client *compliance.Client
}

// Metadata returns the resource type name.
func (r *assessmentProfileResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_compliance_assessment_profile"
}

// Schema defines the schema for the resource.
func (r *assessmentProfileResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a compliance assessment profile.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "The ID of the assessment profile.",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Description: "The name of the assessment profile.",
				Required:    true,
			},
			"standard_id": schema.StringAttribute{
				Description: "The ID of the compliance standard to assess against.",
				Required:    true,
			},
			"standard_name": schema.StringAttribute{
				Description: "The name of the compliance standard.",
				Computed:    true,
			},
			"asset_group_id": schema.Int64Attribute{
				Description: "The ID of the asset group to assess.",
				Required:    true,
			},
			"asset_group_name": schema.StringAttribute{
				Description: "The name of the asset group.",
				Computed:    true,
			},
			"description": schema.StringAttribute{
				Description: "The description of the assessment profile.",
				Optional:    true,
			},
			"report_frequency": schema.StringAttribute{
				Description: "The frequency for generating reports (cron format). Required when report_type is not 'NONE'.",
				Optional:    true,
			},
			"report_targets": schema.ListAttribute{
				Description: "The list of email addresses to send reports to. Required when report_type is not 'NONE'.",
				Optional:    true,
				ElementType: types.StringType,
			},
			"report_type": schema.StringAttribute{
				Description: "The type of report to generate (e.g., 'PDF', 'CSV', 'NONE').",
				Optional:    true,
			},
			"enabled": schema.BoolAttribute{
				Description: "Whether the assessment profile is enabled. Defaults to true. Note: The API only supports changing this field on update, not on initial creation.",
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(true),
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
			"created_by": schema.StringAttribute{
				Description: "The user who created the assessment profile.",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"modified_by": schema.StringAttribute{
				Description: "The user who last modified the assessment profile.",
				Computed:    true,
			},
		},
	}
}

// Configure adds the provider-configured client to the resource.
func (r *assessmentProfileResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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
func (r *assessmentProfileResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	var plan complianceModels.AssessmentProfileModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Convert plan to create request
	createReq := plan.ToCreateRequest(ctx, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	// Create the assessment profile
	success, err := r.client.CreateAssessmentProfile(ctx, createReq)
	if err != nil {
		resp.Diagnostics.AddError("Error Creating Compliance Assessment Profile", err.Error())
		return
	}
	if !success {
		resp.Diagnostics.AddError("Error Creating Compliance Assessment Profile", "API call was not successful")
		return
	}

	// The API doesn't return the ID, so we need to list profiles to find it
	listReq := complianceTypes.ListAssessmentProfilesRequest{
		Filters: []complianceTypes.Filter{
			{
				Field:    "NAME",
				Operator: "eq",
				Value:    plan.Name.ValueString(),
			},
		},
	}

	listResp, err := r.client.ListAssessmentProfiles(ctx, listReq)
	if err != nil {
		resp.Diagnostics.AddError("Error Reading Compliance Assessment Profile After Create", err.Error())
		return
	}

	if len(listResp.AssessmentProfiles) == 0 {
		resp.Diagnostics.AddError("Error Creating Compliance Assessment Profile", "Could not find the assessment profile after creation.")
		return
	}

	// Get the most recently created profile
	remote := &listResp.AssessmentProfiles[0]

	// If the user set enabled = false, we need to update the profile after creation
	// because the create API does not support the enabled field.
	if !plan.Enabled.IsNull() && !plan.Enabled.IsUnknown() && !plan.Enabled.ValueBool() {
		plan.ID = types.StringValue(remote.ID)
		updateReq := plan.ToUpdateRequest(ctx, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}

		success, err = r.client.UpdateAssessmentProfile(ctx, updateReq)
		if err != nil {
			resp.Diagnostics.AddError("Error Disabling Compliance Assessment Profile After Create",
				"The profile was created but could not be disabled: "+err.Error())
			return
		}
		if !success {
			resp.Diagnostics.AddError("Error Disabling Compliance Assessment Profile After Create",
				"The profile was created but the update to disable it was not successful")
			return
		}

		// Re-read the profile after the update
		getReq := complianceTypes.GetAssessmentProfileRequest{
			ID: remote.ID,
		}
		updatedRemote, err := r.client.GetAssessmentProfile(ctx, getReq)
		if err != nil {
			resp.Diagnostics.AddError("Error Reading Compliance Assessment Profile After Disable", err.Error())
			return
		}
		remote = updatedRemote
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
func (r *assessmentProfileResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	var state complianceModels.AssessmentProfileModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Get the assessment profile from the API
	getReq := complianceTypes.GetAssessmentProfileRequest{
		ID: state.ID.ValueString(),
	}

	remote, err := r.client.GetAssessmentProfile(ctx, getReq)
	if err != nil {
		// If the profile doesn't exist, remove it from state
		resp.Diagnostics.AddWarning("Compliance Assessment Profile Not Found", "Removing from state.")
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
func (r *assessmentProfileResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	var plan complianceModels.AssessmentProfileModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Convert plan to update request
	updateReq := plan.ToUpdateRequest(ctx, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	// Update the assessment profile
	success, err := r.client.UpdateAssessmentProfile(ctx, updateReq)
	if err != nil {
		resp.Diagnostics.AddError("Error Updating Compliance Assessment Profile", err.Error())
		return
	}
	if !success {
		resp.Diagnostics.AddError("Error Updating Compliance Assessment Profile", "API call was not successful")
		return
	}

	// Read back the updated profile
	getReq := complianceTypes.GetAssessmentProfileRequest{
		ID: plan.ID.ValueString(),
	}

	remote, err := r.client.GetAssessmentProfile(ctx, getReq)
	if err != nil {
		resp.Diagnostics.AddError("Error Reading Compliance Assessment Profile After Update", err.Error())
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
func (r *assessmentProfileResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	var state complianceModels.AssessmentProfileModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Delete the assessment profile
	deleteReq := complianceTypes.DeleteAssessmentProfileRequest{
		ID: state.ID.ValueString(),
	}

	success, err := r.client.DeleteAssessmentProfile(ctx, deleteReq)
	if err != nil {
		resp.Diagnostics.AddError("Error Deleting Compliance Assessment Profile", err.Error())
		return
	}

	if !success {
		resp.Diagnostics.AddError("Error Deleting Compliance Assessment Profile", "API call was not successful")
		return
	}
}

// ImportState imports the resource into Terraform state.
func (r *assessmentProfileResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// Use the ID from the import request
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
