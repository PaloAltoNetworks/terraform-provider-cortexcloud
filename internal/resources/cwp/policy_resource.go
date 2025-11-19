// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package cwp

import (
	"context"
	"strconv"

	models "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/cwp"
	providerModels "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/provider"
	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/util"

	cwpSdk "github.com/PaloAltoNetworks/cortex-cloud-go/cwp"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ resource.Resource                = &policyResource{}
	_ resource.ResourceWithConfigure   = &policyResource{}
	_ resource.ResourceWithImportState = &policyResource{}
)

// NewPolicyResource is a helper function to simplify the provider implementation.
func NewPolicyResource() resource.Resource {
	return &policyResource{}
}

// policyResource is the resource implementation.
type policyResource struct {
	client *cwpSdk.Client
}

// Metadata returns the resource type name.
func (r *policyResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cwp_policy"
}

// Schema defines the schema for the resource.
func (r *policyResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a CWP (Cloud Workload Protection) policy.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "The unique identifier of the policy.",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"revision": schema.Int64Attribute{
				Description: "The revision number of the policy.",
				Computed:    true,
			},
			"created_at": schema.StringAttribute{
				Description: "The timestamp when the policy was created.",
				Computed:    true,
			},
			"modified_at": schema.StringAttribute{
				Description: "The timestamp when the policy was last modified.",
				Computed:    true,
			},
			"type": schema.StringAttribute{
				Description: "The type of the policy.",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"created_by": schema.StringAttribute{
				Description: "The user who created the policy.",
				Computed:    true,
			},
			"disabled": schema.BoolAttribute{
				Description: "Whether the policy is disabled.",
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(false),
			},
			"name": schema.StringAttribute{
				Description: "The name of the policy.",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"description": schema.StringAttribute{
				Description: "The description of the policy.",
				Optional:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"evaluation_modes": schema.ListAttribute{
				ElementType: types.StringType,
				Description: "The evaluation modes for the policy.",
				Optional:    true,
				PlanModifiers: []planmodifier.List{
					listplanmodifier.UseStateForUnknown(),
				},
			},
			"evaluation_stage": schema.StringAttribute{
				Description: "The evaluation stage for the policy.",
				Optional:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"rules_ids": schema.ListAttribute{
				ElementType: types.StringType,
				Description: "The list of rule IDs associated with the policy.",
				Optional:    true,
				PlanModifiers: []planmodifier.List{
					listplanmodifier.UseStateForUnknown(),
				},
			},
			"condition": schema.StringAttribute{
				Description: "The condition for the policy.",
				Optional:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"exception": schema.StringAttribute{
				Description: "The exception for the policy.",
				Optional:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"asset_scope": schema.StringAttribute{
				Description: "The asset scope for the policy.",
				Optional:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"asset_group_ids": schema.ListAttribute{
				ElementType: types.Int64Type,
				Description: "The list of asset group IDs associated with the policy.",
				Optional:    true,
				PlanModifiers: []planmodifier.List{
					listplanmodifier.UseStateForUnknown(),
				},
			},
			"asset_groups": schema.ListAttribute{
				ElementType: types.StringType,
				Description: "The list of asset groups associated with the policy.",
				Computed:    true,
			},
			"policy_action": schema.StringAttribute{
				Description: "The action to take when the policy is triggered.",
				Optional:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"policy_severity": schema.StringAttribute{
				Description: "The severity level of the policy.",
				Optional:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"remediation_guidance": schema.StringAttribute{
				Description: "The remediation guidance for the policy.",
				Optional:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
		},
	}
}

// Configure adds the provider-configured client to the resource.
func (r *policyResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(*providerModels.CortexCloudSDKClients)
	if !ok {
		util.AddUnexpectedResourceConfigureTypeError(&resp.Diagnostics, "*providerModels.CortexCloudSDKClients", req.ProviderData)
		return
	}

	r.client = client.CWP
}

// Create creates the resource and sets the initial Terraform state.
func (r *policyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan models.PolicyModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	request := plan.ToCreateRequest()
	createResponse, err := r.client.CreatePolicy(ctx, request)
	if err != nil {
		resp.Diagnostics.AddError("Error creating policy", err.Error())
		return
	}

	// Get the created policy to populate all fields
	policy, err := r.client.GetPolicyByID(ctx, createResponse.Id)
	if err != nil {
		resp.Diagnostics.AddError("Error reading created policy", err.Error())
		return
	}

	plan.RefreshFromRemote(ctx, &resp.Diagnostics, &policy)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Read refreshes the Terraform state with the latest data.
func (r *policyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state models.PolicyModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	policy, err := r.client.GetPolicyByID(ctx, state.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Error reading policy", err.Error())
		return
	}

	state.RefreshFromRemote(ctx, &resp.Diagnostics, &policy)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *policyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan models.PolicyModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var state models.PolicyModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// --- THIS IS THE FIX ---
	// We are removing the entire 'if err != nil { ... }' block
	// that was trying to catch a specific merge error.
	// Now, if the SDK fails, we just fail.

	request := plan.ToUpdateRequest()
	err := r.client.UpdatePolicy(ctx, request)
	if err != nil {
		// If the SDK returns any error, we add it and return.
		resp.Diagnostics.AddError("Error updating Workload Policy", err.Error())
		return
	}
	// --- END FIX ---

	// Get the policy state (whether update succeeded or not)
	policy, err := r.client.GetPolicyByID(ctx, plan.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Error reading policy after update", err.Error())
		return
	}

	plan.RefreshFromRemote(ctx, &resp.Diagnostics, &policy)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Delete deletes the resource and removes it from the Terraform state on success.
func (r *policyResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state models.PolicyModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Convert string ID to int for CWP SDK
	policyID, err := strconv.Atoi(state.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Error converting policy ID", "Could not convert policy ID to integer: "+err.Error())
		return
	}

	err = r.client.DeletePolicy(ctx, policyID, true) // close_issues = true
	if err != nil {
		resp.Diagnostics.AddError("Error deleting policy", err.Error())
		return
	}
}

// ImportState imports the resource into the Terraform state.
func (r *policyResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
