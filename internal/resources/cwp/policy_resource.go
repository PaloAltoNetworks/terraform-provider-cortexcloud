// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

// Package cwp provides Terraform resources for Cloud Workload Protection policies.
package cwp

import (
	"context"
	"fmt"
	"strings"

	"github.com/PaloAltoNetworks/cortex-cloud-go/cwp"
	"github.com/PaloAltoNetworks/cortex-cloud-go/enums"
	cwpModels "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/cwp"
	models "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/provider"
	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/util"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
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
	client *cwp.Client
}

// Metadata returns the resource type name.
func (r *policyResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cwp_policy"
}

// Schema defines the schema for the resource.
func (r *policyResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a Cloud Workload Protection (CWP) policy. \n\nCWP policies help prevent and manage security violations in cloud runtime instances by applying detection logic to specific asset groups at desired SDLC stages.\n\nNote: When this resource is deleted, any issues connected to the deleted policy will NOT be closed.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "The ID of the CWP policy.",
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
				Description: "The timestamp when the policy was created. Note: Due to an API limitation, this value may change when the policy is updated.",
				Computed:    true,
			},
			"modified_at": schema.StringAttribute{
				Description: "The timestamp when the policy was last modified.",
				Computed:    true,
			},
			"type": schema.StringAttribute{
				Description: fmt.Sprintf("The policy's type. Possible values are: \"%s\".", strings.Join(enums.AllPolicyTypes(), "\", \"")),
				Required:    true,
			},
			"created_by": schema.StringAttribute{
				Description: "The user who created the policy. Note: Due to an API limitation, this field may be empty for policies created via the API.",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"disabled": schema.BoolAttribute{
				Description: "Whether the policy is disabled. Note: This field is read-only because the API does not currently honor this value on create or update operations.",
				Computed:    true,
			},
			"name": schema.StringAttribute{
				Description: "The name of the CWP policy.",
				Required:    true,
			},
			"description": schema.StringAttribute{
				Description: "The description of the CWP policy.",
				Optional:    true,
				Computed:    true,
				Default:     stringdefault.StaticString(""),
			},
			"evaluation_modes": schema.ListAttribute{
				Description: "The evaluation modes for the policy.",
				Optional:    true,
				ElementType: types.StringType,
			},
			"evaluation_stage": schema.StringAttribute{
				Description: fmt.Sprintf("The evaluation stage for the policy. Possible values are: \"%s\".", strings.Join(enums.AllEvaluationStages(), "\", \"")),
				Required:    true,
			},
			"policy_rules": schema.ListNestedAttribute{
				Description: "The CWP rules attached to the policy.",
				Required:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"action": schema.StringAttribute{
							Description: fmt.Sprintf("The CWP rule's action. Possible values are: \"%s\".", strings.Join(enums.AllPolicyActions(), "\", \"")),
							Required:    true,
						},
						"id": schema.StringAttribute{
							Description: "The policy rule's ID.\n\nThis value differs from the rule_id value, which is the unique ID of the individual CWP rule.",
							Computed:    true,
						},
						"policy_id": schema.StringAttribute{
							Description: "The ID of the underlying policy.",
							Computed:    true,
						},
						"policy_revision": schema.Int32Attribute{
							Description: "The revision of the underlying policy.",
							Computed:    true,
						},
						"remediation_guidance": schema.StringAttribute{
							Description: "The remediation steps for the underlying policy.",
							Computed:    true,
						},
						"rule_id": schema.StringAttribute{
							Description: "The ID of the CWP rule.",
							Required:    true,
						},
						"rule_name": schema.StringAttribute{
							Description: "The name of the CWP rule.",
							Computed:    true,
						},
						"severity": schema.StringAttribute{
							Description: "The severity of the CWP rule.",
							Required:    true,
						},
						"user_remediation_guidance": schema.StringAttribute{
							Description: "The procedure to remediate the issue captured by the CWP rule.",
							Optional:    true,
							Computed:    true,
							Default:     stringdefault.StaticString(""),
						},
					},
				},
			},
			"condition": schema.StringAttribute{
				Description: "The condition in blob form (base64 encoded). Required for non-compliance policies.",
				Optional:    true,
				Computed:    true,
			},
			"exception": schema.StringAttribute{
				Description: "The exception in blob form (base64 encoded).",
				Optional:    true,
				Computed:    true,
			},
			"asset_scope": schema.StringAttribute{
				Description: "The asset scope in blob form (base64 encoded).",
				Optional:    true,
				Computed:    true,
			},
			"asset_group_ids": schema.ListAttribute{
				Description: "The IDs of the asset groups that this policy applies to.",
				Required:    true,
				ElementType: types.Int64Type,
			},
			"asset_groups": schema.ListAttribute{
				Description: "The asset group names (computed from asset_group_ids).",
				Computed:    true,
				ElementType: types.StringType,
			},
			"action": schema.StringAttribute{
				Description: "The policy's action. \n\nThis will be set according to the actions configured for the attached rules. The \"Prevent\" action takes precedence over the \"Issue\" action.",
				Computed:    true,
			},
			"severity": schema.StringAttribute{
				Description: "The policy's severity level. \n\nThis will be set according to the highest severity level in the attached rules.",
				Computed:    true,
			},
			"remediation_guidance": schema.StringAttribute{
				Description: "Remediation guidance for the policy.",
				Optional:    true,
				Computed:    true,
				Default:     stringdefault.StaticString(""),
			},
		},
	}
}

// Configure adds the provider-configured client to the resource.
func (r *policyResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(*models.CortexCloudSDKClients)
	if !ok {
		util.AddUnexpectedResourceConfigurationTypeError(&resp.Diagnostics, "*models.CortexCloudSDKClients", req.ProviderData)
		return
	}

	r.client = client.CWP
}

// Create creates the resource and sets the initial Terraform state.
func (r *policyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	var plan cwpModels.PolicyModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Convert plan to create request
	createReq := plan.ToCreateRequest(ctx, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	// Create the policy
	result, err := r.client.CreatePolicy(ctx, createReq)
	if err != nil {
		resp.Diagnostics.AddError("Error Creating CWP Policy", err.Error())
		return
	}

	// Read back the created policy to get computed fields
	remote, err := r.client.GetPolicyByID(ctx, result.PolicyID)
	if err != nil {
		resp.Diagnostics.AddError("Error Fetching CWP Policy After Create", err.Error())
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
func (r *policyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	var state cwpModels.PolicyModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Get the policy from the API
	remote, err := r.client.GetPolicyByID(ctx, state.ID.ValueString())
	if err != nil {
		// If the policy doesn't exist, remove it from state
		resp.Diagnostics.AddWarning("CWP Policy Not Found", "Removing from state.")
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
func (r *policyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	var plan cwpModels.PolicyModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Convert plan to update request
	updateReq := plan.ToUpdateRequest(ctx, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	// Update the policy
	err := r.client.UpdatePolicy(ctx, plan.ID.ValueString(), updateReq)
	if err != nil {
		resp.Diagnostics.AddError("Error Updating CWP Policy", err.Error())
		return
	}

	// Read back the updated policy to get computed fields
	remote, err := r.client.GetPolicyByID(ctx, plan.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Error Fetching CWP Policy After Update", err.Error())
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
func (r *policyResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	var state cwpModels.PolicyModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Delete the policy (closeIssues = false by default)
	err := r.client.DeletePolicy(ctx, state.ID.ValueString(), false)
	if err != nil {
		resp.Diagnostics.AddError("Error Deleting CWP Policy", err.Error())
		return
	}
}

// ImportState imports the resource into Terraform state.
func (r *policyResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// Use the ID from the import request
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
