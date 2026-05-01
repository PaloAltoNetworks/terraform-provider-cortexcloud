// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package appsec

import (
	"context"

	"github.com/PaloAltoNetworks/cortex-cloud-go/appsec"
	appsecModels "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/appsec"
	providerModels "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/provider"
	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/util"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource                = &ruleResource{}
	_ resource.ResourceWithConfigure   = &ruleResource{}
	_ resource.ResourceWithImportState = &ruleResource{}
)

func NewRuleResource() resource.Resource {
	return &ruleResource{}
}

type ruleResource struct {
	client *appsec.Client
}

func (r *ruleResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_appsec_rule"
}

func (r *ruleResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages an Application Security rule.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "Unique identifier for the rule.",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Description: "A unique name for the Appsec rule.",
				Required:    true,
			},
			"severity": schema.StringAttribute{
				Description: "The severity level of the rule (CRITICAL, HIGH, MEDIUM, LOW).",
				Required:    true,
			},
			"scanner": schema.StringAttribute{
				Description: "The type of security scanner used to detect findings of this rule. Allowed values: IAC or SECRETS.",
				Required:    true,
			},
			"category": schema.StringAttribute{
				Description: "Custom rule IaC category.",
				Required:    true,
			},
			"sub_category": schema.StringAttribute{
				Description: "Custom rule subcategory.",
				Required:    true,
			},
			"description": schema.StringAttribute{
				Description: "The rule description.",
				Required:    true,
			},
			"labels": schema.ListAttribute{
				Description: "Labels to be assigned to the rule.",
				Optional:    true,
				ElementType: types.StringType,
			},
			"is_custom": schema.BoolAttribute{
				Description: "Indicates whether the rule is custom.",
				Computed:    true,
				PlanModifiers: []planmodifier.Bool{
					boolplanmodifier.UseStateForUnknown(),
				},
			},
			"is_enabled": schema.BoolAttribute{
				Description: "Indicates whether the rule is enabled.",
				Computed:    true,
			},
			"cloud_provider": schema.StringAttribute{
				Description: "The cloud provider.",
				Computed:    true,
			},
			"domain": schema.StringAttribute{
				Description: "The domain associated with the rule.",
				Computed:    true,
			},
			"finding_category": schema.StringAttribute{
				Description: "The finding category.",
				Computed:    true,
			},
			"created_at": schema.StringAttribute{
				Description: "The timestamp when the rule was created.",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"updated_at": schema.StringAttribute{
				Description: "The timestamp when the rule was updated.",
				Computed:    true,
			},
		},
		Blocks: map[string]schema.Block{
			"frameworks": schema.ListNestedBlock{
				Description: "The framework or language that the Application Security rule applies to.",
				NestedObject: schema.NestedBlockObject{
					Attributes: map[string]schema.Attribute{
						"name": schema.StringAttribute{
							Description: "Name of the configured frameworks.",
							Required:    true,
						},
						"definition": schema.StringAttribute{
							Description: "The rule definition.",
							Required:    true,
						},
						"definition_link": schema.StringAttribute{
							Description: "HTTP link to the definition documentation.",
							Optional:    true,
						},
						"remediation_description": schema.StringAttribute{
							Description: "The remediation steps that will appear on the rule's findings.",
							Optional:    true,
						},
					},
				},
			},
		},
	}
}

func (r *ruleResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(*providerModels.CortexCloudSDKClients)
	if !ok {
		util.AddUnexpectedResourceConfigurationTypeError(&resp.Diagnostics, "*providerModels.CortexCloudSDKClients", req.ProviderData)
		return
	}

	r.client = client.AppSec
}

func (r *ruleResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	var plan appsecModels.RuleModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	createReq := plan.ToCreateRequest(ctx, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	result, err := r.client.CreateOrClone(ctx, createReq)
	if err != nil {
		resp.Diagnostics.AddError("Error Creating AppSec Rule", err.Error())
		return
	}

	plan.RefreshFromRemote(ctx, &resp.Diagnostics, &result)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *ruleResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	var state appsecModels.RuleModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	remote, err := r.client.Get(ctx, state.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddWarning("AppSec Rule Not Found", "Removing from state.")
		resp.State.RemoveResource(ctx)
		return
	}

	state.RefreshFromRemote(ctx, &resp.Diagnostics, &remote)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *ruleResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	var plan appsecModels.RuleModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Check if this is an OOB rule - only labels can be updated
	if !plan.IsCustom.ValueBool() {
		resp.Diagnostics.AddWarning(
			"Limited Update for OOB Rule",
			"Out-of-box rules can only have their labels updated. Other fields will be ignored.",
		)
	}

	updateReq := plan.ToUpdateRequest(ctx, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	updateResp, err := r.client.Update(ctx, plan.ID.ValueString(), updateReq)
	if err != nil {
		resp.Diagnostics.AddError("Error Updating AppSec Rule", err.Error())
		return
	}

	plan.RefreshFromRemote(ctx, &resp.Diagnostics, &updateResp.Rule)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *ruleResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	var state appsecModels.RuleModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	err := r.client.Delete(ctx, state.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Error Deleting AppSec Rule", err.Error())
		return
	}
}

func (r *ruleResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
