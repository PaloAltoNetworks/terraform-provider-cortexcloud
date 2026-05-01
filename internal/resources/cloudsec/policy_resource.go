// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package cloudsec

import (
	"context"
	"fmt"
	"strings"

	"github.com/PaloAltoNetworks/cortex-cloud-go/cloudsec"
	cloudsecTypes "github.com/PaloAltoNetworks/cortex-cloud-go/types/cloudsec"
	cloudsecModels "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/cloudsec"
	providerModels "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/provider"
	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/util"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"

	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ resource.Resource                   = &CloudSecPolicyResource{}
	_ resource.ResourceWithImportState    = &CloudSecPolicyResource{}
	_ resource.ResourceWithValidateConfig = &CloudSecPolicyResource{}
)

// NewCloudSecPolicyResource is a helper function to simplify the provider implementation.
func NewCloudSecPolicyResource() resource.Resource {
	return &CloudSecPolicyResource{}
}

// CloudSecPolicyResource is the resource implementation.
type CloudSecPolicyResource struct {
	client *cloudsec.Client
}

// Metadata returns the resource type name.
func (r *CloudSecPolicyResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cloudsec_policy"
}

// getFilterCriteriaSchema returns the recursive filter criteria schema.
func getFilterCriteriaSchema(depth int, maxDepth int) map[string]schema.Attribute {
	attrs := map[string]schema.Attribute{
		"operator": schema.StringAttribute{
			Description: "Logical operator for combining criteria (AND or OR). Required when criteria is provided.",
			Optional:    true,
			Validators: []validator.String{
				stringvalidator.OneOf("AND", "OR"),
			},
		},
		"field": schema.StringAttribute{
			Description: "Field name to filter on (e.g., 'severity', 'cloudType'). Required for leaf nodes.",
			Optional:    true,
		},
		"type": schema.StringAttribute{
			Description: "Filter operation type. Required for leaf nodes.",
			Optional:    true,
			Validators: []validator.String{
				stringvalidator.OneOf("EQ", "NEQ", "CONTAINS", "NCONTAINS", "ARRAY_CONTAINS"),
			},
		},
		"value": schema.StringAttribute{
			Description: "Value to filter for. Required for leaf nodes.",
			Optional:    true,
		},
	}

	// Add recursive criteria list if we haven't reached max depth
	if depth < maxDepth {
		attrs["criteria"] = schema.ListNestedAttribute{
			Description: "List of nested filter criteria. Required when operator is provided.",
			Optional:    true,
			NestedObject: schema.NestedAttributeObject{
				Attributes: getFilterCriteriaSchema(depth+1, maxDepth),
			},
		}
	}

	return attrs
}

// Schema defines the schema for the resource.
func (r *CloudSecPolicyResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a CloudSec policy that associates detection rules with assets.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "Unique identifier of the policy (UUID format).",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Description: "Unique policy name.",
				Required:    true,
			},
			"description": schema.StringAttribute{
				Description: "Policy description.",
				Optional:    true,
			},
			"labels": schema.SetAttribute{
				Description: "Custom labels for the policy.",
				Optional:    true,
				ElementType: types.StringType,
			},
			"rule_matching": schema.SingleNestedAttribute{
				Description: "Configuration for how rules are matched to this policy.",
				Required:    true,
				Attributes: map[string]schema.Attribute{
					"type": schema.StringAttribute{
						Description: "How rules are matched: ALL_RULES (all rules), RULES (specific rule IDs), or RULE_FILTER (filter criteria).",
						Required:    true,
						Validators: []validator.String{
							stringvalidator.OneOf("ALL_RULES", "RULES", "RULE_FILTER"),
						},
					},
					"rules": schema.ListAttribute{
						Description: "List of rule UUIDs. Required when type is RULES.",
						Optional:    true,
						ElementType: types.StringType,
					},
					"filter_criteria": schema.SingleNestedAttribute{
						Description: "Filter criteria for rules. Required when type is RULE_FILTER.",
						Optional:    true,
						Attributes:  getFilterCriteriaSchema(0, 3),
					},
				},
			},
			"asset_matching": schema.SingleNestedAttribute{
				Description: "Configuration for how assets are matched to this policy.",
				Required:    true,
				Attributes: map[string]schema.Attribute{
					"type": schema.StringAttribute{
						Description: "How assets are matched: ALL_ASSETS (all assets), ASSET_GROUPS (specific asset groups), or CLOUD_ACCOUNTS (specific cloud accounts).",
						Required:    true,
						Validators: []validator.String{
							stringvalidator.OneOf("ALL_ASSETS", "ASSET_GROUPS", "CLOUD_ACCOUNTS"),
						},
					},
					"asset_group_ids": schema.ListAttribute{
						Description: "List of asset group IDs. Required when type is ASSET_GROUPS.",
						Optional:    true,
						ElementType: types.Int64Type,
					},
					"cloud_account_ids": schema.ListAttribute{
						Description: "List of cloud account IDs. Required when type is CLOUD_ACCOUNTS.",
						Optional:    true,
						ElementType: types.StringType,
					},
				},
			},
			"enabled": schema.BoolAttribute{
				Description: "Whether the policy is enabled (defaults to true).",
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(true),
			},
			"mode": schema.StringAttribute{
				Description: "Policy mode (DEFAULT or CUSTOM).",
				Computed:    true,
			},
			"created_at": schema.Int64Attribute{
				Description: "Creation timestamp (epoch milliseconds).",
				Computed:    true,
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.UseStateForUnknown(),
				},
			},
			"created_by": schema.StringAttribute{
				Description: "User who created the policy.",
				Computed:    true,
			},
			"updated_at": schema.Int64Attribute{
				Description: "Last modification timestamp (epoch milliseconds).",
				Computed:    true,
			},
			"updated_by": schema.StringAttribute{
				Description: "User who last modified the policy.",
				Computed:    true,
			},
		},
	}
}

// Configure adds the provider-configured client to the resource.
func (r *CloudSecPolicyResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	clients, ok := req.ProviderData.(*providerModels.CortexCloudSDKClients)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf("Expected *providerModels.CortexCloudSDKClients, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)
		return
	}

	r.client = clients.CloudSec
}

// Create creates the resource and sets the initial Terraform state.
func (r *CloudSecPolicyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	var plan cloudsecModels.CloudSecPolicyResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Validate conditional requirements
	validateRuleMatching(ctx, &plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	validateAssetMatching(ctx, &plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	// Convert plan to SDK create request
	createReq := plan.ToSDKCreateRequest(ctx, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	// Call SDK
	createResp, err := r.client.CreatePolicy(ctx, createReq)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Creating CloudSec Policy",
			fmt.Sprintf("Could not create policy: %s", err.Error()),
		)
		return
	}

	// WORKAROUND: The CloudSec Create API endpoint ignores the "enabled" field,
	// always creating policies as enabled. When the user wants enabled=false,
	// we fire a subsequent PATCH to disable it.
	//
	// Remove this workaround once the upstream API bug is fixed.
	//
	// See SDK test: TestAccPolicy_CreateDisabledBugDetection
	if !plan.Enabled.IsNull() &&
		!plan.Enabled.IsUnknown() &&
		!plan.Enabled.ValueBool() {
		tflog.Debug(ctx, fmt.Sprintf("disabling newly-created cloud security policy \"%s\"", plan.Name.ValueString()))

		enabled := false
		disableReq := cloudsecTypes.PolicyUpdateRequest{
			ID:      createResp.ID,
			Enabled: &enabled,
		}

		createResp, err = r.client.UpdatePolicy(ctx, disableReq)
		if err != nil {
			resp.Diagnostics.AddError(
				"Error Disabling New CloudSec Policy",
				fmt.Sprintf("Could not disable policy after creation: %s", err.Error()),
			)
			return
		}
	}

	// Update plan with response data
	plan.FromSDKResponse(ctx, &resp.Diagnostics, &createResp)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Read refreshes the Terraform state with the latest data.
func (r *CloudSecPolicyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	var state cloudsecModels.CloudSecPolicyResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Call SDK Get method
	policyResp, err := r.client.GetPolicy(ctx, state.ID.ValueString())
	if err != nil {
		// Check if policy not found
		errMsg := err.Error()
		if strings.Contains(errMsg, "not found") || strings.Contains(errMsg, "404") {
			resp.Diagnostics.AddWarning(
				"CloudSec Policy Not Found",
				fmt.Sprintf("Policy with ID %s was not found and will be removed from state.", state.ID.ValueString()),
			)
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError(
			"Error Reading CloudSec Policy",
			fmt.Sprintf("Could not read policy %s: %s", state.ID.ValueString(), err.Error()),
		)
		return
	}

	// Update state with response data
	state.FromSDKResponse(ctx, &resp.Diagnostics, &policyResp)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *CloudSecPolicyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	var state cloudsecModels.CloudSecPolicyResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var plan cloudsecModels.CloudSecPolicyResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Validate conditional requirements
	validateRuleMatching(ctx, &plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	validateAssetMatching(ctx, &plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	// Convert plan to SDK update request
	updateReq := plan.ToSDKUpdateRequest(ctx, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	// Call SDK
	policyResp, err := r.client.UpdatePolicy(ctx, updateReq)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Updating CloudSec Policy",
			fmt.Sprintf("Could not update policy %s: %s", state.ID.ValueString(), err.Error()),
		)
		return
	}

	// Update plan with response data
	plan.FromSDKResponse(ctx, &resp.Diagnostics, &policyResp)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Delete deletes the resource and removes it from the Terraform state on success.
func (r *CloudSecPolicyResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	var state cloudsecModels.CloudSecPolicyResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Call SDK Delete method
	err := r.client.DeletePolicy(ctx, state.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Deleting CloudSec Policy",
			fmt.Sprintf("Could not delete policy %s: %s", state.ID.ValueString(), err.Error()),
		)
		return
	}
}

// ImportState imports the resource by ID.
func (r *CloudSecPolicyResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// Import by ID (UUID format)
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// ValidateConfig performs plan-time validation of the resource configuration.
// This ensures conditional requirements (e.g., filter_criteria required when type=RULE_FILTER)
// are caught during `terraform plan` rather than `terraform apply`.
func (r *CloudSecPolicyResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var config cloudsecModels.CloudSecPolicyResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Validate rule matching conditional requirements
	validateRuleMatching(ctx, &config, &resp.Diagnostics)

	// Validate asset matching conditional requirements
	validateAssetMatching(ctx, &config, &resp.Diagnostics)
}

// validateRuleMatching validates the rule matching configuration.
func validateRuleMatching(ctx context.Context, model *cloudsecModels.CloudSecPolicyResourceModel, diags *diag.Diagnostics) {
	if model.RuleMatching.IsNull() || model.RuleMatching.IsUnknown() {
		return
	}

	var ruleMatching cloudsecModels.RuleMatchingModel
	diags.Append(model.RuleMatching.As(ctx, &ruleMatching, basetypes.ObjectAsOptions{})...)
	if diags.HasError() {
		return
	}

	// If type is unknown (e.g., from a variable), skip conditional validation
	if ruleMatching.Type.IsUnknown() {
		return
	}

	matchingType := ruleMatching.Type.ValueString()

	switch matchingType {
	case "RULES":
		if ruleMatching.Rules.IsNull() || ruleMatching.Rules.IsUnknown() {
			diags.AddAttributeError(
				path.Root("rule_matching").AtName("rules"),
				"Missing Required Field",
				"rules is required when rule_matching.type is RULES",
			)
		}
	case "RULE_FILTER":
		if ruleMatching.FilterCriteria.IsNull() || ruleMatching.FilterCriteria.IsUnknown() {
			diags.AddAttributeError(
				path.Root("rule_matching").AtName("filter_criteria"),
				"Missing Required Field",
				"filter_criteria is required when rule_matching.type is RULE_FILTER",
			)
		}
	}
}

// validateAssetMatching validates the asset matching configuration.
func validateAssetMatching(ctx context.Context, model *cloudsecModels.CloudSecPolicyResourceModel, diags *diag.Diagnostics) {
	if model.AssetMatching.IsNull() || model.AssetMatching.IsUnknown() {
		return
	}

	var assetMatching cloudsecModels.AssetMatchingModel
	diags.Append(model.AssetMatching.As(ctx, &assetMatching, basetypes.ObjectAsOptions{})...)
	if diags.HasError() {
		return
	}

	// If type is unknown (e.g., from a variable), skip conditional validation
	if assetMatching.Type.IsUnknown() {
		return
	}

	matchingType := assetMatching.Type.ValueString()

	switch matchingType {
	case "ASSET_GROUPS":
		if assetMatching.AssetGroupIDs.IsNull() || assetMatching.AssetGroupIDs.IsUnknown() {
			diags.AddAttributeError(
				path.Root("asset_matching").AtName("asset_group_ids"),
				"Missing Required Field",
				"asset_group_ids is required when asset_matching.type is ASSET_GROUPS",
			)
		}
	case "CLOUD_ACCOUNTS":
		if assetMatching.CloudAccountIDs.IsNull() || assetMatching.CloudAccountIDs.IsUnknown() {
			diags.AddAttributeError(
				path.Root("asset_matching").AtName("cloud_account_ids"),
				"Missing Required Field",
				"cloud_account_ids is required when asset_matching.type is CLOUD_ACCOUNTS",
			)
		}
	}
}
