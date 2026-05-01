// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package appsec

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/PaloAltoNetworks/cortex-cloud-go/appsec"
	sdkErrors "github.com/PaloAltoNetworks/cortex-cloud-go/errors"
	appsecTypes "github.com/PaloAltoNetworks/cortex-cloud-go/types/appsec"
	appsecModels "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/appsec"
	providerModels "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/provider"
	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/util"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/objectplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// overrideIssueSeverityValues are the API-accepted values for the
// override_issue_severity attribute on each trigger block.
var overrideIssueSeverityValues = []string{"Critical", "High", "Medium", "Low"}

var (
	_ resource.Resource                = &policyResource{}
	_ resource.ResourceWithConfigure   = &policyResource{}
	_ resource.ResourceWithImportState = &policyResource{}
)

func NewPolicyResource() resource.Resource {
	return &policyResource{}
}

type policyResource struct {
	client *appsec.Client
}

func (r *policyResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_appsec_policy"
}

func (r *policyResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages an Application Security policy.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "Unique identifier for the policy.",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Description: "Name of the policy.",
				Required:    true,
			},
			"description": schema.StringAttribute{
				Description: "Description of the policy.",
				Optional:    true,
			},
			"status": schema.StringAttribute{
				Description: "Indicates whether the policy is enabled or disabled.",
				Optional:    true,
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"is_custom": schema.BoolAttribute{
				Description: "Indicates if the policy is a custom policy or a system-provided policy.",
				Computed:    true,
				PlanModifiers: []planmodifier.Bool{
					boolplanmodifier.UseStateForUnknown(),
				},
			},
			"conditions": schema.StringAttribute{
				Description: "Policy conditions as JSON-encoded string with nested AND/OR logic.",
				Required:    true,
			},
			"scope": schema.StringAttribute{
				Description: "Asset targeting scope as JSON-encoded string. Mutually exclusive with asset_group_ids.",
				Optional:    true,
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"asset_group_ids": schema.ListAttribute{
				Description: "List of asset groups to which the policy applies. If the array is empty, the policy applies to all asset groups. Mutually exclusive with scope.",
				Optional:    true,
				Computed:    true,
				ElementType: types.Int64Type,
			},
			"periodic_trigger": schema.SingleNestedAttribute{
				Description: "If true, the policy is evaluated periodically (for example, daily or weekly). Defaults to disabled if this attribute is not configured.",
				Optional:    true,
				Computed:    true,
				PlanModifiers: []planmodifier.Object{
					objectplanmodifier.UseStateForUnknown(),
				},
				Attributes: map[string]schema.Attribute{
					"enabled": schema.BoolAttribute{
						Description: "Enables the periodic trigger for the policy.",
						Required:    true,
					},
					"override_issue_severity": schema.StringAttribute{
						Description: "Sets the severity of the issue, overriding the system severity. If not configured, the system severity is used.",
						Optional:    true,
						Validators: []validator.String{
							stringvalidator.OneOf(overrideIssueSeverityValues...),
						},
					},
					"actions": schema.SingleNestedAttribute{
						Description: "Actions to take when the policy detects its target risk and the policy is triggered.",
						Required:    true,
						Attributes: map[string]schema.Attribute{
							"report_issue": schema.BoolAttribute{
								Description: "Indicates if triggering the policy should create an issue in the connected system.",
								Required:    true,
							},
						},
					},
				},
			},
			"pr_trigger": schema.SingleNestedAttribute{
				Description: "If true, the policy is evaluated on Pull Request (PR) events. Defaults to disabled if this attribute is not configured.",
				Optional:    true,
				Computed:    true,
				PlanModifiers: []planmodifier.Object{
					objectplanmodifier.UseStateForUnknown(),
				},
				Attributes: map[string]schema.Attribute{
					"enabled": schema.BoolAttribute{
						Description: "Enables the PR trigger for the policy.",
						Required:    true,
					},
					"override_issue_severity": schema.StringAttribute{
						Description: "Set the severity of the issue (and override the system severity). If not used, system severity is kept.",
						Optional:    true,
						Validators: []validator.String{
							stringvalidator.OneOf(overrideIssueSeverityValues...),
						},
					},
					"actions": schema.SingleNestedAttribute{
						Description: "Actions to take when the policy detects its target risk and the policy is triggered.",
						Required:    true,
						Attributes: map[string]schema.Attribute{
							"report_issue": schema.BoolAttribute{
								Description: "Indicates if triggering the policy should create an issue in the connected system.",
								Required:    true,
							},
							"block_pr": schema.BoolAttribute{
								Description: "Indicates if triggering the policy should block the pull request. Ensure that the PR trigger is selected.",
								Required:    true,
							},
							"report_pr_comment": schema.BoolAttribute{
								Description: "Indicates if triggering the policy should create comments on the pull request. Ensure that the PR trigger is selected.",
								Required:    true,
							},
						},
					},
				},
			},
			"cicd_trigger": schema.SingleNestedAttribute{
				Description: "If true, the policy is evaluated on CI/CD pipeline events. Defaults to disabled if this attribute is not configured.",
				Optional:    true,
				Computed:    true,
				PlanModifiers: []planmodifier.Object{
					objectplanmodifier.UseStateForUnknown(),
				},
				Attributes: map[string]schema.Attribute{
					"enabled": schema.BoolAttribute{
						Description: "Enables the CI/CD trigger for the policy.",
						Required:    true,
					},
					"override_issue_severity": schema.StringAttribute{
						Description: "Set the severity of the issue (and override the system severity). If not used, system severity is kept.",
						Optional:    true,
						Validators: []validator.String{
							stringvalidator.OneOf(overrideIssueSeverityValues...),
						},
					},
					"actions": schema.SingleNestedAttribute{
						Description: "Actions to take when the policy detects its target risk and the policy is triggered.",
						Required:    true,
						Attributes: map[string]schema.Attribute{
							"report_issue": schema.BoolAttribute{
								Description: "Indicates if triggering the policy should create an issue in the connected system.",
								Required:    true,
							},
							"block_cicd": schema.BoolAttribute{
								Description: "Indicates if triggering the policy should block the CI/CD pipeline. Ensure that the CI/CD trigger is selected.",
								Required:    true,
							},
							"report_cicd": schema.BoolAttribute{
								Description: "Indicates if triggering the policy should soft fail the CI/CD pipeline in the platform. Ensure that the CI/CD trigger is selected.",
								Required:    true,
							},
						},
					},
				},
			},
			"ci_image_trigger": schema.SingleNestedAttribute{
				Description: "CI image scan trigger configuration. Defaults to disabled if this attribute is not configured.",
				Optional:    true,
				Computed:    true,
				PlanModifiers: []planmodifier.Object{
					objectplanmodifier.UseStateForUnknown(),
				},
				Attributes: map[string]schema.Attribute{
					"enabled": schema.BoolAttribute{
						Description: "Whether the CI image trigger is enabled.",
						Required:    true,
					},
					"override_issue_severity": schema.StringAttribute{
						Description: "Set the severity of the issue (and override the system severity). If not used, system severity is kept.",
						Optional:    true,
						Validators: []validator.String{
							stringvalidator.OneOf(overrideIssueSeverityValues...),
						},
					},
					"actions": schema.SingleNestedAttribute{
						Description: "Actions to take when the policy detects its target risk and the policy is triggered.",
						Required:    true,
						Attributes: map[string]schema.Attribute{
							"report_issue": schema.BoolAttribute{
								Description: "Indicates if triggering the policy should create an issue in the connected system.",
								Required:    true,
							},
							"report_cicd": schema.BoolAttribute{
								Description: "Indicates if triggering the policy should soft fail the CI/CD pipeline in the platform.",
								Required:    true,
							},
							"block_cicd": schema.BoolAttribute{
								Description: "Indicates if triggering the policy should block the CI/CD pipeline.",
								Required:    true,
							},
						},
					},
				},
			},
			"image_registry_trigger": schema.SingleNestedAttribute{
				Description: "Image registry scan trigger configuration. Defaults to disabled if this attribute is not configured.",
				Optional:    true,
				Computed:    true,
				PlanModifiers: []planmodifier.Object{
					objectplanmodifier.UseStateForUnknown(),
				},
				Attributes: map[string]schema.Attribute{
					"enabled": schema.BoolAttribute{
						Description: "Whether the image registry trigger is enabled.",
						Required:    true,
					},
					"override_issue_severity": schema.StringAttribute{
						Description: "Set the severity of the issue (and override the system severity). If not used, system severity is kept.",
						Optional:    true,
						Validators: []validator.String{
							stringvalidator.OneOf(overrideIssueSeverityValues...),
						},
					},
					"actions": schema.SingleNestedAttribute{
						Description: "Actions to take when the policy detects its target risk and the policy is triggered.",
						Required:    true,
						Attributes: map[string]schema.Attribute{
							"report_issue": schema.BoolAttribute{
								Description: "Indicates if triggering the policy should create an issue in the connected system.",
								Required:    true,
							},
						},
					},
				},
			},
			"developer_suppression_affects": schema.BoolAttribute{
				Description: "Whether developer suppression affects the policy. This field is read-only as the API does not honor this value on create or update.",
				Computed:    true,
			},
			"override_issue_severity": schema.StringAttribute{
				Description: "Override severity for issues.",
				Optional:    true,
			},
			"created_by": schema.StringAttribute{
				Description: "The user or system that created the policy.",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"date_created": schema.StringAttribute{
				Description: "The date and time when the policy was created.",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"modified_by": schema.StringAttribute{
				Description: "The user or system that last modified the policy.",
				Computed:    true,
			},
			"date_modified": schema.StringAttribute{
				Description: "The date and time when the policy was last modified.",
				Computed:    true,
			},
			"version": schema.Float64Attribute{
				Description: "The version of the policy - goes up by one every policy update.",
				Computed:    true,
			},
		},
	}
}

func (r *policyResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *policyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	var plan appsecModels.PolicyModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	createReq := plan.ToCreateRequest(ctx, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	createResult, err := r.client.CreatePolicy(ctx, createReq)
	if err != nil {
		// The CREATE API returns HTTP 204 No Content (empty body). The SDK's
		// Do() method may fail to unmarshal the empty response, producing a
		// deserialization error. Treat this as "success with no body" and fall
		// through to the name-based lookup below.
		errMsg := err.Error()
		if strings.Contains(errMsg, "unmarshal") || strings.Contains(errMsg, "unexpected end of JSON") || strings.Contains(errMsg, "EOF") {
			tflog.Warn(ctx, "CreatePolicy returned a deserialization error (likely HTTP 204 empty body); treating as success",
				map[string]interface{}{"error": errMsg})
			createResult = appsecTypes.Policy{}
		} else {
			resp.Diagnostics.AddError("Error Creating AppSec Policy", util.FormatAPIError(err))
			return
		}
	}

	// The CREATE API may return HTTP 204 No Content (empty body), which means
	// the SDK returns a zero-value Policy with no ID. In that case, look up
	// the newly created policy by name via the list endpoint.
	policyID := createResult.ID
	if policyID == "" {
		tflog.Debug(ctx, "CREATE returned no policy ID (HTTP 204); looking up by name",
			map[string]interface{}{"policy_name": createReq.Name})

		// Retry loop to handle eventual consistency after create
		backoffs := []time.Duration{1 * time.Second, 2 * time.Second, 4 * time.Second}
		for attempt, backoff := range backoffs {
			time.Sleep(backoff)

			tflog.Debug(ctx, "Listing policies to find newly created policy",
				map[string]interface{}{"attempt": attempt + 1, "max_attempts": len(backoffs)})

			policies, listErr := r.client.ListPolicies(ctx, appsecTypes.ListPoliciesRequest{IsCustom: true})
			if listErr != nil {
				resp.Diagnostics.AddError("Error Looking Up AppSec Policy After Create",
					"The policy was created successfully but could not be found: "+listErr.Error())
				return
			}

			for _, p := range policies {
				if strings.EqualFold(p.Name, createReq.Name) {
					policyID = p.ID
					break
				}
			}

			if policyID != "" {
				break
			}
		}

		if policyID == "" {
			resp.Diagnostics.AddError("Error Looking Up AppSec Policy After Create",
				fmt.Sprintf("The policy was created successfully but could not be found by name %q in the policy list after 3 attempts.", createReq.Name))
			return
		}
	}

	tflog.Debug(ctx, "Re-reading policy after create to get complete state",
		map[string]interface{}{"policy_id": policyID})

	fullPolicy, err := r.client.GetPolicy(ctx, policyID)
	if err != nil {
		resp.Diagnostics.AddError("Error Reading AppSec Policy After Create",
			"The policy was created successfully but could not be read back: "+util.FormatAPIError(err))
		return
	}

	plan.RefreshFromRemote(ctx, &resp.Diagnostics, &fullPolicy)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *policyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	var state appsecModels.PolicyModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	remote, err := r.client.GetPolicy(ctx, state.ID.ValueString())
	if err != nil {
		// Check if the error is a 404 (resource not found) — remove from state.
		// For all other errors, return an error diagnostic so Terraform can retry.
		var sdkErr *sdkErrors.CortexCloudSdkError
		if sdkErrors.AsCortexCloudSdkError(err, &sdkErr) && sdkErr.HTTPStatus != nil && *sdkErr.HTTPStatus == http.StatusNotFound {
			resp.Diagnostics.AddWarning("AppSec Policy Not Found", "Removing from state.")
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Error Reading AppSec Policy", util.FormatAPIError(err))
		return
	}

	state.RefreshFromRemote(ctx, &resp.Diagnostics, &remote)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *policyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	var plan appsecModels.PolicyModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Read the current policy from the API first. The UpdatePolicy endpoint uses
	// PUT (full replacement), so the request must include all fields. Fields like
	// relatedDetectionRules and actions are server-computed and not managed by
	// Terraform, but must still be present in the PUT body.
	policyID := plan.ID.ValueString()
	tflog.Debug(ctx, "Reading current policy before update for read-modify-write", map[string]interface{}{
		"policy_id": policyID,
	})

	current, err := r.client.GetPolicy(ctx, policyID)
	if err != nil {
		resp.Diagnostics.AddError("Error Reading AppSec Policy Before Update",
			"Could not read the current policy state required for update: "+util.FormatAPIError(err))
		return
	}

	updateReq := plan.ToUpdateRequest(ctx, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	// Merge server-computed fields from the current policy into the update request.
	mergeServerFields(&updateReq, &current)

	_, err = r.client.UpdatePolicy(ctx, policyID, updateReq)
	if err != nil {
		resp.Diagnostics.AddError("Error Updating AppSec Policy", util.FormatAPIError(err))
		return
	}

	// The PUT API returns HTTP 204 (no body), so we must GET the updated policy
	// to refresh state — same pattern as Create.
	result, err := r.client.GetPolicy(ctx, policyID)
	if err != nil {
		resp.Diagnostics.AddError("Error Reading AppSec Policy After Update",
			"Policy was updated successfully but could not be read back: "+util.FormatAPIError(err))
		return
	}

	plan.RefreshFromRemote(ctx, &resp.Diagnostics, &result)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// mergeServerFields populates server-computed fields in the update request from
// the current policy state. The AppSec Policy API uses PUT (full replacement),
// so all fields must be present even if they are not managed by Terraform.
// Without these fields, the API returns ValidateError with empty details.
func mergeServerFields(req *appsecTypes.UpdatePolicyRequest, current *appsecTypes.Policy) {
	// RelatedDetectionRules — server-managed, not exposed in Terraform schema.
	// Must be present in PUT body (even as empty array).
	if req.RelatedDetectionRules == nil {
		req.RelatedDetectionRules = current.RelatedDetectionRules
		if req.RelatedDetectionRules == nil {
			req.RelatedDetectionRules = []string{}
		}
	}

	// NOTE: Do NOT merge Actions here. The "actions" field is a server-computed
	// aggregate of trigger actions (read-only). The PUT endpoint rejects it as
	// an excess property. The per-trigger actions inside "triggers" are the
	// correct way to set actions.

	// Scope — required by the API even on PUT. If the user doesn't configure
	// scope in Terraform, use the current server value or an empty scope.
	if req.Scope == nil {
		req.Scope = current.Scope
		if req.Scope == nil {
			req.Scope = &appsecTypes.PolicyScope{}
		}
	}

	// AssetGroupIds — ensure present even when empty.
	// Terraform may not set this if the user doesn't configure it.
	if req.AssetGroupIds == nil {
		req.AssetGroupIds = current.AssetGroupIds
		if req.AssetGroupIds == nil {
			req.AssetGroupIds = []int{}
		}
	}
}

func (r *policyResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	var state appsecModels.PolicyModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	err := r.client.DeletePolicy(ctx, state.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Error Deleting AppSec Policy", util.FormatAPIError(err))
		return
	}
}

func (r *policyResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
