// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package cloudsec

import (
	"context"
	"fmt"
	"strings"

	"github.com/PaloAltoNetworks/cortex-cloud-go/cloudsec"
	"github.com/PaloAltoNetworks/cortex-cloud-go/compliance"
	cloudsecTypes "github.com/PaloAltoNetworks/cortex-cloud-go/types/cloudsec"
	complianceTypes "github.com/PaloAltoNetworks/cortex-cloud-go/types/compliance"
	cloudsecModels "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/cloudsec"
	providerModels "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/provider"
	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/planmodifiers"
	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/util"

	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ resource.Resource                = &CloudSecRuleResource{}
	_ resource.ResourceWithImportState = &CloudSecRuleResource{}
)

// NewCloudSecRuleResource is a helper function to simplify the provider implementation.
func NewCloudSecRuleResource() resource.Resource {
	return &CloudSecRuleResource{}
}

// CloudSecRuleResource is the resource implementation.
type CloudSecRuleResource struct {
	client           *cloudsec.Client
	complianceClient *compliance.Client
}

// Metadata returns the resource type name.
func (r *CloudSecRuleResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cloudsec_rule"
}

// Schema defines the schema for the resource.
func (r *CloudSecRuleResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a CloudSec detection rule for CSPM (Cloud Security Posture Management).",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "Unique identifier of the rule (UUID format).",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Description: "Unique rule name (max 255 characters).",
				Required:    true,
				Validators: []validator.String{
					stringvalidator.LengthBetween(1, 255),
				},
			},
			"description": schema.StringAttribute{
				Description: "Detailed rule description (max 2000 characters).",
				Required:    true,
				Validators: []validator.String{
					stringvalidator.LengthBetween(1, 2000),
				},
			},
			"class": schema.StringAttribute{
				Description: "Rule class - must be 'config' for CSPM rules.",
				Required:    true,
				Validators: []validator.String{
					stringvalidator.OneOf("config"),
				},
			},
			"type": schema.StringAttribute{
				Description: "Rule type - defaults to 'DETECTION' if not provided.",
				Optional:    true,
				Computed:    true,
				Default:     stringdefault.StaticString("DETECTION"),
				Validators: []validator.String{
					stringvalidator.OneOf("DETECTION"),
				},
			},
			"asset_types": schema.ListAttribute{
				Description: "Array with exactly one asset type identifier (e.g., 'aws-s3-bucket').",
				Required:    true,
				ElementType: types.StringType,
				Validators: []validator.List{
					listvalidator.SizeBetween(1, 1),
					listvalidator.ValueStringsAre(stringvalidator.LengthAtLeast(1)),
				},
			},
			"severity": schema.StringAttribute{
				Description: "Rule severity level.",
				Required:    true,
				Validators: []validator.String{
					stringvalidator.OneOf("low", "medium", "high", "critical", "informational"),
				},
				PlanModifiers: []planmodifier.String{
					planmodifiers.ToLowercase(),
				},
			},
			"query": schema.SingleNestedAttribute{
				Description: "Query definition containing XQL.",
				Required:    true,
				Attributes: map[string]schema.Attribute{
					"xql": schema.StringAttribute{
						Description: "Valid XQL query string.",
						Required:    true,
						Validators: []validator.String{
							stringvalidator.LengthAtLeast(1),
						},
					},
				},
			},
			"metadata": schema.SingleNestedAttribute{
				Description: "Metadata containing issue information. The API auto-populates this field even when not specified.",
				Optional:    true,
				Computed:    true,
				Attributes: map[string]schema.Attribute{
					"issue": schema.SingleNestedAttribute{
						Description: "Issue information with remediation details.",
						Optional:    true,
						Computed:    true,
						Attributes: map[string]schema.Attribute{
							"recommendation": schema.StringAttribute{
								Description: "Remediation steps (max 5000 characters).",
								Optional:    true,
								Computed:    true,
								Validators: []validator.String{
									stringvalidator.LengthAtMost(5000),
								},
							},
						},
					},
				},
			},
			"compliance_metadata": schema.ListNestedAttribute{
				Description: "List of compliance metadata with control IDs (max 100). " +
					"For custom controls created via cortexcloud_compliance_control, the control must first be " +
					"associated with a compliance standard via cortexcloud_compliance_standard before it can be " +
					"referenced here. See the resource_with_compliance example for the correct workflow.",
				Optional: true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"control_id": schema.StringAttribute{
							Description: "Compliance control identifier. For built-in controls, use the standard ID " +
								"(e.g., 'CIS-AWS-2.1.5'). For custom controls created via cortexcloud_compliance_control, " +
								"the control must first be associated with a compliance standard via " +
								"cortexcloud_compliance_standard.controls_ids before it can be used here.",
							Required: true,
							Validators: []validator.String{
								stringvalidator.LengthAtLeast(1),
							},
						},
						"standard_id": schema.StringAttribute{
							Description: "Compliance standard identifier.",
							Computed:    true,
						},
						"standard_name": schema.StringAttribute{
							Description: "Full name of the compliance standard.",
							Computed:    true,
						},
						"control_name": schema.StringAttribute{
							Description: "Full name of the compliance control.",
							Computed:    true,
						},
					},
				},
				Validators: []validator.List{
					listvalidator.SizeAtMost(100),
				},
			},
			"labels": schema.SetAttribute{
				Description: "Custom labels (max 50, each max 100 characters).",
				Optional:    true,
				ElementType: types.StringType,
				Validators: []validator.Set{
					setvalidator.SizeAtMost(50),
					setvalidator.ValueStringsAre(stringvalidator.LengthAtMost(100)),
				},
			},
			"enabled": schema.BoolAttribute{
				Description: "Whether the rule is enabled (defaults to true).",
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(true),
			},
			"providers": schema.ListAttribute{
				Description: "Cloud providers derived from asset_types.",
				Computed:    true,
				ElementType: types.StringType,
			},
			"system_default": schema.BoolAttribute{
				Description: "Indicates if this is a system default rule.",
				Computed:    true,
			},
			"created_by": schema.StringAttribute{
				Description: "User who created the rule.",
				Computed:    true,
			},
			"created_on": schema.Int64Attribute{
				Description: "Creation timestamp (epoch milliseconds).",
				Computed:    true,
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.UseStateForUnknown(),
				},
			},
			"last_modified_by": schema.StringAttribute{
				Description: "User who last modified the rule.",
				Computed:    true,
			},
			"last_modified_on": schema.Int64Attribute{
				Description: "Last modification timestamp (epoch milliseconds).",
				Computed:    true,
			},
			"deleted": schema.BoolAttribute{
				Description: "Deletion status.",
				Computed:    true,
			},
			"deleted_at": schema.Int64Attribute{
				Description: "Deletion timestamp (epoch milliseconds).",
				Computed:    true,
			},
			"deleted_by": schema.StringAttribute{
				Description: "User who deleted the rule.",
				Computed:    true,
			},
		},
	}
}

// Configure adds the provider-configured client to the resource.
func (r *CloudSecRuleResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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
	r.complianceClient = clients.Compliance
}

// Create creates the resource and sets the initial Terraform state.
func (r *CloudSecRuleResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	var plan cloudsecModels.CloudSecRuleResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Convert plan to SDK create request
	createReq := plan.ToSDKCreateRequest(ctx, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	// Pre-flight validation: verify custom compliance control IDs are associated with a standard
	r.validateComplianceMetadata(ctx, &resp.Diagnostics, extractControlIDs(createReq.ComplianceMetadata))
	if resp.Diagnostics.HasError() {
		return
	}

	// Call SDK
	ruleResp, err := r.client.Create(ctx, createReq)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Creating CloudSec Rule",
			fmt.Sprintf("Could not create rule: %s", err.Error()),
		)
		return
	}

	// Update plan with response data
	plan.FromSDKResponse(ctx, &resp.Diagnostics, &ruleResp)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Read refreshes the Terraform state with the latest data.
func (r *CloudSecRuleResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	var state cloudsecModels.CloudSecRuleResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Call SDK Get method
	ruleResp, err := r.client.Get(ctx, state.ID.ValueString())
	if err != nil {
		// Check if rule not found
		errMsg := err.Error()
		if strings.Contains(errMsg, "not found") || strings.Contains(errMsg, "404") {
			resp.Diagnostics.AddWarning(
				"CloudSec Rule Not Found",
				fmt.Sprintf("Rule with ID %s was not found and will be removed from state.", state.ID.ValueString()),
			)
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError(
			"Error Reading CloudSec Rule",
			fmt.Sprintf("Could not read rule %s: %s", state.ID.ValueString(), err.Error()),
		)
		return
	}

	// Update state with response data
	state.FromSDKResponse(ctx, &resp.Diagnostics, &ruleResp)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *CloudSecRuleResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	var state cloudsecModels.CloudSecRuleResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var plan cloudsecModels.CloudSecRuleResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Convert plan to SDK update request (selective-PATCH: only changed fields)
	updateReq := plan.ToSDKUpdateRequest(ctx, &resp.Diagnostics, &state)
	if resp.Diagnostics.HasError() {
		return
	}

	// Pre-flight validation: verify custom compliance control IDs are associated with a standard
	r.validateComplianceMetadata(ctx, &resp.Diagnostics, extractControlIDs(updateReq.ComplianceMetadata))
	if resp.Diagnostics.HasError() {
		return
	}

	// Call SDK to update the rule
	_, err := r.client.Update(ctx, state.ID.ValueString(), updateReq)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Updating CloudSec Rule",
			fmt.Sprintf("Could not update rule %s: %s", state.ID.ValueString(), err.Error()),
		)
		return
	}

	// Re-read the rule to get complete state (PATCH response may omit computed fields like compliance_metadata)
	ruleResp, err := r.client.Get(ctx, state.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Reading CloudSec Rule After Update",
			fmt.Sprintf("Could not read rule %s after update: %s", state.ID.ValueString(), err.Error()),
		)
		return
	}

	// Update plan with the complete response data from GET
	plan.FromSDKResponse(ctx, &resp.Diagnostics, &ruleResp)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Delete deletes the resource and removes it from the Terraform state on success.
func (r *CloudSecRuleResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	var state cloudsecModels.CloudSecRuleResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Call SDK Delete method
	err := r.client.Delete(ctx, state.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Deleting CloudSec Rule",
			fmt.Sprintf("Could not delete rule %s: %s", state.ID.ValueString(), err.Error()),
		)
		return
	}
}

// ImportState imports the resource by ID.
func (r *CloudSecRuleResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// Import by ID (UUID format)
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// validateComplianceMetadata performs pre-flight validation on compliance control IDs.
// For custom controls (hex-format IDs), it verifies the control exists and is associated with
// at least one compliance standard. Built-in controls (e.g., 'CIS-AWS-2.1.5') are skipped
// since they are always associated with their respective standards.
func (r *CloudSecRuleResource) validateComplianceMetadata(ctx context.Context, diags *diag.Diagnostics, controlIDs []string) {
	if len(controlIDs) == 0 || r.complianceClient == nil {
		return
	}

	for _, controlID := range controlIDs {
		if controlID == "" {
			continue
		}

		// Skip built-in control IDs — they contain uppercase letters and/or hyphens/dots
		// Custom control IDs are lowercase hex strings (e.g., "48e2f6a9fcc049579e9c6b8eda0bd123")
		if !isCustomControlID(controlID) {
			tflog.Debug(ctx, fmt.Sprintf("Skipping validation for built-in control ID: %s", controlID))
			continue
		}

		tflog.Debug(ctx, fmt.Sprintf("Validating custom compliance control ID: %s", controlID))

		control, err := r.complianceClient.GetControl(ctx, complianceTypes.GetControlRequest{
			ID: controlID,
		})
		if err != nil {
			diags.AddError(
				"Invalid Compliance Control ID",
				fmt.Sprintf("Compliance control '%s' was not found. Verify the control exists "+
					"and was created via cortexcloud_compliance_control. Error: %s", controlID, err.Error()),
			)
			continue
		}

		if len(control.Standards) == 0 {
			diags.AddError(
				"Compliance Control Not Associated with Standard",
				fmt.Sprintf("Custom compliance control '%s' (%s) is not associated with any compliance standard. "+
					"Custom controls must be associated with a standard (via cortexcloud_compliance_standard with "+
					"controls_ids) before they can be used in CloudSec rule compliance_metadata. "+
					"Create a cortexcloud_compliance_standard resource that includes this control's ID in its "+
					"controls_ids list, and add a depends_on reference to ensure correct ordering.",
					controlID, control.Name),
			)
			continue
		}

		tflog.Debug(ctx, fmt.Sprintf("Custom control '%s' is associated with %d standard(s): %v",
			controlID, len(control.Standards), control.Standards))
	}
}

// extractControlIDs extracts control IDs from a slice of ComplianceMetadataInput.
func extractControlIDs(cms []cloudsecTypes.ComplianceMetadataInput) []string {
	ids := make([]string, len(cms))
	for i, cm := range cms {
		ids[i] = cm.ControlID
	}
	return ids
}

// isCustomControlID determines whether a control ID is a custom (hex) ID or a built-in ID.
// Built-in IDs contain uppercase letters, hyphens, or dots (e.g., "CIS-AWS-2.1.5", "NIST-800-53-AC-2").
// Custom IDs are 32-character lowercase hex strings (e.g., "48e2f6a9fcc049579e9c6b8eda0bd123").
func isCustomControlID(id string) bool {
	if len(id) != 32 {
		return false
	}
	for _, c := range id {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}
