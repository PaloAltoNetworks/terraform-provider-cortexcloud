// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package cloud_onboarding

import (
	"context"
	"fmt"

	"github.com/PaloAltoNetworks/cortex-cloud-go/cloudonboarding"
	"github.com/PaloAltoNetworks/cortex-cloud-go/enums"
	cortexTypes "github.com/PaloAltoNetworks/cortex-cloud-go/types/cloudonboarding"

	models "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/cloud_onboarding"
	providerModels "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/provider"
	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/util"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/setplanmodifier"

	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ resource.Resource               = &OutpostTemplateResource{}
	_ resource.ResourceWithModifyPlan = &OutpostTemplateResource{}
)

// NewOutpostTemplateResource is a helper function to simplify the provider implementation.
func NewOutpostTemplateResource() resource.Resource {
	return &OutpostTemplateResource{}
}

// OutpostTemplateResource is the resource implementation.
type OutpostTemplateResource struct {
	client *cloudonboarding.Client
}

// Metadata returns the resource type name.
func (r *OutpostTemplateResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_outpost_template_aws"
}

// Schema defines the schema for the resource.
func (r *OutpostTemplateResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a CSP outpost template for AWS.",
		Attributes: map[string]schema.Attribute{
			"custom_resources_tags": schema.SetNestedAttribute{
				Description: "Tags applied to any new resource created by " +
					"Cortex Cloud in the cloud environment." +
					"\n\nThe tag \"managed_by\" with the value " +
					"\"paloaltonetworks\" will always be applied by default.",
				MarkdownDescription: "Tags applied to any new resource created by " +
					"Cortex Cloud in the cloud environment." +
					"\n\nThe tag `managed_by` with the value " +
					"`paloaltonetworks` will be applied by default.",
				Optional: true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"key": schema.StringAttribute{
							Description: "The tag key.",
							Required:    true,
						},
						"value": schema.StringAttribute{
							Description: "The tag value.",
							Required:    true,
						},
					},
				},
				// TODO: enforce unique keys
				//Validators: []validator.Set{
				//	//setvalidator.
				//},
				PlanModifiers: []planmodifier.Set{
					setplanmodifier.RequiresReplaceIfConfigured(),
				},
			},
			"terraform_module_url": schema.StringAttribute{
				Description: "The full URL returned by Cortex Cloud when selecting the Terraform method of downloading the template. Opening this URL in your browser will begin a download of the created template as a Terraform module, which you can then apply to permit Cortex Cloud to scan your Azure resources.",
				MarkdownDescription: "The full URL returned by Cortex Cloud when selecting the Terraform method of downloading the template. Opening this URL in your browser will begin a download of the created template as a Terraform module, which you can then apply to permit Cortex Cloud to scan your Azure resources.",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
		},
	}
}

// Configure adds the provider-configured client to the resource.
func (r *OutpostTemplateResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	// Prevent panic if the provider has not been configured
	if req.ProviderData == nil {
		return
	}

	ctx = tflog.SetField(ctx, "resource_type", "outpost_template_aws")
	ctx = tflog.SetField(ctx, "resource_operation", "Configure")
	tflog.Debug(ctx, "Configuring SDK client")

	client, ok := req.ProviderData.(*providerModels.CortexCloudSDKClients)

	if !ok {
		util.AddUnexpectedResourceConfigureTypeError(&resp.Diagnostics, "*http.Client", req.ProviderData)
		return
	}

	r.client = client.CloudOnboarding
}

func (r *OutpostTemplateResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	ctx = tflog.SetField(ctx, "resource_type", "outpost_template_aws")
	ctx = tflog.SetField(ctx, "resource_operation", "ModifyPlan")
	tflog.Debug(ctx, "Executing ModifyPlan")

	// If the entire plan is null, the resource is planned for destruction
	if req.Plan.Raw.IsNull() {
		var state models.OutpostTemplateModel
		resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
		if resp.Diagnostics.HasError() {
			return
		}
		resp.Diagnostics.AddWarning(
			"Manual Deletion Required for Cloud Integration Template Resources",
			fmt.Sprintf("Destroying this resource will only remove it from the Terraform state. You may manually delete the template in the Cortex UI by navigating to Settings > Data Sources, right-clicking the record with the ID value \"%s\", and clicking \"Delete\". If you do not see the template in Data Sources, adjust the table filters to include rows with a status of \"PENDING\".", state.TrackingGUID.ValueString()),
		)
	}
}

func fetchTemplateAWS(ctx context.Context, diagnostics *diag.Diagnostics, sdkClient *cloudonboarding.Client, model models.OutpostTemplateModel) []cortexTypes.IntegrationInstance {
	tflog.Debug(ctx, "Generating fetch API request payload")
	request := model.ToGetRequest(ctx, diagnostics)
	if diagnostics.HasError() {
		return []cortexTypes.IntegrationInstance{}
	}

	tflog.Debug(ctx, "Executing API request")
	response, err := sdkClient.ListIntegrationInstances(ctx, request)
	if err != nil {
		diagnostics.AddError(
			"Error Fetching Cloud Integration Template",
			err.Error(),
		)
		return []cortexTypes.IntegrationInstance{}
	}

	return response
}

// Create creates the resource and sets the initial Terraform state.
func (r *OutpostTemplateResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	ctx = tflog.SetField(ctx, "resource_type", "outpost_template_aws")
	ctx = tflog.SetField(ctx, "resource_operation", "Create")

	// Retrieve values from plan
	tflog.Debug(ctx, "Retrieving values from plan")
	var plan models.OutpostTemplateModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "Generating API request payload")
	createRequest := plan.ToCreateRequest(ctx, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "Executing API request")
	createResponse, err := r.client.CreateIntegrationTemplate(ctx, createRequest)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Creating Cloud Integration Template",
			err.Error(),
		)
		return
	}

	// Fetch the created template and populate OutpostID
	if createResponse.Automated.TrackingGUID != nil {
		tflog.Debug(ctx, "Fetching created template")
		plan.TrackingGUID = types.StringValue(*createResponse.Automated.TrackingGUID)
		response := fetchTemplateAWS(ctx, &resp.Diagnostics, r.client, plan)
		if resp.Diagnostics.HasError() {
			return
		}

		if len(response) == 1 && response[0].OutpostID != "" {
			plan.OutpostID = types.StringValue(response[0].OutpostID)
		} else {
			plan.OutpostID = types.StringNull()
		}
	} else {
		tflog.Debug(ctx, "No Tracking GUID found")

		plan.TrackingGUID = types.StringNull()
		plan.OutpostID = types.StringNull()
	}

	// Map response body to schema and populate Computed attribute values
	tflog.Debug(ctx, "Setting computed attributes")
	plan.SetGeneratedValues(ctx, &resp.Diagnostics, createResponse)
	if resp.Diagnostics.HasError() {
		return
	}

	// Set state to fully populated data
	tflog.Debug(ctx, "Setting state")
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Read refreshes the Terraform state with the latest values.
func (r *OutpostTemplateResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	ctx = tflog.SetField(ctx, "resource_type", "outpost_template_aws")
	ctx = tflog.SetField(ctx, "resource_id_field", "tracking_guid")
	ctx = tflog.SetField(ctx, "resource_operation", "Read")

	// Retrieve values from state
	tflog.Debug(ctx, "Retrieving values from state")
	var state models.OutpostTemplateModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	ctx = tflog.SetField(ctx, "resource_id_value", state.TrackingGUID.ValueString())

	// Retrieve integration details from API
	tflog.Debug(ctx, "Generating API request payload")
	request := state.ToGetRequest(ctx, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "Executing API request")
	response, err := r.client.ListIntegrationInstances(ctx, request)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Reading Cloud Integration Template",
			err.Error(),
		)
		return
	}

	if len(response) == 0 {
		tflog.Debug(ctx, "Template not found, removing from state")
		resp.State.RemoveResource(ctx)
		return
	}

	if len(response) > 1 {
		tflog.Debug(ctx, "API returned multiple results")
		resp.Diagnostics.AddWarning(
			"Multiple Cloud Integration Templates Returned",
			"Cortex Cloud returned multiple results for this resource. "+
				"Please report this issue to the provider developers.",
		)
		return
	}

	// Refresh state values
	tflog.Debug(ctx, "Refreshing configured attributes")
	state.RefreshConfiguredPropertyValues(ctx, &resp.Diagnostics, response[0])
	if resp.Diagnostics.HasError() {
		return
	}

	// Set refreshed state
	tflog.Debug(ctx, "Setting refreshed state")
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *OutpostTemplateResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	ctx = tflog.SetField(ctx, "resource_type", "outpost_template_aws")
	ctx = tflog.SetField(ctx, "resource_id_field", "tracking_guid")
	ctx = tflog.SetField(ctx, "resource_operation", "Read")

	// The resource should require replacement upon modifying any of the
	// configurable attributes, but as a fallback we will remove the resource
	// from the state.
	resp.State.RemoveResource(ctx)
}

// Delete deletes the resource and removes it from the Terraform state on success.
func (r *OutpostTemplateResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	defer util.PanicHandler(&resp.Diagnostics)
	resp.State.RemoveResource(ctx)
}
