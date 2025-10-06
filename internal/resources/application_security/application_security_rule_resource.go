// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package application_security

import (
	"context"
	//"fmt"

	models "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/application_security"
	providerModels "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/provider"
	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/util"

	"github.com/PaloAltoNetworks/cortex-cloud-go/appsec"

	//"dario.cat/mergo"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int32planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/setplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"gopkg.in/yaml.v3"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ resource.Resource               = &ApplicationSecurityRuleResource{}
	_ resource.ResourceWithModifyPlan = &ApplicationSecurityRuleResource{}
)

// NewApplicationSecurityRuleResource is a helper function to simplify the provider implementation.
func NewApplicationSecurityRuleResource() resource.Resource {
	return &ApplicationSecurityRuleResource{}
}

// ApplicationSecurityRuleResource is the resource implementation.
type ApplicationSecurityRuleResource struct {
	client *appsec.Client
}

// Metadata returns the resource type name.
func (r *ApplicationSecurityRuleResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_application_security_rule"
}

// Schema defines the schema for the resource.
func (r *ApplicationSecurityRuleResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "TODO",
		Attributes: map[string]schema.Attribute{
			"category": schema.StringAttribute{
				// TODO: validation
				Description: "TODO",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"cloud_provider": schema.StringAttribute{
				Description: "TODO",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"created_at": schema.StringAttribute{
				Description: "TODO",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"description": schema.StringAttribute{
				// TODO: rename to "Impact"
				// TODO: validation
				Description: "TODO",
				Optional:    true,
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
				Default: stringdefault.StaticString(""),
			},
			"detection_method": schema.StringAttribute{
				Description: "TODO",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"doc_link": schema.StringAttribute{
				Description: "TODO",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"domain": schema.StringAttribute{
				Description: "TODO",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"finding_category": schema.StringAttribute{
				Description: "TODO",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"finding_docs": schema.StringAttribute{
				Description: "TODO",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"finding_type_id": schema.Int32Attribute{
				Description: "TODO",
				Computed:    true,
				PlanModifiers: []planmodifier.Int32{
					int32planmodifier.UseStateForUnknown(),
				},
			},
			"finding_type_name": schema.StringAttribute{
				Description: "TODO",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"frameworks": schema.ListNestedAttribute{
				// TODO: validator to make sure this is not null
				Description: "TODO",
				Required:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"name": schema.StringAttribute{
							Description: "TODO",
							Required:    true,
							PlanModifiers: []planmodifier.String{
								stringplanmodifier.UseStateForUnknown(),
							},
						},
						"definition": schema.StringAttribute{
							Description: "TODO",
							Optional:    true,
							Computed:    true,
						},
						"definition_link": schema.StringAttribute{
							Description: "TODO",
							Optional:    true,
							Computed:    true,
							Default:     stringdefault.StaticString(""),
							PlanModifiers: []planmodifier.String{
								stringplanmodifier.UseStateForUnknown(),
							},
						},
						"remediation_description": schema.StringAttribute{
							Description: "TODO",
							Optional:    true,
							Computed:    true,
							Default:     stringdefault.StaticString(""),
						},
					},
				},
			},
			"id": schema.StringAttribute{
				Description: "TODO",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"is_custom": schema.BoolAttribute{
				Description: "TODO",
				Computed:    true,
				PlanModifiers: []planmodifier.Bool{
					boolplanmodifier.UseStateForUnknown(),
				},
			},
			"is_enabled": schema.BoolAttribute{
				Description: "TODO",
				Computed:    true,
				PlanModifiers: []planmodifier.Bool{
					boolplanmodifier.UseStateForUnknown(),
				},
			},
			"labels": schema.SetAttribute{
				Description: "TODO",
				Required:    true,
				ElementType: types.StringType,
				PlanModifiers: []planmodifier.Set{
					setplanmodifier.UseStateForUnknown(),
				},
			},
			"mitre_tactics": schema.SetAttribute{
				Description: "TODO",
				Computed:    true,
				ElementType: types.StringType,
				PlanModifiers: []planmodifier.Set{
					setplanmodifier.UseStateForUnknown(),
				},
			},
			"mitre_techniques": schema.SetAttribute{
				Description: "TODO",
				Computed:    true,
				ElementType: types.StringType,
				PlanModifiers: []planmodifier.Set{
					setplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				// TODO: validation
				// TODO: should this be modifiable? does it require replace?
				Description: "TODO",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"owner": schema.StringAttribute{
				Description: "TODO",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"scanner": schema.StringAttribute{
				// TODO: validation
				Description: "TODO",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"severity": schema.StringAttribute{
				// TODO: validation
				Description: "TODO",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"source": schema.StringAttribute{
				// TODO: validation
				Description: "TODO",
				Optional:    true,
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"sub_category": schema.StringAttribute{
				// TODO: validation
				Description: "TODO",
				Optional:    true,
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"updated_at": schema.StringAttribute{
				Description: "TODO",
				Computed:    true,
			},
		},
	}
}

// Configure adds the provider-configured client to the resource.
func (r *ApplicationSecurityRuleResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(*providerModels.CortexCloudSDKClients)

	if !ok {
		util.AddUnexpectedResourceConfigureTypeError(&resp.Diagnostics, "*http.Client", req.ProviderData)
		return
	}

	r.client = client.AppSec
}

// ModifyPlan modifies the planned state of the resource
//
// NOTE: Because this resource's implementation of this function only serves
// to validate the YAML definitions for each of the configured frameworks, it
// should *probably* be implemented in the ValidateConfiguration function
// instead, but I haven't found a way to be able to make it work in there since
// the API client isn't initialized when that function is called.
func (r *ApplicationSecurityRuleResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	// If the entire plan is null, the resource is planned for destruction
	if req.Plan.Raw.IsNull() {
		return
	}

	// Read Terraform plan data into model
	var plan models.ApplicationSecurityRuleModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Serialize framework YAML definitions
	for _, framework := range plan.Frameworks {
		yamlBytes, err := yaml.Marshal(framework.Definition.ValueString())
		if err != nil {
			resp.Diagnostics.AddError(
				"Error Converting YAML",
				err.Error(),
			)
			return
		}

		framework.Definition = types.StringValue(string(yamlBytes))
	}

	// Update frameworks attribute with serialized definitions
	resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("frameworks"), plan.Frameworks)...)

	//// If the resource already exists and the planned value of the frameworks
	//// attribute is equal to the value in the state, then no validation needs
	//// to occur
	//// TODO: fix this
	////if !req.State.Raw.IsNull() {
	////	var state models.ApplicationSecurityRuleModel
	////	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	////	if resp.Diagnostics.HasError() {
	////		return
	////	}

	////	if !state.Frameworks.IsNull() && plan.Frameworks.Equal(state.Frameworks) {
	////		return
	////	}
	////}

	//// Validate framework attribute definition against API
	//validationRequest := plan.ToValidateRequest(ctx, &resp.Diagnostics)
	//if resp.Diagnostics.HasError() {
	//	return
	//}

	//appSecAPI.Validate(ctx, &resp.Diagnostics, r.client, validationRequest)
}

// Create creates the resource and sets the initial Terraform state.
func (r *ApplicationSecurityRuleResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	//defer util.PanicHandler(&resp.Diagnostics)

	//// Read Terraform plan data into model
	//var plan models.ApplicationSecurityRuleModel
	//resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	//if resp.Diagnostics.HasError() {
	//	return
	//}

	//// Generate API create request body from plan
	//createRequest := plan.ToCreateOrCloneRequest(ctx, &resp.Diagnostics)
	//if resp.Diagnostics.HasError() {
	//	return
	//}

	//validateRequestData := []appsec.ValidateRequest{}
	//for _, framework := range createRequest.Frameworks {
	//	validateRequestData = append(validateRequestData, appsec.ValidateRequest{
	//		Framework:  framework.Name,
	//		Definition: framework.Definition,
	//	})
	//}

	//validateResponse, err := r.client.Validate(ctx, validateRequestData)
	//if err != nil {
	//	resp.Diagnostics.AddError(
	//		"Error Creating Or Cloning Application Security Rule",
	//		err.Error(),
	//	)
	//	return
	//}

	//if validateResponse.IsValid == nil || *validateResponse.IsValid == false {
	//	resp.Diagnostics.AddError(
	//		"Error Creating Or Cloning Application Security Rule",
	//		fmt.Sprintf("rule validation failed: %+v", validateResponse),
	//	)
	//	return

	//}

	//// Create new resource
	//response, err := r.client.CreateOrClone(ctx, createRequest)
	//if err != nil {
	//	resp.Diagnostics.AddError(
	//		"Error Creating Or Cloning Application Security Rule",
	//		err.Error(),
	//	)
	//	return
	//}

	//// Populate API response values in model
	//plan.RefreshFromRemote(ctx, &resp.Diagnostics, response)
	//if resp.Diagnostics.HasError() {
	//	return
	//}

	//// Set state to fully populated data
	//resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Read refreshes the Terraform state with the latest data.
func (r *ApplicationSecurityRuleResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	//defer util.PanicHandler(&resp.Diagnostics)

	//// Get current state
	//var state models.ApplicationSecurityRuleModel
	//resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	//if resp.Diagnostics.HasError() {
	//	return
	//}

	//// Retrieve resource from API
	//rule, err := r.client.Get(ctx, state.Id.ValueString())
	//if err != nil {
	//	resp.Diagnostics.AddError(
	//		"Error Reading Application Security Rule",
	//		err.Error(),
	//	)
	//	return
	//}

	//// Refresh state values
	//state.RefreshFromRemote(ctx, &resp.Diagnostics, rule)
	//if resp.Diagnostics.HasError() {
	//	return
	//}

	//// Set refreshed state
	//resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *ApplicationSecurityRuleResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	//defer util.PanicHandler(&resp.Diagnostics)

	//// Get current state
	//var state models.ApplicationSecurityRuleModel
	//resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	//if resp.Diagnostics.HasError() {
	//	return
	//}

	//// Read Terraform plan data into model
	//var plan models.ApplicationSecurityRuleModel
	//resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	//if resp.Diagnostics.HasError() {
	//	return
	//}

	//if err := mergo.MergeWithOverwrite(&state, plan); err != nil {
	//	resp.Diagnostics.AddError(
	//		"Error Updating Application Security Rule",
	//		fmt.Sprintf("Error occurred while merging existing application security rule with planned value: %s", err.Error()),
	//	)
	//	return
	//}

	//// Generate API create request body from plan
	//request := plan.ToUpdateRequest(ctx, &resp.Diagnostics)
	//if resp.Diagnostics.HasError() {
	//	return
	//}

	//// Update resource
	//response, err := r.client.Update(ctx, plan.Id.ValueString(), request)
	//if err != nil {
	//	resp.Diagnostics.AddError(
	//		"Error Updating Application Security Rule",
	//		err.Error(),
	//	)
	//	return
	//}

	//// Populate new values
	//plan.RefreshFromRemote(ctx, &resp.Diagnostics, response.Rule)
	//if resp.Diagnostics.HasError() {
	//	return
	//}

	//// Set refreshed state
	//resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Delete deletes the resource and removes it from the Terraform state on success.
func (r *ApplicationSecurityRuleResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	//defer util.PanicHandler(&resp.Diagnostics)

	//// Get current state
	//var state models.ApplicationSecurityRuleModel
	//resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	//if resp.Diagnostics.HasError() {
	//	return
	//}

	//// Delete resource
	//err := r.client.Delete(ctx, state.Id.ValueString())
	//if err != nil {
	//	resp.Diagnostics.AddError(
	//		"Error Deleting Application Security Rule",
	//		err.Error(),
	//	)
	//	return
	//}
}
