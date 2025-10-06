// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package cloud_onboarding

import (
	"context"
	"fmt"

	"github.com/PaloAltoNetworks/cortex-cloud-go/cloudonboarding"
	"github.com/PaloAltoNetworks/cortex-cloud-go/enums"

	models "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/cloud_onboarding"
	providerModels "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/provider"
	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/util"
	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/validators"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/objectdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ resource.Resource               = &CloudIntegrationTemplateResource{}
	_ resource.ResourceWithModifyPlan = &CloudIntegrationTemplateResource{}
)

// NewCloudIntegrationTemplateResource is a helper function to simplify the provider implementation.
func NewCloudIntegrationTemplateResource() resource.Resource {
	return &CloudIntegrationTemplateResource{}
}

// CloudIntegrationTemplateResource is the resource implementation.
type CloudIntegrationTemplateResource struct {
	client *cloudonboarding.Client
}

// Metadata returns the resource type name.
func (r *CloudIntegrationTemplateResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cloud_integration_template"
}

// Schema defines the schema for the resource.
func (r *CloudIntegrationTemplateResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		// TODO: when populating the description, make sure to call out that
		// only AWS and GCP are currently supported.
		Description: "TODO",
		Attributes: map[string]schema.Attribute{
			//"account_details": schema.SingleNestedAttribute{
			//	Description: "TODO",
			//	Optional:    true,
			//	Computed:    true,
			//	Attributes: map[string]schema.Attribute{
			//		"organization_id": schema.StringAttribute{
			//			Description: "TODO",
			//			Required: true,
			//		},
			//	},
			//	Default: objectdefault.StaticValue(types.ObjectNull(map[string]attr.Type{"organization_id": types.StringType})),
			//},
			"additional_capabilities": schema.SingleNestedAttribute{
				Description: "Define which additional security capabilities " +
					"to enable. Note that adding additional capabilities " +
					"typically requires additional cloud provider " +
					"permissions. For more information, refer to the official documentation: " +
					"https://docs-cortex.paloaltonetworks.com/r/Cortex-CLOUD/Cortex-Cloud-Posture-Management-Documentation/Cloud-service-provider-permissions",
				MarkdownDescription: "Define which additional security capabilities " +
					"to enable. Note that adding additional capabilities " +
					"typically requires additional cloud provider " +
					"permissions. For more information, refer to the " +
					"[official documentation](https://docs-cortex.paloaltonetworks.com/r/Cortex-CLOUD/Cortex-Cloud-Posture-Management-Documentation/Cloud-service-provider-permissions).",
				Optional: true,
				Computed: true,
				// TODO: update all descriptions with more verbosity
				Attributes: map[string]schema.Attribute{
					"data_security_posture_management": schema.BoolAttribute{
						Description: "Enable data security posture management.",
						Optional:    true,
						Computed:    true,
						Default:     booldefault.StaticBool(true),
					},
					"registry_scanning": schema.BoolAttribute{
						Description: "Enable registry scanning.",
						Optional:    true,
						Computed:    true,
						Default:     booldefault.StaticBool(true),
					},
					"registry_scanning_options": schema.SingleNestedAttribute{
						Description: "TODO",
						Optional:    true,
						Computed:    true,
						Attributes: map[string]schema.Attribute{
							"type": schema.StringAttribute{
								Description: "Type of registry scanning. " +
									"Must be one of `ALL`, `LATEST_TAG` or " +
									"`TAGS_MODIFIED_DAYS`. If set to " +
									"`TAGS_MODIFIED_DAYS`, `last_days` must " +
									"be configured.",
								Optional: true,
								Computed: true,
								Validators: []validator.String{
									stringvalidator.OneOf(
										enums.AllRegistryScanningTypes()...,
									),
									validators.AlsoRequiresOnStringValues(
										[]string{
											enums.RegistryScanningTypeTagsModifiedDays.String(),
										},
										path.MatchRelative().AtParent().AtName("last_days"),
									),
								},
							},
							//"last_days": schema.Int32Attribute{
							//	Description: "Number of days within which " +
							//		"the tags on a registry image must have " +
							//		"been created or updated for the image " +
							//		"to be scanned. Minimum value is 0 and " +
							//		"maximum value is 90. Cannot be " +
							//		"configured if `type` is not set to " +
							//		"`TAGS_MODIFIED_DAYS`.",
							//	Optional: true,
							//	Computed: true,
							//	Validators: []validator.Int32{
							//		int32validator.Between(0, 90),
							//		int32validator.AlsoRequires(path.MatchRelative().AtParent().AtName("type")),
							//	},
							//	PlanModifiers: []planmodifier.Int32{
							//		planmodifiers.NullIfAlsoSetInt32(
							//			[]string{
							//				util.CloudIntegrationRegistryScanningTypeEnumAll,
							//				util.CloudIntegrationRegistryScanningTypeEnumLatestTag,
							//			},
							//		),
							//	},
							//	//Default: int32default.StaticInt32(90),
							//},
						},
					},
					// TODO: is this supposed to be "serverless *functions* scanning"?
					"serverless_scanning": schema.BoolAttribute{
						Description: "Enable serverless scanning.",
						Optional:    true,
						Computed:    true,
						Default:     booldefault.StaticBool(true),
					},
					"xsiam_analytics": schema.BoolAttribute{
						Description: "Whether to enable XSIAM analytics to " +
							"analyze your endpoint data to develop a " +
							"baseline and raise Analytics and Analytics " +
							"BIOC alerts when anomalies and malicious " +
							"behaviors are detected.",
						Optional: true,
						Computed: true,
						Default:  booldefault.StaticBool(true),
					},
				},
			},
			"cloud_provider": schema.StringAttribute{
				//Description: "The cloud service provider that is being " +
				//	"integrated. Must be one of `AWS`, `AZURE` or `GCP`.",
				Description: "The cloud service provider that is being " +
					"integrated. Must be either `AWS` or `GCP`.",
				Required: true,
				Validators: []validator.String{
					stringvalidator.OneOf(
						"AWS",
						"GCP",
					),

					// TODO: remove the above validator and use these when
					// Azure template creation is fixed

					//stringvalidator.OneOf(
					//	enums.AllCloudProviders()...,
					//),
					//validators.AlsoRequiresOnStringValues(
					//	[]string{
					//		enums.CloudProviderAzure.String(),
					//	},
					//	path.MatchRelative().AtParent().AtName("account_details"),
					//),
				},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"collection_configuration": schema.SingleNestedAttribute{
				Description: "Configure the data that will be collected.",
				Optional:    true,
				Computed:    true,
				Attributes: map[string]schema.Attribute{
					"audit_logs": schema.SingleNestedAttribute{
						Description: "Configuration for audit logs " +
							"collection.",
						Optional: true,
						Computed: true,
						Attributes: map[string]schema.Attribute{
							"enabled": schema.BoolAttribute{
								Description: "Toggle audit log collection.",
								Optional:    true,
								Computed:    true,
							},
						},
					},
				},
				// TODO: make helpers for this
				Default: objectdefault.StaticValue(
					types.ObjectValueMust(
						map[string]attr.Type{
							"audit_logs": types.ObjectType{
								AttrTypes: map[string]attr.Type{
									"enabled": types.BoolType,
								},
							},
						},
						map[string]attr.Value{
							"audit_logs": types.ObjectValueMust(
								map[string]attr.Type{
									"enabled": types.BoolType,
								},
								map[string]attr.Value{
									"enabled": types.BoolValue(true),
								},
							),
						},
					),
				),
			},
			"custom_resources_tags": schema.SetNestedAttribute{
				// TODO: prevent duplicate tag keys
				Description: "Custom tags that will be applied to any new " +
					"resource created by Cortex in the cloud environment. " +
					"By default, the `managed_by` tag will always be " +
					"applied with the value `paloaltonetworks`.",
				Optional: true,
				Computed: true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"key": schema.StringAttribute{
							Description: "The key of the custom resource tag.",
							Optional:    true,
							Computed:    true,
						},
						"value": schema.StringAttribute{
							Description: "The value of the custom resource tag.",
							Optional:    true,
							Computed:    true,
						},
					},
				},
			},
			"instance_name": schema.StringAttribute{
				// TODO: validation
				Description: "Name of the integration instance. If left " +
					"empty, the name will be auto-populated.",
				Optional: true,
				Computed: true,
				Validators: []validator.String{
					validators.ValidateCloudIntegrationInstanceName(),
				},
				Default: stringdefault.StaticString(""),
			},
			"scan_mode": schema.StringAttribute{
				// TODO: add description of outpost
				// TODO: verify that an outpost id is specified if set to MANAGED
				// TODO: find out how to get the default outpost id
				Description: "Define where the scanning for the cloud " +
					"environment will occur. Must be either `MANAGED` or " +
					"`OUTPOST`. If set to `MANAGED`, scanning will be done " +
					"in the Cortex Cloud tenant's environment. If set to " +
					"`OUTPOST`, scanning will be done on the cloud " +
					"infrastructure owned and managed by you." +
					"\n\nNOTE: Scanning with an outpost may require " +
					"additional CSP permissions and may incur additional " +
					"costs.",
				Required: true,
				Validators: []validator.String{
					stringvalidator.OneOf(
						enums.AllScanModes()...,
					),
				},
			},
			"scope": schema.StringAttribute{
				Description: "Define the scope for this integration " +
					"instance. Must be one of `ACCOUNT`, `ORGANIZATION` or " +
					"`ACCOUNT_GROUP`.",
				Required: true,
				Validators: []validator.String{
					stringvalidator.OneOf(
						enums.AllScopes()...,
					),
				},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			/*
				If scan scope is "ACCOUNT",
			*/
			"scope_modifications": schema.SingleNestedAttribute{
				Description: "Define the scope of scans by including/excluding " +
					"accounts or regions.",
				Optional: true,
				Computed: true,
				Attributes: map[string]schema.Attribute{
					"accounts": schema.SingleNestedAttribute{
						Description: "Configuration for account-level scope " +
							"modifications for AWS integrations. Cannot be " +
							"configured if `cloud_type` is not set to `AWS`.",
						Optional: true,
						Computed: true,
						Attributes: map[string]schema.Attribute{
							"enabled": schema.BoolAttribute{
								Description: "TODO",
								Optional:    true,
								Computed:    true,
							},
							"type": schema.StringAttribute{
								// TODO: validation ("INCLUDE", "EXCLUDE")
								Description: "TODO",
								Optional:    true,
								Computed:    true,
							},
							"account_ids": schema.SetAttribute{
								Description: "TODO",
								Optional:    true,
								Computed:    true,
								ElementType: types.StringType,
							},
						},
						Default: objectdefault.StaticValue(
							types.ObjectNull(
								map[string]attr.Type{
									"enabled": types.BoolType,
									"type":    types.StringType,
									"account_ids": types.SetType{
										ElemType: types.StringType,
									},
								},
							),
						),
					},
					"projects": schema.SingleNestedAttribute{
						Description: "TODO",
						Optional:    true,
						Computed:    true,
						Attributes: map[string]schema.Attribute{
							"enabled": schema.BoolAttribute{
								Description: "TODO",
								Optional:    true,
								Computed:    true,
							},
							"type": schema.StringAttribute{
								// TODO: validation ("INCLUDE", "EXCLUDE")
								Description: "TODO",
								Optional:    true,
								Computed:    true,
							},
							"project_ids": schema.SetAttribute{
								Description: "TODO",
								Optional:    true,
								Computed:    true,
								ElementType: types.StringType,
							},
						},
						Default: objectdefault.StaticValue(
							types.ObjectNull(
								map[string]attr.Type{
									"enabled": types.BoolType,
									"type":    types.StringType,
									"project_ids": types.SetType{
										ElemType: types.StringType,
									},
								},
							),
						),
					},
					"subscriptions": schema.SingleNestedAttribute{
						Description: "TODO",
						Optional:    true,
						Computed:    true,
						Attributes: map[string]schema.Attribute{
							"enabled": schema.BoolAttribute{
								Description: "TODO",
								Optional:    true,
								Computed:    true,
							},
							"type": schema.StringAttribute{
								// TODO: validation ("INCLUDE", "EXCLUDE")
								Description: "TODO",
								Optional:    true,
								Computed:    true,
							},
							"subscription_ids": schema.SetAttribute{
								Description: "TODO",
								Optional:    true,
								Computed:    true,
								ElementType: types.StringType,
							},
						},
						Default: objectdefault.StaticValue(
							types.ObjectNull(
								map[string]attr.Type{
									"enabled": types.BoolType,
									"type":    types.StringType,
									"subscription_ids": types.SetType{
										ElemType: types.StringType,
									},
								},
							),
						),
					},
					"regions": schema.SingleNestedAttribute{
						Description: "TODO",
						Optional:    true,
						Computed:    true,
						Attributes: map[string]schema.Attribute{
							// TODO: do we need an enabled attribute or is it
							// not needed since it's optional?
							"enabled": schema.BoolAttribute{
								Description: "TODO",
								Required:    true,
								// TODO: if this is true,
								//Optional:    true,
								//Computed:    true,
							},
							"type": schema.StringAttribute{
								// TODO: validation ("INCLUDE", "EXCLUDE")
								Description: "TODO",
								//Required:    true,
								Optional: true,
								//Computed:    true,
							},
							"regions": schema.SetAttribute{
								Description: "TODO",
								Optional:    true,
								//Computed:    true,
								ElementType: types.StringType,
							},
						},
						Default: objectdefault.StaticValue(
							types.ObjectNull(
								map[string]attr.Type{
									"enabled": types.BoolType,
									"type":    types.StringType,
									"regions": types.SetType{
										ElemType: types.StringType,
									},
								},
							),
						),
					},
				},
			},
			"status": schema.StringAttribute{
				Description: "Status of the integration.",
				Computed:    true,
				Default:     stringdefault.StaticString("PENDING"),
			},
			// TODO: Planmodifier to use state if config values are unchanged
			"tracking_guid": schema.StringAttribute{
				Description: "TODO (be sure to mention that this is the instance_id)",
				Computed:    true,
				//PlanModifiers: []planmodifier.String{
				//	stringplanmodifier.UseStateForUnknown(),
				//},
			},
			// TODO: make this a configurable attribute
			// (this is set to null in the platform if not configured)
			"outpost_id": schema.StringAttribute{
				Description: "TODO",
				Computed:    true,
				Default:     stringdefault.StaticString(""),
				//PlanModifiers: []planmodifier.String{
				//	stringplanmodifier.UseStateForUnknown(),
				//},
			},
			// TODO: Planmodifier to use state if config values are unchanged
			"automated_deployment_link": schema.StringAttribute{
				Description: "TODO",
				Computed:    true,
				//PlanModifiers: []planmodifier.String{
				//	stringplanmodifier.UseStateForUnknown(),
				//},
			},
			// TODO: Planmodifier to use state if config values are unchanged
			"manual_deployment_link": schema.StringAttribute{
				Description: "TODO",
				Computed:    true,
				//PlanModifiers: []planmodifier.String{
				//	stringplanmodifier.UseStateForUnknown(),
				//},
			},
			// TODO: Planmodifier to use state if config values are unchanged
			"cloud_formation_template_url": schema.StringAttribute{
				Description: "TODO",
				Optional:    true,
				Computed:    true,
				//PlanModifiers: []planmodifier.String{
				//	stringplanmodifier.UseStateForUnknown(),
				//},
			},
		},
	}
}

// Configure adds the provider-configured client to the resource.
func (r *CloudIntegrationTemplateResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	// Prevent panic if the provider has not been configured
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(*providerModels.CortexCloudSDKClients)

	if !ok {
		util.AddUnexpectedResourceConfigureTypeError(&resp.Diagnostics, "*http.Client", req.ProviderData)
		return
	}

	r.client = client.CloudOnboarding
}

func (r *CloudIntegrationTemplateResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	// If the entire plan is null, the resource is planned for destruction
	if req.Plan.Raw.IsNull() {
		resp.Diagnostics.AddWarning(
			"Resource Destruction Considerations",
			"Destroying this resource will only remove the "+
				"resource from the Terraform state. It will not delete the "+
				"template from your Cortex Cloud tenant due to API limitations. "+
				"To delete this template, open the Cortex Cloud console and "+
				"navigate to Settings > Data Sources, find and right-click the "+
				"template, and select \"Delete\".",
		)
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *CloudIntegrationTemplateResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	// Read Terraform plan data into model
	var plan models.CloudIntegrationTemplateModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Generate API request body from plan
	request := plan.ToCreateRequest(ctx, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	// Create new cloud onboarding integration template
	response, err := r.client.CreateIntegrationTemplate(ctx, request)
	if err != nil {
		resp.Diagnostics.AddError(
			"Cloud Integration Template Create Error", // TODO: standardize this
			//err.Error(),
			err.Error(),
		)
		return
	}

	// Populate API response values into model
	plan.RefreshComputedPropertyValues(&resp.Diagnostics, response)
	if resp.Diagnostics.HasError() {
		return
	}

	// Set state to fully populated data
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Read refreshes the Terraform state with the latest data.
func (r *CloudIntegrationTemplateResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	//// Get current state
	//var state models.CloudIntegrationTemplateModel
	//resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	//if resp.Diagnostics.HasError() {
	//	return
	//}

	//// Retrieve integration details from API
	//request := state.ToGetRequest(ctx, &resp.Diagnostics)
	//if resp.Diagnostics.HasError() {
	//	return
	//}

	//response, err := r.client.ListIntegrationInstances(ctx, request)
	//if err != nil {
	//	resp.Diagnostics.AddError(
	//		"Cloud Integration Template Read Error", // TODO: standardize this
	//		err.Error(),
	//	)
	//	return
	//}

	//// Refresh state values
	//state.RefreshConfiguredPropertyValues(ctx, &resp.Diagnostics, response)
	//if resp.Diagnostics.HasError() {
	//	return
	//}

	////state.RefreshComputedPropertyValues(ctx, &resp.Diagnostics, response)
	////if resp.Diagnostics.HasError() {
	////	return
	////}

	//// Set refreshed state
	//resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *CloudIntegrationTemplateResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	// Read Terraform plan data into model
	var plan models.CloudIntegrationTemplateModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Generate API request body from plan
	request := plan.ToUpdateRequest(ctx, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	// Update integration
	response, err := r.client.EditIntegrationInstance(ctx, request)
	if err != nil {
		resp.Diagnostics.AddError(
			"Cloud Integration Template Update Error", // TODO: standardize this
			err.Error(),
		)
		return
	}

	// Refresh state values
	plan.RefreshComputedPropertyValues(&resp.Diagnostics, response)
	if resp.Diagnostics.HasError() {
		return
	}

	// Set state to updated values
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Delete deletes the resource and removes it from the Terraform state on success.
func (r *CloudIntegrationTemplateResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	// Get current state
	var state models.CloudIntegrationTemplateModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.AddWarning(
		"Cloud Integration Template Not Deleted",
		fmt.Sprintf("Due to current limitations of the Cortex Cloud API, cloud integration templates cannot be deleted outside of the UI. To complete the deletion of this resource, navigate to Settings > Data Sources in the Cortex Cloud UI and manually delete the \"%s\" instance. You may need to remove the filter on instances with the status \"PENDING\" to find the instance in the results table.", state.InstanceName.ValueString()),
	)
}
