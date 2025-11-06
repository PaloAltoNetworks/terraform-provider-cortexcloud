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
	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/planmodifiers"
	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/util"
	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/validators"

	"github.com/hashicorp/terraform-plugin-framework-validators/int32validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
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
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ resource.Resource               = &CloudIntegrationTemplateAzureResource{}
	_ resource.ResourceWithModifyPlan = &CloudIntegrationTemplateAzureResource{}
)

// NewCloudIntegrationTemplateAzureResource is a helper function to simplify the provider implementation.
func NewCloudIntegrationTemplateAzureResource() resource.Resource {
	return &CloudIntegrationTemplateAzureResource{}
}

// CloudIntegrationTemplateAzureResource is the resource implementation.
type CloudIntegrationTemplateAzureResource struct {
	client *cloudonboarding.Client
}

// Metadata returns the resource type name.
func (r *CloudIntegrationTemplateAzureResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cloud_integration_template_azure"
}

// Schema defines the schema for the resource.
func (r *CloudIntegrationTemplateAzureResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	configurableAttributes := []path.Path{
		path.Root("instance_name"),
		path.Root("scan_mode"),
		path.Root("scope"),
	}
	useStateIfConfigUnchangedModifier := planmodifiers.StringUseStateIfConfigUnchanged(configurableAttributes)

	resp.Schema = schema.Schema{
		Description: "Manages a cloud onboarding integration template for Azure.",
		Attributes: map[string]schema.Attribute{
			"account_details": schema.SingleNestedAttribute{
				Description: "Additional required configuration parameters " +
					"for Azure tenants.",
				Required: true,
				Attributes: map[string]schema.Attribute{
					"organization_id": schema.StringAttribute{
						Description: "Azure tenant ID.",
						Required:    true,
					},
				},
			},
			"additional_capabilities": schema.SingleNestedAttribute{
				Description: "Define which additional security capabilities " +
					"to enable. Note that adding additional capabilities " +
					"typically requires additional cloud provider " +
					"permissions. For more information, refer to the Cortex " +
					"Cloud Posture Management documentation: " +
					"https://docs-cortex.paloaltonetworks.com/r/Cortex-CLOUD/Cortex-Cloud-Posture-Management-Documentation/Cloud-service-provider-permissions",
				MarkdownDescription: "Define which additional security capabilities " +
					"to enable. Note that adding additional capabilities " +
					"typically requires additional cloud provider " +
					"permissions. For more information, refer to the " +
					"[Cortex Cloud Posture Management documentation]" +
					"(https://docs-cortex.paloaltonetworks.com/r/Cortex-CLOUD/Cortex-Cloud-Posture-Management-Documentation/Cloud-service-provider-permissions).",
				Optional: true,
				Computed: true,
				Attributes: map[string]schema.Attribute{
					"data_security_posture_management": schema.BoolAttribute{
						Description: "Whether to enable data security " +
							"posture management, an agentless data security " +
							"scanner that discovers, classifies, protects, " +
							"and governs sensitive data.",
						Optional: true,
						Computed: true,
						Default:  booldefault.StaticBool(true),
					},
					"registry_scanning": schema.BoolAttribute{
						Description: "Whether to enable registry scanning, " +
							"a container registry scanner that scans " +
							"registry images for vulnerabilities, malware, " +
							"and secrets.",
						Optional: true,
						Computed: true,
						Default:  booldefault.StaticBool(true),
					},
					"registry_scanning_options": schema.SingleNestedAttribute{
						Description: "Additional configuration options for" +
							"registry scanning.",
						Optional: true,
						Computed: true,
						Attributes: map[string]schema.Attribute{
							"type": schema.StringAttribute{
								Description: "Type of registry scanning.",
								Optional:    true,
								Computed:    true,
								Default:     stringdefault.StaticString(enums.RegistryScanningTypeAll.String()),
								Validators: []validator.String{
									stringvalidator.OneOf(
										enums.AllRegistryScanningTypes()...
									),
									validators.AlsoRequiresOnStringValues(
										[]string{
											enums.RegistryScanningTypeTagsModifiedDays.String(),
										},
										path.MatchRelative().AtParent().AtName("last_days"),
									),
								},
							},
							"last_days": schema.Int32Attribute{
								Description: "Number of days within which " +
									"the tags on a registry image must have " +
									"been created or updated for the image " +
									"to be scanned. Minimum value is 0 and " +
									"maximum value is 90. Cannot be " +
									"configured if \"type\" is not set to " +
									"\"TAGS_MODIFIED_DAYS\".",
								MarkdownDescription: "Number of days within which " +
									"the tags on a registry image must have " +
									"been created or updated for the image " +
									"to be scanned. Minimum value is 0 and " +
									"maximum value is 90. Cannot be " +
									"configured if `type` is not set to " +
									"`TAGS_MODIFIED_DAYS`.",
								Optional: true,
								Validators: []validator.Int32{
									int32validator.Between(0, 90),
								},
							},
						},
					},
					"agentless_disk_scanning": schema.BoolAttribute{
						Description: "Whether to enable agentless disk " +
							"scanning to remotely detect and remediate " +
							"vulnerabilities during the development " +
							"lifecycle.",
						Optional: true,
						Computed: true,
						Default:  booldefault.StaticBool(true),
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
			"collection_configuration": schema.SingleNestedAttribute{
				Description: "Configure log data collection.",
				Optional:    true,
				Computed:    true,
				Attributes: map[string]schema.Attribute{
					"audit_logs": schema.SingleNestedAttribute{
						Description: "Configuration for audit logs collection.",
						Optional:    true,
						Computed:    true,
						Attributes: map[string]schema.Attribute{
							"enabled": schema.BoolAttribute{
								Description: "Whether to enable audit log collection.",
								Optional:    true,
								Computed:    true,
								Default:     booldefault.StaticBool(true),
							},
							"collection_method": schema.StringAttribute{
								Description: "Method of audit log collection.",
								Optional:    true,
								Computed:    true,
								Default:     stringdefault.StaticString(enums.AuditLogCollectionMethodAutomated.String()),
								Validators: []validator.String{
									stringvalidator.OneOf(
										enums.AllAuditLogCollectionMethods()...
									),
								},
							},
							"data_events": schema.BoolAttribute{
								Description: "Whether to collect data " +
									"events as part of audit log collection.",
								Optional: true,
								Computed: true,
								Default:  booldefault.StaticBool(false),
							},
						},
					},
				},
				Default: objectdefault.StaticValue(
					types.ObjectValueMust(
						map[string]attr.Type{
							"audit_logs": types.ObjectType{
								AttrTypes: map[string]attr.Type{
									"enabled":           types.BoolType,
									"collection_method": types.StringType,
									"data_events":       types.BoolType,
								},
							},
						},
						map[string]attr.Value{
							"audit_logs": types.ObjectValueMust(
								map[string]attr.Type{
									"enabled":           types.BoolType,
									"collection_method": types.StringType,
									"data_events":       types.BoolType,
								},
								map[string]attr.Value{
									"enabled":           types.BoolValue(true),
									"collection_method": types.StringValue(enums.AuditLogCollectionMethodAutomated.String()),
									"data_events":       types.BoolValue(false),
								},
							),
						},
					),
				),
			},
			"custom_resources_tags": schema.SetNestedAttribute{
				Description: "Tags applied to any new resource created by " +
					"Cortex Cloud in the cloud environment." +
					"\n\n" +
					"The tag \"managed_by\" with the value " +
					"\"paloaltonetworks\" will be applied by default.",
				MarkdownDescription: "Tags applied to any new resource created by " +
					"Cortex Cloud in the cloud environment." +
					"\n\n" +
					"The tag `managed_by` with the value " +
					"`paloaltonetworks` will be applied by default.",
				Optional: true,
				Computed: true,
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
			},
			"instance_name": schema.StringAttribute{
				Description: "Name of the integration instance. If left " +
					"empty, the name will be auto-populated.",
				Optional: true,
				//Validators: []validator.String{
				//	validators.ValidateCloudIntegrationInstanceName(),
				//},
			},
			"scan_mode": schema.StringAttribute{
				Description: "Define what infrastructure the integration " +
					"will use to scan cloud workloads. If set to" +
					"\"MANAGED\", scanning will be done in the Cortex Cloud" +
					"environment. If set to `OUTPOST`, scanning will be done on infrastructure deployed to a cloud account owned by you. Default value is \"%s\". Possible values are: \"%s\"." +
					"\n\nNOTE: Scanning with an outpost may require " +
					"additional CSP permissions and may incur additional " +
					"costs.",
				Optional: true,
				Computed: true,
				Validators: []validator.String{
					stringvalidator.OneOf(
						enums.AllScanModes()...
					),
					validators.AlsoRequiresOnStringValues(
						[]string{
							enums.ScanModeOutpost.String(),
						},
						path.MatchRelative().AtParent().AtName("outpost_id"),
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
						enums.AllScopes()...
					),
				},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"scope_modifications": schema.SingleNestedAttribute{
				Description: "Define the scope of scans by including/excluding " +
					"accounts or regions.",
				Optional: true,
				Computed: true,
				Attributes: map[string]schema.Attribute{
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
								Description: "TODO",
								Optional:    true,
								Computed:    true,
								Validators: []validator.String{
									stringvalidator.OneOf(
										enums.AllScopeModificationTypes()...
									),
								},
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
							"enabled": schema.BoolAttribute{
								Description: "TODO",
								Required:    true,
								Validators: []validator.Bool{
									validators.AlsoRequiresOnBoolValue(
										true,
										path.MatchRelative().AtParent().AtName("type"),
										path.MatchRelative().AtParent().AtName("regions"),
									),
								},
							},
							"type": schema.StringAttribute{
								Description: "TODO",
								Optional:    true,
								Computed:    true,
								PlanModifiers: []planmodifier.String{
									planmodifiers.StringSuppressIfAttributeEquals(
										path.Root("scan_mode"), 
										types.StringValue(enums.ScanModeManaged.String()),
									),
								},
								Validators: []validator.String{
									stringvalidator.OneOf(
										enums.AllScopeModificationTypes()...
									),
								},
							},
							"regions": schema.SetAttribute{
								Description: "TODO",
								Optional:    true,
								ElementType: types.StringType,
								Validators: []validator.Set{
									setvalidator.SizeAtLeast(1),
								},
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
				Default:     stringdefault.StaticString(enums.IntegrationInstanceStatusPending.String()),
			},
			"tracking_guid": schema.StringAttribute{
				Description: "TODO (be sure to mention that this is the instance_id)",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"outpost_id": schema.StringAttribute{
				Description: "TODO",
				Optional:    true,
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					useStateIfConfigUnchangedModifier,
					planmodifiers.ToNullStringIfUnknown(),
				},
			},
			"automated_deployment_url": schema.StringAttribute{
				Description: "TODO",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					useStateIfConfigUnchangedModifier,
				},
			},
			"manual_deployment_url": schema.StringAttribute{
				Description: "TODO",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					useStateIfConfigUnchangedModifier,
				},
			},
			"arm_template_url": schema.StringAttribute{
				Description: "TODO",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					useStateIfConfigUnchangedModifier,
				},
			},
		},
	}
}

// Configure adds the provider-configured client to the resource.
func (r *CloudIntegrationTemplateAzureResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	// Prevent panic if the provider has not been configured
	if req.ProviderData == nil {
		return
	}

	ctx = tflog.SetField(ctx, "resource_type", "cloud_integration_template_azure")
	ctx = tflog.SetField(ctx, "resource_operation", "Configure")
	tflog.Debug(ctx, "Configuring SDK client")

	client, ok := req.ProviderData.(*providerModels.CortexCloudSDKClients)

	if !ok {
		util.AddUnexpectedResourceConfigureTypeError(&resp.Diagnostics, "*http.Client", req.ProviderData)
		return
	}

	r.client = client.CloudOnboarding
}

func (r *CloudIntegrationTemplateAzureResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	ctx = tflog.SetField(ctx, "resource_type", "cloud_integration_template_azure")
	ctx = tflog.SetField(ctx, "resource_operation", "ModifyPlan")
	tflog.Debug(ctx, "Executing ModifyPlan")

	

	// If the entire plan is null, the resource is planned for destruction
	if req.Plan.Raw.IsNull() {
		var state models.CloudIntegrationTemplateAzureModel
		resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
		if resp.Diagnostics.HasError() {
			return
		}
		resp.Diagnostics.AddWarning(
			"Manual Deletion Required for Cloud Integration Template",
			fmt.Sprintf("Terraform will remove this resource from the state, but cannot delete the cloud integration template with ID \"%s\" from Cortex due to API limitations. To complete the deletion, manually remove it in the Cortex UI under Settings > Data Sources. You may need to adjust filters to find templates with a 'PENDING' status.", state.TrackingGUID.ValueString()),
		)
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *CloudIntegrationTemplateAzureResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	ctx = tflog.SetField(ctx, "resource_type", "cloud_integration_template_azure")
	ctx = tflog.SetField(ctx, "resource_operation", "Create")

	// Retrieve values from plan
	tflog.Debug(ctx, "Retrieving values from plan")
	var plan models.CloudIntegrationTemplateAzureModel
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
func (r *CloudIntegrationTemplateAzureResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	ctx = tflog.SetField(ctx, "resource_type", "cloud_integration_template_azure")
	ctx = tflog.SetField(ctx, "resource_id_field", "tracking_guid")
	ctx = tflog.SetField(ctx, "resource_operation", "Read")

	// Retrieve values from state
	tflog.Debug(ctx, "Retrieving values from state")
	var state models.CloudIntegrationTemplateAzureModel
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
			"Multiple values returned for the following arguments: "+
				"status, instance_name, account_name, outpost_id, creation_time\n\n"+
				"The provider will attempt to populate these arguments during "+
				"the next terraform refresh or apply operation.",
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
func (r *CloudIntegrationTemplateAzureResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	defer util.PanicHandler(&resp.Diagnostics)
	//resp.Diagnostics.AddWarning(
	//	"Updating Not Supported",
	//	//"Cloud integration templates do not support updates. If you wish to change 
	//)
	resp.State.RemoveResource(ctx)
}

// Delete deletes the resource and removes it from the Terraform state on success.
func (r *CloudIntegrationTemplateAzureResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	defer util.PanicHandler(&resp.Diagnostics)
}
