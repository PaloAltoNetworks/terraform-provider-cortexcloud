// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package cloud_onboarding

import (
	"context"
	"fmt"
	"strings"

	"github.com/PaloAltoNetworks/cortex-cloud-go/cloudonboarding"
	cortexTypes "github.com/PaloAltoNetworks/cortex-cloud-go/types/cloudonboarding"
	"github.com/PaloAltoNetworks/cortex-cloud-go/enums"

	models "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/cloud_onboarding"
	providerModels "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/provider"
	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/util"
	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/validators"

	"github.com/hashicorp/terraform-plugin-framework-validators/int32validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/objectdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/objectplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/setplanmodifier"
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
	resp.Schema = schema.Schema{
		Description: "Manages a cloud onboarding integration template for Azure.",
		Attributes: map[string]schema.Attribute{
			"account_details": schema.SingleNestedAttribute{
				Description: "Additional details required for account onboarding.",
				Required: true,
				Attributes: map[string]schema.Attribute{
					"organization_id": schema.StringAttribute{
						Required:    true,
						Description: "Your Azure tenant ID." +
							"\n\n~>**NOTE**: You must first approve Cortex " +
							"Cloud as an enterprise application in your " +
							"Azure tenant before attempting to create this " +
							"resource. If you attempt to create a template " +
							"for a tenant that has not approved the Cortex " +
							"Cloud application, the API will return an error.",
					},
				},
			},
			"additional_capabilities": schema.SingleNestedAttribute{
				Description: "Define which additional security capabilities to enable. " +
				"\n\n~>**NOTE**: adding additional capabilities " +
					"typically requires additional cloud provider " +
					"permissions. For more information, refer to the Cortex " +
					"Cloud Posture Management documentation: " +
					"https://docs-cortex.paloaltonetworks.com/r/Cortex-CLOUD/Cortex-Cloud-Posture-Management-Documentation/Cloud-service-provider-permissions",
				MarkdownDescription: "Define which additional security capabilities to enable. \n\n~>**NOTE** that adding additional capabilities typically requires additional cloud provider permissions. For more information, refer to the [Cortex Cloud Posture Management documentation](https://docs-cortex.paloaltonetworks.com/r/Cortex-CLOUD/Cortex-Cloud-Posture-Management-Documentation/Cloud-service-provider-permissions).",
				Optional: true,
				Computed: true,
				Attributes: map[string]schema.Attribute{
					"data_security_posture_management": schema.BoolAttribute{
						Description: "Whether to enable data security " +
							"posture management, an agentless data security " +
							"scanner that discovers, classifies, protects, " +
							"and governs sensitive data. Default value is \"true\".",
						MarkdownDescription: "Whether to enable data security " +
							"posture management, an agentless data security " +
							"scanner that discovers, classifies, protects, " +
							"and governs sensitive data. Default value is `true`.",
						Optional: true,
						Computed: true,
						Default:  booldefault.StaticBool(true),
					},
					"registry_scanning": schema.BoolAttribute{
						Description: "Whether to enable registry scanning, " +
							"a container registry scanner that scans " +
							"registry images for vulnerabilities, malware, " +
							"and secrets. Default value is \"true\".",
						MarkdownDescription: "Whether to enable registry scanning, " +
							"a container registry scanner that scans " +
							"registry images for vulnerabilities, malware, " +
							"and secrets. Default value is `true`.",
						Optional: true,
						Computed: true,
						Default:  booldefault.StaticBool(true),
					},
					"registry_scanning_options": schema.SingleNestedAttribute{
						Description: "Additional configuration options for" +
							"registry scanning. Default value is \"true\".",
						MarkdownDescription: "Additional configuration options for" +
							"registry scanning. Default value is `true`.",
						Optional: true,
						Computed: true,
						Attributes: map[string]schema.Attribute{
							"type": schema.StringAttribute{
								Description: "Type of registry scanning.",
								Required:    true,
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
						Default: objectdefault.StaticValue(
							types.ObjectValueMust(
								map[string]attr.Type{
									"type":      types.StringType,
									"last_days": types.Int32Type,
								},
								map[string]attr.Value{
									"type":      types.StringValue(enums.RegistryScanningTypeAll.String()),
									"last_days": types.Int32Null(),
								},
							),
						),
					},
					"agentless_disk_scanning": schema.BoolAttribute{
						Description: "Whether to enable agentless disk " +
							"scanning to remotely detect and remediate " +
							"vulnerabilities during the development " +
							"lifecycle. Default value is \"true\".",
						MarkdownDescription: "Whether to enable agentless disk " +
							"scanning to remotely detect and remediate " +
							"vulnerabilities during the development " +
							"lifecycle. Default value is `true`.",
						Optional: true,
						Computed: true,
						Default:  booldefault.StaticBool(true),
					},
					"xsiam_analytics": schema.BoolAttribute{
						Description: "Whether to enable XSIAM analytics to " +
							"analyze your endpoint data to develop a " +
							"baseline and raise Analytics and Analytics " +
							"BIOC alerts when anomalies and malicious " +
							"behaviors are detected. Default value is \"true\".",
						MarkdownDescription: "Whether to enable XSIAM analytics to " +
							"analyze your endpoint data to develop a " +
							"baseline and raise Analytics and Analytics " +
							"BIOC alerts when anomalies and malicious " +
							"behaviors are detected. Default value is `true`.",
						Optional: true,
						Computed: true,
						Default:  booldefault.StaticBool(true),
					},
					"serverless_scanning": schema.BoolAttribute{
						Description: "Whether to enable serverless scanning to detect and remediate vulnerabilities within serverless functions during the development lifecycle. Default value is \"true\".",
						MarkdownDescription: "Whether to enable agentless disk " +
							"scanning to remotely detect and remediate " +
							"vulnerabilities during the development " +
							"lifecycle. Default value is `true`.",
						Optional: true,
						Computed: true,
						Default:  booldefault.StaticBool(true),
					},
				},
				Default: objectdefault.StaticValue(
					types.ObjectValueMust(
						map[string]attr.Type{
							"data_security_posture_management": types.BoolType,
							"registry_scanning":                types.BoolType,
							"registry_scanning_options": types.ObjectType{
								AttrTypes: map[string]attr.Type{
									"type":      types.StringType,
									"last_days": types.Int32Type,
								},
							},
							"agentless_disk_scanning": types.BoolType,
							"xsiam_analytics":         types.BoolType,
							"serverless_scanning":         types.BoolType,
						},
						map[string]attr.Value{
							"data_security_posture_management": types.BoolValue(false),
							"registry_scanning":                types.BoolValue(true),
							"registry_scanning_options": types.ObjectValueMust(
								map[string]attr.Type{
									"type":      types.StringType,
									"last_days": types.Int32Type,
								},
								map[string]attr.Value{
									"type":      types.StringValue(enums.RegistryScanningTypeAll.String()),
									"last_days": types.Int32Null(),
								},
							),
							"agentless_disk_scanning": types.BoolValue(true),
							"xsiam_analytics":         types.BoolValue(true),
							"serverless_scanning":         types.BoolValue(true),
						},
					),
				),
				PlanModifiers: []planmodifier.Object{
					objectplanmodifier.RequiresReplaceIfConfigured(),
				},
			},
			"collection_configuration": schema.SingleNestedAttribute{
				Description: "Configure log data collection.",
				MarkdownDescription: "Configure log data collection.",
				Optional:    true,
				Computed:    true,
				Attributes: map[string]schema.Attribute{
					"audit_logs": schema.SingleNestedAttribute{
						Description: "Configuration for audit logs collection.",
						MarkdownDescription: "Configuration for audit logs collection.",
						Required:    true,
						Attributes: map[string]schema.Attribute{
							"enabled": schema.BoolAttribute{
								Description: "Whether to enable audit log collection. Default value is \"true\".",
								MarkdownDescription: "Whether to enable audit log collection. Default value is `true`.",
								Optional:    true,
								Computed:    true,
								Default:     booldefault.StaticBool(true),
							},
							"collection_method": schema.StringAttribute{
								Description: fmt.Sprintf("Method of audit log collection. Default value is \"%s\".", enums.AuditLogCollectionMethodAutomated.String()),
								MarkdownDescription: fmt.Sprintf("Method of audit log collection. Default value is `%s`.", enums.AuditLogCollectionMethodAutomated.String()),
								Optional:    true,
								Computed:    true,
								Default:     stringdefault.StaticString(enums.AuditLogCollectionMethodAutomated.String()),
								Validators: []validator.String{
									stringvalidator.OneOf(
										enums.AllAuditLogCollectionMethods()...,
									),
								},
							},
							"data_events": schema.BoolAttribute{
								Description: "Whether to collect data " +
									"events as part of audit log collection. Default value is \"false\".",
								MarkdownDescription: "Whether to collect data " +
									"events as part of audit log collection. Default value is `false`.",
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
				PlanModifiers: []planmodifier.Object{
					objectplanmodifier.RequiresReplaceIfConfigured(),
				},
			},
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
			"instance_name": schema.StringAttribute{
				// TODO: add guidance on results of empty value here
				Description: "The name of the integration template. When the template is executed, integrations will appear in the console with this value.",
				MarkdownDescription: "The name of the integration template. When the template is executed, integrations will appear in the console with this value.",
				Optional: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplaceIfConfigured(),
				},
			},
			"scan_mode": schema.StringAttribute{
				Description: fmt.Sprintf("Define what infrastructure the integration will use to scan cloud workloads. If set to \"MANAGED\", scanning will be done in the Cortex Cloud environment. If set to \"OUTPOST\", scanning will be done on infrastructure deployed to a cloud account owned by you. Possible values are: \"%s\". \n\n~>**NOTE** Scanning with an outpost may require additional CSP permissions and may incur additional costs.", strings.Join(enums.AllScanModes(), "\", \"")),
				MarkdownDescription: fmt.Sprintf("Define what infrastructure the integration will use to scan cloud workloads. If set to `MANAGED`, scanning will be done in the Cortex Cloud environment. If set to `OUTPOST`, scanning will be done on infrastructure deployed to a cloud account owned by you. Possible values are: `%s`. \n\n~>**NOTE** Scanning with an outpost may require additional CSP permissions and may incur additional costs.", strings.Join(enums.AllScanModes(), "`, `")),
				Required: true,
				Validators: []validator.String{
					stringvalidator.OneOf(
						enums.AllScanModes()...,
					),
					validators.AlsoRequiresOnStringValues(
						[]string{
							enums.ScanModeOutpost.String(),
						},
						path.MatchRelative().AtParent().AtName("outpost_id"),
					),
				},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplaceIfConfigured(),
				},
			},
			"scope": schema.StringAttribute{
				Description: fmt.Sprintf("Define the scope for this integration instance. Possible values are: \"%s\"", strings.Join(enums.AllScopes(), "\", \"")),
				MarkdownDescription: fmt.Sprintf("Define the scope for this integration instance. Possible values are: `%s`", strings.Join(enums.AllScopes(), "`, `")),
				Required: true,
				Validators: []validator.String{
					stringvalidator.OneOf(
						enums.AllScopes()...,
					),
				},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplaceIfConfigured(),
				},
			},
			"scope_modifications": schema.SingleNestedAttribute{
				Description: "Define the scope of scans by including/excluding " +
					"subscriptions or regions.",
				MarkdownDescription: "Define the scope of scans by including/excluding " +
					"subscriptions or regions.",
				Optional: true,
				Computed: true,
				Attributes: map[string]schema.Attribute{
					"subscriptions": schema.SingleNestedAttribute{
						Description: "Configuration for subscription-level " +
							"scope modifications for Azure integrations.",
						MarkdownDescription: "Configuration for " +
							"subscription-level scope modifications for " +
							"Azure integrations.",
						Optional: true,
						Computed: true,
						Attributes: map[string]schema.Attribute{
							"enabled": schema.BoolAttribute{
								Description: "Whether to enable this scope modification. Cannot be set to \"true\" if scope is set to \"ACCOUNT\". If enabled, the \"type\" and \"subscription_ids\" attributes must be configured as well.",
								MarkdownDescription: "Whether to enable this scope modification. Cannot be set to `true` if scope is set to `ACCOUNT`. If enabled, the `type` and `subscription_ids` attributes must be configured as well.",
								Required:    true,
								// TODO: add validation to prevent this from
								// being configured if scope set to `ACCOUNT`
								Validators: []validator.Bool{
									validators.AlsoRequiresOnBoolValue(
										true,
										path.MatchRelative().AtParent().AtName("type"),
									),
									validators.AlsoRequiresOnBoolValue(
										true,
										path.MatchRelative().AtParent().AtName("subscription_ids"),
									),
								},
							},
							"type": schema.StringAttribute{
								Description: fmt.Sprintf("Whether the specified subscription IDs should be included in the scope or excluded from the scope. Must be configured if \"enabled\" is set to \"true\" and scope is not set to `ACCOUNT`. Possible values are: \"%s\"", strings.Join(enums.AllScopeModificationTypes(), "\", \"")),
								MarkdownDescription: fmt.Sprintf("Whether the specified subscription IDs should be included in the scope or excluded from the scope. Must be configured if `enabled` is set to `true` and scope is not set to `ACCOUNT`. Possible values are: `%s`", strings.Join(enums.AllScopeModificationTypes(), "`, `")),
								Optional:    true,
								// TODO: add validation to prevent this from
								// being configured if scope set to `ACCOUNT`
								Validators: []validator.String{
									stringvalidator.OneOf(
										enums.AllScopeModificationTypes()...,
									),
								},
							},
							"subscription_ids": schema.SetAttribute{
								Description: "Subscription IDs to include or exclude from scans. Cannot be configured if scope is set to \"ACCOUNT\". If scope is set to \"ORGANIZATION\" or \"ACCOUNT_GROUP\" and enabled is set to \"true\", it must be configured with at least 1 value.",
								MarkdownDescription: "Subscription IDs to include or exclude from scans. Cannot be configured if scope is set to `ACCOUNT`. If scope is set to `ORGANIZATION` or `ACCOUNT_GROUP` and enabled is set to `true`, it must be configured with at least 1 value.",
								Optional:    true,
								ElementType: types.StringType,
								// TODO: add validation to prevent this from
								// being configured if scope set to `ACCOUNT`
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
								Description: "Whether to enable this scope modification. If set to \"true\", the \"type\" and \"regions\" attributes must be configured as well.",
								MarkdownDescription: "Whether to enable this scope modification. If set to `true`, the `type` and `regions` attributes must be configured as well.",
								Required:    true,
								Validators: []validator.Bool{
									validators.AlsoRequiresOnBoolValue(
										true,
										path.MatchRelative().AtParent().AtName("type"),
									),
									validators.AlsoRequiresOnBoolValue(
										true,
										path.MatchRelative().AtParent().AtName("regions"),
									),
								},
							},
							"type": schema.StringAttribute{
								Description: fmt.Sprintf("Whether the specified regions should be included in the scope or excluded from the scope. Must be configured if \"enabled\" is set to \"true\". Possible values are: \"%s\"", strings.Join(enums.AllScopeModificationTypes(), "\", \"")),
								MarkdownDescription: fmt.Sprintf("Whether the specified regions should be included in the scope or excluded from the scope. Must be configured if `enabled` is set to `true`. Possible values are: `%s`", strings.Join(enums.AllScopeModificationTypes(), "`, `")),
								Optional:    true,
								Validators: []validator.String{
									stringvalidator.OneOf(
										enums.AllScopeModificationTypes()...,
									),
								},
							},
							"regions": schema.SetAttribute{
								Description: "Regions to include or exclude from scans. Must be configured with at least 1 value if \"enabled\" is set to \"true\".",
								MarkdownDescription: "Regions to include or exclude from scans. Must be configured with at least 1 value if `enabled` is set to `true`.",
								Optional:    true,
								ElementType: types.StringType,
								Validators: []validator.Set{
									setvalidator.SizeAtLeast(1),
								},
							},
						},
						Default: objectdefault.StaticValue(
							types.ObjectValueMust(
								map[string]attr.Type{
									"enabled": types.BoolType,
									"type":    types.StringType,
									"regions": types.SetType{
										ElemType: types.StringType,
									},
								},
								map[string]attr.Value{
									"enabled": types.BoolValue(false),
									"type":    types.StringNull(),
									"regions": types.SetNull(types.StringType),
								},
							),
						),
					},
				},
				Default: objectdefault.StaticValue(
					types.ObjectValueMust(
						map[string]attr.Type{
							"subscriptions": types.ObjectType{
								AttrTypes: map[string]attr.Type{
									"enabled": types.BoolType,
									"type":    types.StringType,
									"subscription_ids": types.SetType{
										ElemType: types.StringType,
									},
								},
							},
							"regions": types.ObjectType{
								AttrTypes: map[string]attr.Type{
									"enabled": types.BoolType,
									"type":    types.StringType,
									"regions": types.SetType{
										ElemType: types.StringType,
									},
								},
							},
						},
						map[string]attr.Value{
							"subscriptions": types.ObjectNull(
								map[string]attr.Type{
									"enabled": types.BoolType,
									"type":    types.StringType,
									"subscription_ids": types.SetType{
										ElemType: types.StringType,
									},
								},
							),
							"regions": types.ObjectValueMust(
								map[string]attr.Type{
									"enabled": types.BoolType,
									"type":    types.StringType,
									"regions": types.SetType{
										ElemType: types.StringType,
									},
								},
								map[string]attr.Value{
									"enabled": types.BoolValue(false),
									"type":    types.StringNull(),
									"regions": types.SetNull(types.StringType),
								},
							),
						},
					),
				),
				PlanModifiers: []planmodifier.Object{
					objectplanmodifier.RequiresReplaceIfConfigured(),
				},
			},
			"outpost_id": schema.StringAttribute{
				// TODO: allow user to specify the name of an outpost (if its unique)
				// which we then go and retrieve the ID of.
				Description: "The ID of the outpost that will be used for scanning. Must be configured if \"scan_mode\" is set to \"OUTPOST\".",
				MarkdownDescription: "The ID of the outpost that will be used for scanning. Must be configured if `scan_mode` is set to `OUTPOST`.",
				Optional:    true,
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
					stringplanmodifier.RequiresReplaceIfConfigured(),
				},
			},
			"status": schema.StringAttribute{
				Description: "Status of the template.",
				MarkdownDescription: "Status of the template.",
				Computed:    true,
				Default:     stringdefault.StaticString(enums.IntegrationInstanceStatusPending.String()),
			},
			"tracking_guid": schema.StringAttribute{
				Description: "The unique ID value assigned to this template after creation.",
				MarkdownDescription: "The unique ID value assigned to this template after creation.",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
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
			"arm_template_url": schema.StringAttribute{
				Description: "The full URL returned by Cortex Cloud when selecting the Azure Resource Manager method of downloading the template. Opening this URL in your browser will begin a download of the created template as an ARM template, which you can then deploy to permit Cortex Cloud to scan your Azure resources.",
				MarkdownDescription: "The full URL returned by Cortex Cloud when selecting the Azure Resource Manager method of downloading the template. Opening this URL in your browser will begin a download of the created template as an ARM template, which you can then deploy to permit Cortex Cloud to scan your Azure resources.",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
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
			"Manual Deletion Required for Cloud Integration Template Resources",
			fmt.Sprintf("Destroying this resource will only remove it from the Terraform state. You may manually delete the template in the Cortex UI by navigating to Settings > Data Sources, right-clicking the record with the ID value \"%s\", and clicking \"Delete\". If you do not see the template in Data Sources, adjust the table filters to include rows with a status of \"PENDING\".", state.TrackingGUID.ValueString()),
		)
	}
}

func fetchTemplateAzure(ctx context.Context, diagnostics *diag.Diagnostics, sdkClient *cloudonboarding.Client, model models.CloudIntegrationTemplateAzureModel) []cortexTypes.IntegrationInstance {
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

	// Fetch the created template and populate OutpostID
	trackingGUID, trackingGuidErr := createResponse.GetTrackingGUIDFromARMURL()
	if trackingGUID != "" && trackingGuidErr == nil {
		tflog.Debug(ctx, "Fetching created template")
		plan.TrackingGUID = types.StringValue(trackingGUID)
		response := fetchTemplateAzure(ctx, &resp.Diagnostics, r.client, plan)	
		if resp.Diagnostics.HasError() {
			return
		}

		if len(response) == 1 && response[0].OutpostID != "" {
			plan.OutpostID = types.StringValue(response[0].OutpostID)
		} else {
			plan.OutpostID = types.StringNull()
		}
	} else {
		if trackingGuidErr != nil {
			tflog.Debug(ctx, fmt.Sprintf("No Tracking GUID found: %s", trackingGuidErr.Error()))
		} else {
			tflog.Debug(ctx, "No Tracking GUID found")
		}

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

	tflog.Debug(ctx, "Fetching template")
	response := fetchTemplateAzure(ctx, &resp.Diagnostics, r.client, state)	
	if resp.Diagnostics.HasError() {
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
			"Cortex Cloud returned multiple results for this resource. " +
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
func (r *CloudIntegrationTemplateAzureResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	defer util.PanicHandler(&resp.Diagnostics)
	
	ctx = tflog.SetField(ctx, "resource_type", "cloud_integration_template_azure")
	ctx = tflog.SetField(ctx, "resource_id_field", "tracking_guid")
	ctx = tflog.SetField(ctx, "resource_operation", "Update")

	// The resource should require replacement upon modifying any of the 
	// configurable attributes, but as a fallback we will remove the resource
	// from the state.
	resp.State.RemoveResource(ctx)
}

// Delete deletes the resource and removes it from the Terraform state on success.
func (r *CloudIntegrationTemplateAzureResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	defer util.PanicHandler(&resp.Diagnostics)
}
