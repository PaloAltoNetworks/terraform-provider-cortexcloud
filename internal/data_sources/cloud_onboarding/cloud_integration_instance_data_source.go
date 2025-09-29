// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package cloudonboarding

import (
	"context"

	"github.com/PaloAltoNetworks/cortex-cloud-go/cloudonboarding"
	"github.com/PaloAltoNetworks/cortex-cloud-go/enums"

	models "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/cloud_onboarding"
	providerModels "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/provider"
	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/util"
	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/validators"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ datasource.DataSource = &CloudIntegrationInstanceDataSource{}
)

// NewCloudIntegrationInstanceDataSource is a helper function to simplify the provider implementation.
func NewCloudIntegrationInstanceDataSource() datasource.DataSource {
	return &CloudIntegrationInstanceDataSource{}
}

// CloudIntegrationInstanceDataSource is the data source implementation.
type CloudIntegrationInstanceDataSource struct {
	client *cloudonboarding.Client
}

// Metadata returns the data source type name.
func (r *CloudIntegrationInstanceDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cloud_integration_instance"
}

// Schema defines the schema for the data source.
func (r *CloudIntegrationInstanceDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "TODO",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "A unique identifier of the integration.",
				Required:    true,
			},
			"additional_capabilities": schema.SingleNestedAttribute{
				Description: "Define which additional security capabilities " +
					"to enable.",
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
					},
					"registry_scanning": schema.BoolAttribute{
						Description: "Whether to enable registry scanning, " +
							"a container registry scanner that scans " +
							"registry images for vulnerabilities, malware, " +
							"and secrets.",
						Optional: true,
						Computed: true,
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
							//},
						},
					},
					//"serverless_scanning": schema.BoolAttribute{
					//	Description: "TODO",
					//	Optional:    true,
					//	Computed:    true,
					//},
					"xsiam_analytics": schema.BoolAttribute{
						Description: "Whether to enable XSIAM analytics to " +
							"analyze your endpoint data to develop a " +
							"baseline and raise Analytics and Analytics " +
							"BIOC alerts when anomalies and malicious " +
							"behaviors are detected.",
						Optional: true,
						Computed: true,
					},
				},
			},
			"cloud_provider": schema.StringAttribute{
				Description: "The cloud service provider that is being " +
					"integrated. Must be one of `AWS`, `AZURE` or `GCP`.",
				Computed: true,
				Validators: []validator.String{
					stringvalidator.OneOf(
						enums.AllCloudProviders()...,
					),
				},
			},
			"collector": schema.StringAttribute{
				Description: "The cloud service provider that is being " +
					"integrated. Must be one of `AWS`, `AZURE` or `GCP`.",
				Computed: true,
				Validators: []validator.String{
					stringvalidator.OneOf(
						enums.AllCloudProviders()...,
					),
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
								Description: "Whether to enable audit log " +
									"collection.",
								Optional: true,
								Computed: true,
							},
						},
					},
				},
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
				Description: "Name of the integration instance. If left " +
					"empty, the name will be auto-populated.",
				Optional: true,
				Computed: true,
				Validators: []validator.String{
					validators.ValidateCloudIntegrationInstanceName(),
				},
			},
			"scan": schema.SingleNestedAttribute{
				Description: "TODO",
				Computed:    true,
				Attributes: map[string]schema.Attribute{
					"scan_method": schema.StringAttribute{
						Description: "TODO",
						Computed:    true,
						Validators: []validator.String{
							stringvalidator.OneOf(
								enums.AllScanModes()...,
							),
						},
					},
				},
			},
			"security_capabilities": schema.SetNestedAttribute{
				Description: "TODO",
				Optional:    true,
				Computed:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"name": schema.StringAttribute{
							Description: "TODO",
							Computed:    true,
						},
						"description": schema.StringAttribute{
							Description: "TODO",
							Computed:    true,
						},
						"status": schema.Int32Attribute{
							Description: "TODO",
							Computed:    true,
						},
					},
				},
			},
			"status": schema.StringAttribute{
				Description: "Status of the integration.",
				Computed:    true,
			},
		},
	}
}

// Configure adds the provider-configured client to the data source.
func (r *CloudIntegrationInstanceDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

// Read refreshes the Terraform state with the latest data.
func (r *CloudIntegrationInstanceDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	// Populate data source configuration into model
	var config models.CloudIntegrationInstanceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Retrieve integration details from API
	request := config.ToGetRequest(ctx, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	response, err := r.client.GetIntegrationInstanceDetails(ctx, request)
	if err != nil {
		resp.Diagnostics.AddError(
			"Cloud Integration Data Source Read Error", // TODO: standardize this
			err.Error(),
		)
		return
	}

	// Refresh state values
	config.RefreshPropertyValues(ctx, &resp.Diagnostics, response)
	if resp.Diagnostics.HasError() {
		return
	}

	// Set refreshed state
	resp.Diagnostics.Append(resp.State.Set(ctx, &config)...)
}
