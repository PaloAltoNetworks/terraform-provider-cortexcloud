// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package cloudonboarding

import (
	"context"

	"github.com/PaloAltoNetworks/cortex-cloud-go/cloudonboarding"
	"github.com/PaloAltoNetworks/cortex-cloud-go/enums"
	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/cloud_onboarding"
	providerModels "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/provider"
	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/util"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ datasource.DataSource = &CloudIntegrationInstancesDataSource{}
)

// NewCloudIntegrationInstancesDataSource is a helper function to simplify the provider implementation.
func NewCloudIntegrationInstancesDataSource() datasource.DataSource {
	return &CloudIntegrationInstancesDataSource{}
}

// CloudIntegrationInstancesDataSource is the data source implementation.
type CloudIntegrationInstancesDataSource struct {
	client *cloudonboarding.Client
}

// Metadata returns the data source type name.
func (d *CloudIntegrationInstancesDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cloud_integration_instances"
}

// Schema defines the schema for the data source.
func (d *CloudIntegrationInstancesDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Retrieves a list of cloud integration instances.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "The object ID.",
				Computed:    true,
			},
			"cloud_provider": schema.StringAttribute{
				Description: "",
				Optional:    true,
				Validators: []validator.String{
					stringvalidator.OneOf(
						enums.AllCloudProviders()...,
					),
				},
			},
			"name": schema.StringAttribute{
				Description: "The name to filter by.",
				Optional:    true,
			},
			"status": schema.StringAttribute{
				Description: "The status to filter by.",
				Optional:    true,
				Validators: []validator.String{
					stringvalidator.OneOf(
						enums.AllIntegrationInstanceStatuses()...,
					),
				},
			},
			"scope": schema.StringAttribute{
				Description: "The scope to filter by.",
				Optional:    true,
				Validators: []validator.String{
					stringvalidator.OneOf(
						enums.AllScopes()...,
					),
				},
			},
			"scan_mode": schema.StringAttribute{
				Description: "The scan mode to filter by.",
				Optional:    true,
				Validators: []validator.String{
					stringvalidator.OneOf(
						enums.AllScanModes()...,
					),
				},
			},
			"creation_time": schema.StringAttribute{
				Description: "The creation time to filter by (RFC 3339 format).",
				Optional:    true,
			},
			"outpost_id": schema.StringAttribute{
				Description: "The outpost ID to filter by.",
				Optional:    true,
			},
			"authentication_method": schema.StringAttribute{
				Description: "The authentication method to filter by.",
				Optional:    true,
			},
			"instance_id": schema.StringAttribute{
				Description: "The instance ID to filter by.",
				Optional:    true,
			},
			"instances": schema.ListNestedAttribute{
				Description: "The list of cloud integration instances.",
				Computed:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Description: "A unique identifier of the integration.",
							Computed:    true,
						},
						"account_name": schema.StringAttribute{
							Description: "The name of the account.",
							Computed:    true,
						},
						"total_accounts": schema.Int32Attribute{
							Description: "The total number of accounts.",
							Computed:    true,
						},
						"additional_capabilities": schema.SingleNestedAttribute{
							Description: "Define which additional security capabilities " +
								"to enable.",
							Computed: true,
							Attributes: map[string]schema.Attribute{
								"data_security_posture_management": schema.BoolAttribute{
									Description: "Whether to enable data security " +
										"posture management, an agentless data security " +
										"scanner that discovers, classifies, protects, " +
										"and governs sensitive data.",
									Computed: true,
								},
								"registry_scanning": schema.BoolAttribute{
									Description: "Whether to enable registry scanning, " +
										"a container registry scanner that scans " +
										"registry images for vulnerabilities, malware, " +
										"and secrets.",
									Computed: true,
								},
								"registry_scanning_options": schema.SingleNestedAttribute{
									Description: "Options for registry scanning.",
									Computed:    true,
									Attributes: map[string]schema.Attribute{
										"type": schema.StringAttribute{
											Description: "Type of registry scanning.",
											Computed:    true,
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
											Computed: true,
										},
									},
								},
								"agentless_disk_scanning": schema.BoolAttribute{
									Description: "Whether to enable agentless disk scanning.",
									Computed:    true,
								},
								"serverless_scanning": schema.BoolAttribute{
									Description: "Whether to enable serverless scanning to detect and remediate vulnerabilities within serverless functions during the development lifecycle. Default value is \"true\".",
									MarkdownDescription: "Whether to enable agentless disk " +
										"scanning to remotely detect and remediate " +
										"vulnerabilities during the development " +
										"lifecycle. Default value is `true`.",
									Computed: true,
								},
								"xsiam_analytics": schema.BoolAttribute{
									Description: "Whether to enable XSIAM analytics to " +
										"analyze your endpoint data to develop a " +
										"baseline and raise Analytics and Analytics " +
										"BIOC alerts when anomalies and malicious " +
										"behaviors are detected.",
									Computed: true,
								},
							},
						},
						"cloud_provider": schema.StringAttribute{
							Description: "The cloud service provider that is being integrated.",
							Computed:    true,
						},
						"custom_resources_tags": schema.SetNestedAttribute{
							Description: "Custom tags that will be applied to any new resource created by Cortex in the cloud environment.",
							Computed:    true,
							NestedObject: schema.NestedAttributeObject{
								Attributes: map[string]schema.Attribute{
									"key": schema.StringAttribute{
										Description: "The key of the custom resource tag.",
										Computed:    true,
									},
									"value": schema.StringAttribute{
										Description: "The value of the custom resource tag.",
										Computed:    true,
									},
								},
							},
						},
						"instance_name": schema.StringAttribute{
							Description: "Name of the integration instance. If left " +
								"empty, the name will be auto-populated.",
							Computed: true,
						},
						"scan_mode": schema.StringAttribute{
							Description: "The scan mode of the integration.",
							Computed:    true,
						},
						"scope": schema.StringAttribute{
							Description: "The scope of the integration.",
							Computed:    true,
						},
						"status": schema.StringAttribute{
							Description: "Status of the integration.",
							Computed:    true,
						},
						"provisioning_method": schema.StringAttribute{
							Description: "The provisioning method of the integration.",
							Computed:    true,
						},
						"update_status": schema.StringAttribute{
							Description: "The update status of the integration.",
							Computed:    true,
						},
						"is_pending_changes": schema.BoolAttribute{
							Description: "Indicates if there are pending changes.",
							Computed:    true,
						},
						"outpost_id": schema.StringAttribute{
							Description: "The ID of the outpost.",
							Computed:    true,
						},
						"creation_time": schema.Int64Attribute{
							Description: "The creation time of the integration.",
							Computed:    true,
						},
					},
				},
			},
			"total_count": schema.Int32Attribute{
				Description: "Total number of instances.",
				Computed:    true,
			},
		},
	}
}

// Configure adds the provider-configured client to the data source.
func (d *CloudIntegrationInstancesDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	// Prevent panic if the provider has not been configured
	if req.ProviderData == nil {
		return
	}

	ctx = tflog.SetField(ctx, "data_source_type", "CloudIntegrationInstancesDataSource")
	tflog.Debug(ctx, "Configuring SDK client")

	client, ok := req.ProviderData.(*providerModels.CortexCloudSDKClients)

	if !ok {
		util.AddUnexpectedDataSourceConfigurationTypeError(&resp.Diagnostics, "*providerModels.CortexCloudSDKClients", req.ProviderData)
		return
	}

	d.client = client.CloudOnboarding
}

// Read refreshes the Terraform state with the latest data.
func (d *CloudIntegrationInstancesDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	ctx = tflog.SetField(ctx, "data_source_type", "CloudIntegrationInstancesDataSource")

	// Populate data source configuration into model.
	var config models.CloudIntegrationInstancesDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Create list request from config
	listReq := config.ToListRequest(ctx, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	// Retrieve integration details from API.
	data, err := d.client.ListIntegrationInstances(ctx, listReq)
	if err != nil {
		resp.Diagnostics.AddError(
			"Cloud Integration Instances Data Source Read Error",
			err.Error(),
		)
		return
	}

	// Refresh attribute values
	config.RefreshFromRemote(ctx, &resp.Diagnostics, data)
	if resp.Diagnostics.HasError() {
		return
	}

	// Set refreshed state
	resp.Diagnostics.Append(resp.State.Set(ctx, &config)...)
}
