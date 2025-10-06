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
	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/validators"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-log/tflog"
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
						Description: "TODO",
						Computed:    true,
						Attributes: map[string]schema.Attribute{
							"type": schema.StringAttribute{
								Description: "Type of registry scanning. " +
									"Must be one of `ALL`, `LATEST_TAG` or " +
									"`TAGS_MODIFIED_DAYS`. If set to " +
									"`TAGS_MODIFIED_DAYS`, `last_days` must " +
									"be configured.",
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
					"agentless_disk_scanning": schema.BoolAttribute{
						Description: "TODO",
						Computed:    true,
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
				Computed:    true,
				Attributes: map[string]schema.Attribute{
					"audit_logs": schema.SingleNestedAttribute{
						Description: "Configuration for audit logs " +
							"collection.",
						Computed: true,
						Attributes: map[string]schema.Attribute{
							"enabled": schema.BoolAttribute{
								Description: "Whether to enable audit log " +
									"collection.",
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
				Computed: true,
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
					"outpost_id": schema.StringAttribute{
						Description: "TODO",
						Computed:    true,
					},
					"status_ui": schema.Int32Attribute{
						Description: "TODO",
						Computed:    true,
					},
				},
			},
			"scope": schema.StringAttribute{
				Description: "",
				Computed:    true,
				Validators: []validator.String{
					stringvalidator.OneOf(
						enums.AllScopes()...,
					),
				},
			},
			"security_capabilities": schema.SetNestedAttribute{
				Description: "TODO",
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
						"status": schema.StringAttribute{
							Description: "TODO",
							Computed:    true,
						},
						"status_code": schema.Int32Attribute{
							Description: "TODO",
							Computed:    true,
						},
						"last_scan_coverage": schema.SingleNestedAttribute{
							Description: "TODO",
							Computed:    true,
							Attributes: map[string]schema.Attribute{
								"excluded": schema.Int32Attribute{
									Description: "TODO",
									Computed:    true,
								},
								"issues": schema.Int32Attribute{
									Description: "TODO",
									Computed:    true,
								},
								"pending": schema.Int32Attribute{
									Description: "TODO",
									Computed:    true,
								},
								"success": schema.Int32Attribute{
									Description: "TODO",
									Computed:    true,
								},
								"unsupported": schema.Int32Attribute{
									Description: "TODO",
									Computed:    true,
								},
							},
						},
					},
				},
			},
			"status": schema.StringAttribute{
				Description: "Status of the integration.",
				Computed:    true,
			},
			"upgrade_available": schema.BoolAttribute{
				Description: "TODO",
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

	ctx = tflog.SetField(ctx, "resource_type", "CloudIntegrationInstanceDataSource")
	tflog.Debug(ctx, "Configuring SDK client")

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

	ctx = tflog.SetField(ctx, "resource_type", "CloudIntegrationInstanceDataSource")
	ctx = tflog.SetField(ctx, "resource_id_field", "id")

	// Populate data source configuration into model.
	var config models.CloudIntegrationInstanceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	ctx = tflog.SetField(ctx, "resource_id_value", config.ID.ValueString())

	// Retrieve integration details from API.
	if config.ID.IsNull() || config.ID.IsUnknown() {
		resp.Diagnostics.AddAttributeError(
			path.Root("id"),
			"Cloud Integration Instance Data Source Configuration Error",
			"Recieved null or unknown value for `id` attribute. Please report this issue to the developers.",
		)
	}

	data, err := r.client.GetIntegrationInstanceDetails(ctx, config.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(
			"Cloud Integration Instance Data Source Read Error",
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
