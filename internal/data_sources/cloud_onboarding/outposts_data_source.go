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
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Ensure the implementation satisfies the expected interfaces.
var _ datasource.DataSource = &OutpostsDataSource{}

// NewOutpostsDataSource is a helper function to simplify the provider implementation.
func NewOutpostsDataSource() datasource.DataSource {
	return &OutpostsDataSource{}
}

// OutpostsDataSource is the data source implementation.
type OutpostsDataSource struct {
	client *cloudonboarding.Client
}

// Metadata returns the data source type name.
func (d *OutpostsDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_outposts"
}

// Schema defines the schema for the data source.
func (d *OutpostsDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Retrieves a list of outposts.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "Static identifier for the data source.",
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
			"status": schema.StringAttribute{
				Description: "",
				Optional:    true,
				Validators: []validator.String{
					stringvalidator.OneOf(
						enums.AllIntegrationInstanceStatuses()...,
					),
				},
			},
			"outpost_account_name": schema.StringAttribute{
				Description: "",
				Optional:    true,
			},
			"outpost_account_id": schema.Int64Attribute{
				Description: "",
				Optional:    true,
			},
			"created_at": schema.SingleNestedAttribute{
				Description: "",
				Optional:    true,
				Attributes: map[string]schema.Attribute{
					"from": schema.Int64Attribute{
						Description: "",
						Optional:    true,
						//Computed: true,
					},
					"to": schema.Int64Attribute{
						Description: "",
						Optional:    true,
						//Computed: true,
					},
				},
			},
			"number_of_instances": schema.SingleNestedAttribute{
				Description: "",
				Optional:    true,
				Attributes: map[string]schema.Attribute{
					"condition": schema.StringAttribute{
						Description: "",
						Optional:    true,
						//Computed: true,
					},
					"value": schema.StringAttribute{
						Description: "",
						Optional:    true,
						//Computed: true,
					},
				},
			},
			"outposts": schema.ListNestedAttribute{
				Description: "The list of outposts.",
				Computed:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Description: "The ID of the outpost.",
							Computed:    true,
						},
						"cloud_provider": schema.StringAttribute{
							Description: "The cloud provider of the outpost.",
							Computed:    true,
						},
						"created_at": schema.Int64Attribute{
							Description: "The creation time of the outpost.",
							Computed:    true,
						},
						"type": schema.StringAttribute{
							Description: "The type of the outpost.",
							Computed:    true,
						},
					},
				},
			},
		},
	}
}

// Configure adds the provider-configured client to the data source.
func (d *OutpostsDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	ctx = tflog.SetField(ctx, "data_source_type", "OutpostsDataSource")
	tflog.Debug(ctx, "Configuring SDK client")

	client, ok := req.ProviderData.(*providerModels.CortexCloudSDKClients)
	if !ok {
		util.AddUnexpectedDataSourceConfigurationTypeError(&resp.Diagnostics, "*providerModels.CortexCloudSDKClients", req.ProviderData)
		return
	}
	d.client = client.CloudOnboarding
}

// Read refreshes the Terraform state with the latest data.
func (d *OutpostsDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	ctx = tflog.SetField(ctx, "data_source_type", "OutpostsDataSource")

	var config models.OutpostsDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	listReq := config.ToListRequest(ctx, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	data, err := d.client.ListOutposts(ctx, listReq)
	if err != nil {
		resp.Diagnostics.AddError("Outposts Data Source Read Error", err.Error())
		return
	}

	config.RefreshFromRemote(ctx, &resp.Diagnostics, data.Data)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &config)...)
}
