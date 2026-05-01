// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package compliance

import (
	"context"

	"github.com/PaloAltoNetworks/cortex-cloud-go/compliance"
	complianceModels "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/compliance"
	providerModels "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/provider"
	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/util"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ datasource.DataSource              = &controlsDataSource{}
	_ datasource.DataSourceWithConfigure = &controlsDataSource{}
)

func NewControlsDataSource() datasource.DataSource {
	return &controlsDataSource{}
}

type controlsDataSource struct {
	client *compliance.Client
}

func (d *controlsDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_compliance_controls"
}

func (d *controlsDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Provides a filtered list of Compliance Controls.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "Static identifier for the data source.",
				Computed:    true,
			},
			"search_from": schema.Int64Attribute{
				Description: "The starting index for pagination.",
				Optional:    true,
			},
			"search_to": schema.Int64Attribute{
				Description: "The ending index for pagination.",
				Optional:    true,
			},
			"controls": schema.ListNestedAttribute{
				Description: "The list of compliance controls.",
				Computed:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Description: "The ID of the compliance control.",
							Computed:    true,
						},
						"name": schema.StringAttribute{
							Description: "The name of the compliance control.",
							Computed:    true,
						},
						"description": schema.StringAttribute{
							Description: "The description of the compliance control.",
							Computed:    true,
						},
						"category": schema.StringAttribute{
							Description: "The category of the compliance control.",
							Computed:    true,
						},
						"category_description": schema.StringAttribute{
							Description: "The description of the category.",
							Computed:    true,
						},
						"subcategory": schema.StringAttribute{
							Description: "The subcategory of the compliance control.",
							Computed:    true,
						},
						"subcategory_description": schema.StringAttribute{
							Description: "The description of the subcategory.",
							Computed:    true,
						},
						"standards": schema.ListAttribute{
							Description: "The list of standards this control belongs to.",
							Computed:    true,
							ElementType: types.StringType,
						},
						"severity": schema.StringAttribute{
							Description: "The severity level of the control.",
							Computed:    true,
						},
						"supported": schema.BoolAttribute{
							Description: "Whether the control is supported.",
							Computed:    true,
						},
						"insertion_time": schema.Int64Attribute{
							Description: "The insertion timestamp of the control.",
							Computed:    true,
						},
						"modification_time": schema.Int64Attribute{
							Description: "The modification timestamp of the control.",
							Computed:    true,
						},
						"modified_by": schema.StringAttribute{
							Description: "The user who last modified the control.",
							Computed:    true,
						},
						"created_by": schema.StringAttribute{
							Description: "The user who created the control.",
							Computed:    true,
						},
						"enabled": schema.BoolAttribute{
							Description: "Whether the control is enabled.",
							Computed:    true,
						},
						"is_custom": schema.BoolAttribute{
							Description: "Whether the control is custom.",
							Computed:    true,
						},
					},
				},
			},
		},
		Blocks: map[string]schema.Block{
			"filter": schema.SingleNestedBlock{
				Description: "Filter criteria for the controls. \n\nNote: for the 'is_custom' field, use operator 'in' (the API does not support 'eq'; if 'eq' is specified it will be automatically converted to 'in').",
				Attributes: map[string]schema.Attribute{
					"field": schema.StringAttribute{
						Description: "The field to filter on.",
						Optional:    true,
					},
					"operator": schema.StringAttribute{
						Description: "The filter operator to use (e.g., 'in', 'contains').",
						Optional:    true,
					},
					"value": schema.StringAttribute{
						Description: "The value to filter by.",
						Optional:    true,
					},
				},
			},
		},
	}
}

func (d *controlsDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(*providerModels.CortexCloudSDKClients)
	if !ok {
		util.AddUnexpectedDataSourceConfigurationTypeError(&resp.Diagnostics, "*providerModels.CortexCloudSDKClients", req.ProviderData)
		return
	}

	d.client = client.Compliance
}

func (d *controlsDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	var config complianceModels.ControlsDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	listReq := config.ToListRequest(ctx, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	result, err := d.client.ListControls(ctx, listReq)
	if err != nil {
		resp.Diagnostics.AddError("Error Listing Compliance Controls", err.Error())
		return
	}

	config.RefreshFromRemote(ctx, &resp.Diagnostics, result.Controls)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &config)...)
}
