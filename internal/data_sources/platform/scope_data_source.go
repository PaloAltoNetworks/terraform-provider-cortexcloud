// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package platform

import (
	"context"
	"fmt"

	platformmodel "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/platform"

	platformsdk "github.com/PaloAltoNetworks/cortex-cloud-go/platform"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ datasource.DataSource              = &scopeDataSource{}
	_ datasource.DataSourceWithConfigure = &scopeDataSource{}
)

// scopeDataSource is the data source implementation.
type scopeDataSource struct {
	client *platformsdk.Client
}

func (d *scopeDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(*platformsdk.Client)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Data Source Configure Type",
			fmt.Sprintf("Expected *platformsdk.Client, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)
		return
	}

	d.client = client
}

func (d *scopeDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data platformmodel.ScopeModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Read the scope from the API.
	remote, err := d.client.GetScope(ctx, data.EntityType.ValueString(), data.EntityID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Error getting scope", err.Error())
		return
	}

	// Refresh the model from the remote object.
	data.RefreshFromRemote(ctx, &resp.Diagnostics, remote)

	// Set the state.
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Metadata returns the data source type name.
func (d *scopeDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_scope"
}

// Schema defines the schema for the data source.
func (d *scopeDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Gets a Cortex Cloud scope.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true,
			},
			"entity_type": schema.StringAttribute{
				Description: "The type of the entity.",
				Required:    true,
			},
			"entity_id": schema.StringAttribute{
				Description: "The ID of the entity.",
				Required:    true,
			},
			"assets": schema.SingleNestedAttribute{
				Description: "The assets scope.",
				Computed:    true,
				Attributes: map[string]schema.Attribute{
					"mode": schema.StringAttribute{
						Description: "The mode of the assets scope.",
						Computed:    true,
					},
					"asset_groups": schema.ListNestedAttribute{
						Description: "The asset groups in the scope.",
						Computed:    true,
						NestedObject: schema.NestedAttributeObject{
							Attributes: map[string]schema.Attribute{
								"asset_group_id": schema.Int64Attribute{
									Description: "The ID of the asset group.",
									Computed:    true,
								},
								"asset_group_name": schema.StringAttribute{
									Description: "The name of the asset group.",
									Computed:    true,
								},
							},
						},
					},
				},
			},
			"datasets_rows": schema.SingleNestedAttribute{
				Description: "The datasets rows scope.",
				Computed:    true,
				Attributes: map[string]schema.Attribute{
					"default_filter_mode": schema.StringAttribute{
						Description: "The default filter mode of the datasets rows scope.",
						Computed:    true,
					},
					"filters": schema.ListNestedAttribute{
						Description: "The filters in the datasets rows scope.",
						Computed:    true,
						NestedObject: schema.NestedAttributeObject{
							Attributes: map[string]schema.Attribute{
								"dataset": schema.StringAttribute{
									Description: "The dataset of the filter.",
									Computed:    true,
								},
								"filter": schema.StringAttribute{
									Description: "The filter expression.",
									Computed:    true,
								},
							},
						},
					},
				},
			},
			"endpoints": schema.SingleNestedAttribute{
				Description: "The endpoints scope.",
				Computed:    true,
				Attributes: map[string]schema.Attribute{
					"endpoint_groups": schema.SingleNestedAttribute{
						Description: "The endpoint groups scope.",
						Computed:    true,
						Attributes: map[string]schema.Attribute{
							"mode": schema.StringAttribute{
								Description: "The mode of the endpoint groups scope.",
								Computed:    true,
							},
							"tags": schema.ListNestedAttribute{
								Description: "The tags in the endpoint groups scope.",
								Computed:    true,
								NestedObject: schema.NestedAttributeObject{
									Attributes: map[string]schema.Attribute{
										"tag_id": schema.StringAttribute{
											Description: "The ID of the tag.",
											Computed:    true,
										},
										"tag_name": schema.StringAttribute{
											Description: "The name of the tag.",
											Computed:    true,
										},
									},
								},
							},
						},
					},
					"endpoint_tags": schema.SingleNestedAttribute{
						Description: "The endpoint tags scope.",
						Computed:    true,
						Attributes: map[string]schema.Attribute{
							"mode": schema.StringAttribute{
								Description: "The mode of the endpoint tags scope.",
								Computed:    true,
							},
							"tags": schema.ListNestedAttribute{
								Description: "The tags in the endpoint tags scope.",
								Computed:    true,
								NestedObject: schema.NestedAttributeObject{
									Attributes: map[string]schema.Attribute{
										"tag_id": schema.StringAttribute{
											Description: "The ID of the tag.", Computed: true,
										},
										"tag_name": schema.StringAttribute{
											Description: "The name of the tag.",
											Computed:    true,
										},
									},
								},
							},
						},
					},
				},
			},
			"cases_issues": schema.SingleNestedAttribute{
				Description: "The cases issues scope.",
				Computed:    true,
				Attributes: map[string]schema.Attribute{
					"mode": schema.StringAttribute{
						Description: "The mode of the cases issues scope.",
						Computed:    true,
					},
					"tags": schema.ListNestedAttribute{
						Description: "The tags in the cases issues scope.",
						Computed:    true,
						NestedObject: schema.NestedAttributeObject{
							Attributes: map[string]schema.Attribute{
								"tag_id": schema.StringAttribute{
									Description: "The ID of the tag.",
									Computed:    true,
								},
								"tag_name": schema.StringAttribute{
									Description: "The name of the tag.",
									Computed:    true,
								},
							},
						},
					},
				},
			},
		},
	}
}
