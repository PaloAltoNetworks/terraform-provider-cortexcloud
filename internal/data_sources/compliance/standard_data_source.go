// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package compliance

import (
	"context"

	"github.com/PaloAltoNetworks/cortex-cloud-go/compliance"
	complianceTypes "github.com/PaloAltoNetworks/cortex-cloud-go/types/compliance"
	complianceModels "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/compliance"
	providerModels "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/provider"
	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/util"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ datasource.DataSource              = &standardDataSource{}
	_ datasource.DataSourceWithConfigure = &standardDataSource{}
)

func NewStandardDataSource() datasource.DataSource {
	return &standardDataSource{}
}

type standardDataSource struct {
	client *compliance.Client
}

func (d *standardDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_compliance_standard"
}

func (d *standardDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Provides details about a Compliance Standard.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "The ID of the compliance standard.",
				Required:    true,
			},
			"name": schema.StringAttribute{
				Description: "The name of the compliance standard.",
				Computed:    true,
			},
			"description": schema.StringAttribute{
				Description: "The description of the compliance standard.",
				Computed:    true,
			},
			"version": schema.StringAttribute{
				Description: "The version of the compliance standard.",
				Computed:    true,
			},
			"assessments_profiles_count": schema.Int64Attribute{
				Description: "The number of assessment profiles using this standard.",
				Computed:    true,
			},
			"controls_ids": schema.SetAttribute{
				Description: "The set of control IDs associated with this standard.",
				Computed:    true,
				ElementType: types.StringType,
			},
			"labels": schema.SetAttribute{
				Description: "The set of labels for this standard.",
				Computed:    true,
				ElementType: types.StringType,
			},
			"revision": schema.Int64Attribute{
				Description: "The revision number of the standard.",
				Computed:    true,
			},
			"publisher": schema.StringAttribute{
				Description: "The publisher of the standard.",
				Computed:    true,
			},
			"release_date": schema.StringAttribute{
				Description: "The release date of the standard.",
				Computed:    true,
			},
			"created_date": schema.StringAttribute{
				Description: "The creation date of the standard.",
				Computed:    true,
			},
			"created_by": schema.StringAttribute{
				Description: "The user who created the standard.",
				Computed:    true,
			},
			"insert_ts": schema.Int64Attribute{
				Description: "The insertion timestamp.",
				Computed:    true,
			},
			"modify_ts": schema.Int64Attribute{
				Description: "The modification timestamp.",
				Computed:    true,
			},
			"is_custom": schema.BoolAttribute{
				Description: "Whether the standard is custom.",
				Computed:    true,
			},
		},
	}
}

func (d *standardDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

func (d *standardDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	var config complianceModels.StandardModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	getReq := complianceTypes.GetStandardRequest{
		ID: config.ID.ValueString(),
	}

	remote, err := d.client.GetStandard(ctx, getReq)
	if err != nil {
		resp.Diagnostics.AddError("Error Reading Compliance Standard", err.Error())
		return
	}

	config.RefreshFromRemote(ctx, &resp.Diagnostics, remote)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &config)...)
}
