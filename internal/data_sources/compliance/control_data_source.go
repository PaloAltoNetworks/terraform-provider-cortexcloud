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
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	_ datasource.DataSource              = &controlDataSource{}
	_ datasource.DataSourceWithConfigure = &controlDataSource{}
)

func NewControlDataSource() datasource.DataSource {
	return &controlDataSource{}
}

type controlDataSource struct {
	client *compliance.Client
}

func (d *controlDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_compliance_control"
}

func (d *controlDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Provides details about a Compliance Control.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "The ID of the compliance control.",
				Required:    true,
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
	}
}

func (d *controlDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	ctx = tflog.SetField(ctx, "data_source_type", "ComplianceControlDataSource")
	tflog.Debug(ctx, "Configuring SDK client")

	client, ok := req.ProviderData.(*providerModels.CortexCloudSDKClients)
	if !ok {
		util.AddUnexpectedDataSourceConfigurationTypeError(&resp.Diagnostics, "*providerModels.CortexCloudSDKClients", req.ProviderData)
		return
	}

	d.client = client.Compliance
}

func (d *controlDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	ctx = tflog.SetField(ctx, "data_source_type", "ComplianceControlDataSource")

	var config complianceModels.ControlModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	getReq := complianceTypes.GetControlRequest{
		ID: config.ID.ValueString(),
	}

	remote, err := d.client.GetControl(ctx, getReq)
	if err != nil {
		resp.Diagnostics.AddError("Error Reading Compliance Control", err.Error())
		return
	}

	config.RefreshFromRemote(ctx, &resp.Diagnostics, remote)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &config)...)
}
