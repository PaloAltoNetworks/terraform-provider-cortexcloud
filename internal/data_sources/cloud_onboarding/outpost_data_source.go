// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package cloudonboarding

import (
	"context"
	"fmt"

	"github.com/PaloAltoNetworks/cortex-cloud-go/cloudonboarding"
	models "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/cloud_onboarding"
	providerModels "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/provider"
	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/util"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Ensure the implementation satisfies the expected interfaces.
var _ datasource.DataSource = &OutpostDataSource{}

// NewOutpostDataSource is a helper function to simplify the provider implementation.
func NewOutpostDataSource() datasource.DataSource {
	return &OutpostDataSource{}
}

// OutpostDataSource is the data source implementation.
type OutpostDataSource struct {
	client *cloudonboarding.Client
}

// Metadata returns the data source type name.
func (d *OutpostDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_outpost"
}

// Schema defines the schema for the data source.
func (d *OutpostDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Retrieves a single outpost.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "The ID of the outpost.",
				Required:    true,
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
	}
}

// Configure adds the provider-configured client to the data source.
func (d *OutpostDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	ctx = tflog.SetField(ctx, "data_source_type", "OutpostDataSource")
	tflog.Debug(ctx, "Configuring SDK client")

	client, ok := req.ProviderData.(*providerModels.CortexCloudSDKClients)
	if !ok {
		util.AddUnexpectedDataSourceConfigurationTypeError(&resp.Diagnostics, "*providerModels.CortexCloudSDKClients", req.ProviderData)
		return
	}
	d.client = client.CloudOnboarding
}

// Read refreshes the Terraform state with the latest data.
func (d *OutpostDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	ctx = tflog.SetField(ctx, "data_source_type", "OutpostDataSource")

	var config models.OutpostModel
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
		resp.Diagnostics.AddError("Outpost Data Source Read Error", err.Error())
		return
	}

	if data.FilterCount != 1 {
		resp.Diagnostics.AddError(
			"Unable to find unique outpost",
			fmt.Sprintf("Expected 1 outpost for ID %s, but found %d", config.ID.ValueString(), data.FilterCount),
		)
		return
	}

	config.RefreshFromRemote(ctx, &resp.Diagnostics, data.Data[0])
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &config)...)
}
