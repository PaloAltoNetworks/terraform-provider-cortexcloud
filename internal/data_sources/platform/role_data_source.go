// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package platform

import (
	"context"
	"fmt"

	"github.com/PaloAltoNetworks/cortex-cloud-go/platform"
	//cortexTypes "github.com/PaloAltoNetworks/cortex-cloud-go/types"
	models "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/platform"
	providerModels "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/provider"
	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/util"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ datasource.DataSource = &RoleDataSource{}
)

// NewRoleDataSource is a helper function to simplify the provider implementation.
func NewRoleDataSource() datasource.DataSource {
	return &RoleDataSource{}
}

// RoleDataSource is the data source implementation.
type RoleDataSource struct {
	client *platform.Client
}

// Metadata returns the data source type name.
func (r *RoleDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_role"
}

// Schema defines the schema for the data source.
func (r *RoleDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Provides visibility into a role's access to the Cortex Cloud platform.",
		Attributes: map[string]schema.Attribute{
			"pretty_name": schema.StringAttribute{
				Description: "The name of the role.",
				Required:    true,
			},
			"permissions": schema.ListAttribute{
				Description: "The permissions of the role.",
				Computed:    true,
				ElementType: types.StringType,
			},
			"insert_time": schema.Int64Attribute{
				Description: "The insert time of the role.",
				Computed:    true,
			},
			"update_time": schema.Int64Attribute{
				Description: "The update time of the role.",
				Computed:    true,
			},
			"created_by": schema.StringAttribute{
				Description: "The creator of the role.",
				Computed:    true,
			},
			"description": schema.StringAttribute{
				Description: "The description of the role.",
				Computed:    true,
			},
			"tags": schema.StringAttribute{
				Description: "The tags of the role.",
				Computed:    true,
			},
			"groups": schema.ListAttribute{
				Description: "The groups of the role.",
				Computed:    true,
				ElementType: types.StringType,
			},
			"users": schema.ListAttribute{
				Description: "The users of the role.",
				Computed:    true,
				ElementType: types.StringType,
			},
		},
	}
}

// Configure adds the provider-configured client to the data source.
func (r *RoleDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	// Prevent panic if the provider has not been configured
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(*providerModels.CortexCloudSDKClients)

	if !ok {
		util.AddUnexpectedResourceConfigureTypeError(&resp.Diagnostics, "*http.Client", req.ProviderData)
		return
	}

	r.client = client.Platform
}

// Read refreshes the Terraform state with the latest data.
func (r *RoleDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	ctx = tflog.SetField(ctx, "resource_type", "CloudIntegrationInstanceDataSource")
	ctx = tflog.SetField(ctx, "resource_id_field", "name")

	// Populate data source configuration into model
	var config models.RoleModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	ctx = tflog.SetField(ctx, "resource_id_value", config.PrettyName.ValueString())

	// Retrieve role details from API
	if config.PrettyName.IsNull() || config.PrettyName.IsUnknown() {
		resp.Diagnostics.AddAttributeError(
			path.Root("id"),
			"Cloud Integration Instance Data Source Configuration Error",
			"Recieved null or unknown value for `id` attribute. Please report this issue to the developers.",
		)
	}
	listResponse, err := r.client.ListRoles(ctx, []string{ config.PrettyName.ValueString() })
	if err != nil {
		resp.Diagnostics.AddError(
			"Role Data Source Read Error",
			err.Error(),
		)
		return
	}

	if len(listResponse) == 0 {
		resp.Diagnostics.AddError(
			"Role Data Source Read Error",
			fmt.Sprintf("Cortex API returned no results for role name \"%s\".", config.PrettyName.ValueString()),
		)
		return
	}

	if len(listResponse) > 1 {
		resp.Diagnostics.AddError(
			"Role Data Source Read Error",
			fmt.Sprintf("Cortex API returned multiple results for role name \"%s\". Please report this issue to the developers.", config.PrettyName.ValueString()),
		)
		return
	}

	// Refresh state values
	config.RefreshFromRemote(ctx, &resp.Diagnostics, &listResponse[0])
	if resp.Diagnostics.HasError() {
		return
	}

	// Set refreshed state
	resp.Diagnostics.Append(resp.State.Set(ctx, &config)...)
}
