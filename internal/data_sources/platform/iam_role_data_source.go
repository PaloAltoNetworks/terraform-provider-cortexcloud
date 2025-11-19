// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package platform

import (
	"context"
	"fmt"

	"github.com/PaloAltoNetworks/cortex-cloud-go/platform"
	platformTypes "github.com/PaloAltoNetworks/cortex-cloud-go/types/platform"

	//cortexTypes "github.com/PaloAltoNetworks/cortex-cloud-go/types"
	models "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/platform"
	providerModels "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/provider"
	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/util"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	_ "github.com/hashicorp/terraform-plugin-framework/path"
	_ "github.com/hashicorp/terraform-plugin-framework/types"
	_ "github.com/hashicorp/terraform-plugin-log/tflog"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ datasource.DataSource = &RoleDataSource{}
)

// NewIamRoleDataSource is a helper function to simplify the provider implementation.
func NewIamRoleDataSource() datasource.DataSource {
	return &RoleDataSource{}
}

// RoleDataSource is the data source implementation.
type RoleDataSource struct {
	client *platform.Client
}

// Metadata returns the data source type name.
func (r *RoleDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_iam_role"
}

// Schema defines the schema for the data source.
func (r *RoleDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Provides visibility into an IAM role.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "The ID of the role.",
				Required:    true,
			},
			"pretty_name": schema.StringAttribute{
				Description: "The name of the role.",
				Computed:    true,
			},
			"description": schema.StringAttribute{
				Description: "The description of the role.",
				Computed:    true,
			},
			"is_custom": schema.BoolAttribute{
				Description: "Whether the role is a custom role.",
				Computed:    true,
			},
			"created_by": schema.StringAttribute{
				Description: "The user who created the role.",
				Computed:    true,
			},
			"created_ts": schema.Int64Attribute{
				Description: "The creation time of the role.",
				Computed:    true,
			},
			"updated_ts": schema.Int64Attribute{
				Description: "The last update time of the role.",
				Computed:    true,
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
		util.AddUnexpectedDataSourceConfigurationTypeError(&resp.Diagnostics, "*http.Client", req.ProviderData)
		return
	}

	r.client = client.Platform
}

// Read refreshes the Terraform state with the latest data.
func (r *RoleDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	var config models.IamRoleModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	listResp, err := r.client.ListAllRoles(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Error Reading IAM Role", err.Error())
		return
	}

	var role *platformTypes.RoleListItem
	for _, r := range listResp.Data {
		if r.RoleID == config.ID.ValueString() {
			role = &r
			break
		}
	}

	if role == nil {
		resp.Diagnostics.AddError("IAM Role not found", fmt.Sprintf("IAM Role with ID %s not found", config.ID.ValueString()))
		return
	}

	config.RefreshFromRemote(ctx, &resp.Diagnostics, role)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &config)...)
}
