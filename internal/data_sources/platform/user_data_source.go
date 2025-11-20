// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package platform

import (
	"context"

	models "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/platform"
	providerModels "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/provider"
	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/util"

	platformsdk "github.com/PaloAltoNetworks/cortex-cloud-go/platform"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ datasource.DataSource              = &userDataSource{}
	_ datasource.DataSourceWithConfigure = &userDataSource{}
)

// NewUserDataSource is a helper function to simplify the provider implementation.
func NewUserDataSource() datasource.DataSource {
	return &userDataSource{}
}

// userDataSource is the data source implementation.
type userDataSource struct {
	client *platformsdk.Client
}

// Metadata returns the data source type name.
func (d *userDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_user"
}

// Schema defines the schema for the data source.
func (d *userDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Gets a Cortex Cloud user.",
		Attributes: map[string]schema.Attribute{
			"user_email": schema.StringAttribute{
				Description: "The email of the user.",
				Required:    true,
			},
			"user_first_name": schema.StringAttribute{
				Description: "The first name of the user.",
				Computed:    true,
			},
			"user_last_name": schema.StringAttribute{
				Description: "The last name of the user.",
				Computed:    true,
			},
			"phone_number": schema.StringAttribute{
				Description: "The phone number of the user.",
				Computed:    true,
			},
			"status": schema.StringAttribute{
				Description: "The status of the user.",
				Computed:    true,
			},
			"role_name": schema.StringAttribute{
				Description: "The role name of the user.",
				Computed:    true,
			},
			"last_logged_in": schema.Int64Attribute{
				Description: "The last logged in timestamp of the user.",
				Computed:    true,
			},
			"hidden": schema.BoolAttribute{
				Description: "The hidden status of the user.",
				Computed:    true,
			},
			"user_type": schema.StringAttribute{
				Description: "The user type of the user.",
				Computed:    true,
			},
			"groups": schema.ListNestedAttribute{
				Description: "The groups of the user.",
				Computed:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"group_id": schema.StringAttribute{
							Description: "The ID of the nested group.",
							Computed:    true,
						},
						"group_name": schema.StringAttribute{
							Description: "The name of the nested group.",
							Computed:    true,
						},
					},
				},
			},
		},
	}
}

// Configure adds the provider-configured client to the data source.
func (d *userDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(*providerModels.CortexCloudSDKClients)
	if !ok {
		util.AddUnexpectedDataSourceConfigurationTypeError(&resp.Diagnostics, "*providerModels.CortexCloudSDKClients", req.ProviderData)
		return
	}

	d.client = client.Platform
}

// Read refreshes the Terraform state with the latest data.
func (d *userDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var state models.UserModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	user, err := d.client.GetIAMUser(ctx, state.Email.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Error getting user", err.Error())
		return
	}

	state.RefreshFromRemote(ctx, &resp.Diagnostics, user)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
