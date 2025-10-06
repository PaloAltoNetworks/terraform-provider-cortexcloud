// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package platform

import (
	"context"

	"github.com/PaloAltoNetworks/cortex-cloud-go/platform"
	models "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/platform"
	providerModels "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/provider"
	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/util"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ datasource.DataSource = &UserDataSource{}
)

// NewUserDataSource is a helper function to simplify the provider implementation.
func NewUserDataSource() datasource.DataSource {
	return &UserDataSource{}
}

// UserDataSource is the data source implementation.
type UserDataSource struct {
	client *platform.Client
}

// Metadata returns the data source type name.
func (r *UserDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_user"
}

// Schema defines the schema for the data source.
func (r *UserDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Provides visibility into a user's access to the Cortex Cloud platform.",
		Attributes: map[string]schema.Attribute{
			"email": schema.StringAttribute{
				Description: "The email of the user.",
				Required:    true,
			},
			"first_name": schema.StringAttribute{
				Description: "The first name of the user.",
				Computed:    true,
			},
			"last_name": schema.StringAttribute{
				Description: "The last name of the user.",
				Computed:    true,
			},
			"role_name": schema.StringAttribute{
				Description: "The role name of the user.",
				Computed:    true,
			},
			"last_logged_in": schema.Int64Attribute{
				Description: "The last logged in time of the user.",
				Computed:    true,
			},
			"user_type": schema.StringAttribute{
				Description: "The type of the user.",
				Computed:    true,
			},
			"groups": schema.ListAttribute{
				Description: "The groups of the user.",
				Computed:    true,
				ElementType: types.StringType,
			},
			"scope": schema.SingleNestedAttribute{
				Description: "The scope of the user.",
				Computed:    true,
				Attributes: map[string]schema.Attribute{
					"endpoints": schema.SingleNestedAttribute{
						Description: "The endpoints scope of the user.",
						Computed:    true,
						Attributes: map[string]schema.Attribute{
							"endpoint_groups": schema.SingleNestedAttribute{
								Description: "The endpoint groups scope of the user.",
								Computed:    true,
								Attributes: map[string]schema.Attribute{
									"ids": schema.ListAttribute{
										Description: "The ids of the endpoint groups.",
										Computed:    true,
										ElementType: types.StringType,
									},
									"mode": schema.StringAttribute{
										Description: "The mode of the endpoint groups.",
										Computed:    true,
									},
								},
							},
							"endpoint_tags": schema.SingleNestedAttribute{
								Description: "The endpoint tags scope of the user.",
								Computed:    true,
								Attributes: map[string]schema.Attribute{
									"ids": schema.ListAttribute{
										Description: "The ids of the endpoint tags.",
										Computed:    true,
										ElementType: types.StringType,
									},
									"mode": schema.StringAttribute{
										Description: "The mode of the endpoint tags.",
										Computed:    true,
									},
								},
							},
							"mode": schema.StringAttribute{
								Description: "The mode of the endpoints.",
								Computed:    true,
							},
						},
					},
					"cases_issues": schema.SingleNestedAttribute{
						Description: "The cases issues scope of the user.",
						Computed:    true,
						Attributes: map[string]schema.Attribute{
							"ids": schema.ListAttribute{
								Description: "The ids of the cases issues.",
								Computed:    true,
								ElementType: types.StringType,
							},
							"mode": schema.StringAttribute{
								Description: "The mode of the cases issues.",
								Computed:    true,
							},
						},
					},
				},
			},
		},
	}
}

// Configure adds the provider-configured client to the data source.
func (r *UserDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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
func (r *UserDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	// Populate data source configuration into model
	var config models.UserModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Retrieve user details from API
	response, err := r.client.GetUser(ctx, config.Email.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(
			"User Data Source Read Error",
			err.Error(),
		)
		return
	}

	// Refresh state values
	config.RefreshFromRemote(ctx, &resp.Diagnostics, &response)
	if resp.Diagnostics.HasError() {
		return
	}

	// Set refreshed state
	resp.Diagnostics.Append(resp.State.Set(ctx, &config)...)
}
