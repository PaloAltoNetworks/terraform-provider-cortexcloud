// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package platform

import (
	"context"

	"github.com/PaloAltoNetworks/cortex-cloud-go/platform"
	platformtypes "github.com/PaloAltoNetworks/cortex-cloud-go/types/platform"
	models "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/platform"
	providerModels "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/provider"
	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/util"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ datasource.DataSource = &GroupDataSource{}
)

// NewGroupDataSource is a helper function to simplify the provider implementation.
func NewGroupDataSource() datasource.DataSource {
	return &GroupDataSource{}
}

// GroupDataSource implements data "cortexcloud_user_group"
type GroupDataSource struct {
	client *platform.Client
}

func (r *GroupDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_user_group"
}

func (r *GroupDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Fetch an existing Cortex Cloud user group by group_name.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "User group ID.",
				Computed:    true,
			},

			"group_name": schema.StringAttribute{
				Description: "User group name.",
				Required:    true,
			},

			"description": schema.StringAttribute{
				Description: "User group description.",
				Computed:    true,
			},

			"role_id": schema.StringAttribute{
				Description: "Role ID associated with the group.",
				Computed:    true,
			},

			"pretty_role_name": schema.StringAttribute{
				Description: "Human-readable role name.",
				Computed:    true,
			},

			"created_by": schema.StringAttribute{
				Description: "Creator of the user group.",
				Computed:    true,
			},

			"created_ts": schema.Int64Attribute{
				Description: "Created timestamp (epoch).",
				Computed:    true,
			},

			"updated_ts": schema.Int64Attribute{
				Description: "Updated timestamp (epoch).",
				Computed:    true,
			},

			"users": schema.ListAttribute{
				Description: "Users in the group (emails).",
				ElementType: types.StringType,
				Computed:    true,
			},

			"group_type": schema.StringAttribute{
				Description: "Group type.",
				Computed:    true,
			},

			"nested_groups": schema.ListNestedAttribute{
				Description: "Nested groups (read-only).",
				Computed:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"group_id": schema.StringAttribute{
							Description: "Nested group ID.",
							Computed:    true,
						},
						"group_name": schema.StringAttribute{
							Description: "Nested group name.",
							Computed:    true,
						},
					},
				},
			},

			"idp_groups": schema.ListAttribute{
				Description: "IDP group mappings.",
				ElementType: types.StringType,
				Computed:    true,
			},
		},
	}
}

func (r *GroupDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	clients, ok := req.ProviderData.(*providerModels.CortexCloudSDKClients)
	if !ok {
		util.AddUnexpectedDataSourceConfigurationTypeError(&resp.Diagnostics, "*providerModels.CortexCloudSDKClients", req.ProviderData)
		return
	}

	r.client = clients.Platform
}

func (r *GroupDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	var config models.UserGroupModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if config.GroupName.IsNull() || config.GroupName.IsUnknown() || config.GroupName.ValueString() == "" {
		resp.Diagnostics.AddError("Invalid configuration", "group_name must be provided.")
		return
	}

	groups, err := r.client.ListUserGroups(ctx)
	if err != nil {
		resp.Diagnostics.AddError("User Group Data Source Read Error", err.Error())
		return
	}

	var found *platformtypes.UserGroup
	for i := range groups {
		if groups[i].GroupName == config.GroupName.ValueString() {
			found = &groups[i]
			break
		}
	}

	if found == nil {
		resp.Diagnostics.AddError(
			"User Group not found",
			"No user group found with group_name="+config.GroupName.ValueString(),
		)
		return
	}

	config.RefreshFromRemote(ctx, &resp.Diagnostics, found)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &config)...)
}

