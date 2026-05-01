// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package platform

import (
	"context"
	"fmt"
	"strconv"

	"github.com/PaloAltoNetworks/cortex-cloud-go/platform"
	platformtypes "github.com/PaloAltoNetworks/cortex-cloud-go/types/platform"
	models "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/platform"
	providerModels "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/provider"
	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/util"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
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

// Metadata returns the data source type name.
func (r *GroupDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_user_group"
}

// Schema defines the schema for the data source.
func (r *GroupDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Provides details about an existing User Group.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "The unique identifier of the user group.",
				Computed:    true,
			},
			"group_name": schema.StringAttribute{
				Description: "The unique name of the user group to look up.",
				Required:    true,
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			"description": schema.StringAttribute{
				Description: "A brief description of the user group's purpose.",
				Computed:    true,
			},
			"role_id": schema.StringAttribute{
				Description: "The unique identifier of the role assigned to this group.",
				Computed:    true,
			},
			"pretty_role_name": schema.StringAttribute{
				Description: "The display name of the role assigned to this group.",
				Computed:    true,
			},
			"created_by": schema.StringAttribute{
				Description: "The user or system that created the user group.",
				Computed:    true,
			},
			"created_ts": schema.Int64Attribute{
				Description: "Unix timestamp (milliseconds) of when the user group was created.",
				Computed:    true,
			},
			"updated_ts": schema.Int64Attribute{
				Description: "Unix timestamp (milliseconds) of when the user group was last updated.",
				Computed:    true,
			},
			"users": schema.SetAttribute{
				Description: "A list of user email addresses directly configured in this group.",
				ElementType: types.StringType,
				Computed:    true,
			},
			"all_users": schema.SetAttribute{
				Description: "A list of users with effective membership for this group. \n\nThis list represents the union of users that have been directly configured in this group and any users that are a member of an IDP group configured in the `idp_groups` attribute that have logged in via SSO/JIT authentication.\n\nDue to API limitations, it is currently not possible to determine which users were added from direct configuration versus SSO/JIT authentication.",
				ElementType: types.StringType,
				Computed:    true,
			},
			"group_type": schema.StringAttribute{
				Description: "The type of the user group. Possible values: `custom` (created directly in the UI), `ad_type` (imported and synchronized from Azure Active Directory).",
				Computed:    true,
			},
			"nested_groups": schema.SetNestedAttribute{
				Description: "The list of direct child groups nested within this user group.",
				Computed:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"group_id": schema.StringAttribute{
							Description: "The unique identifier of the nested group.",
							Computed:    true,
						},
						"group_name": schema.StringAttribute{
							Description: "The display name of the nested group.",
							Computed:    true,
						},
					},
				},
			},
			"idp_groups": schema.SetAttribute{
				Description: "The identity provider (IdP) group names associated with this group. Members of these IdP groups are added automatically via SSO/JIT and appear in `idp_users`.",
				ElementType: types.StringType,
				Computed:    true,
			},
		},
	}
}

// Configure adds the provider-configured client to the data source.
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

// Read refreshes the Terraform state with the latest data.
func (r *GroupDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	var config models.UserGroupModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	groups, err := r.client.ListUserGroups(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Error Reading User Group", err.Error())
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
		resp.Diagnostics.AddAttributeError(
			path.Root("group_name"),
			"User Group Not Found",
			fmt.Sprintf("User group with name %s not found", strconv.Quote(config.GroupName.ValueString())),
		)
		return
	}

	config.RefreshFromRemote(ctx, &resp.Diagnostics, found)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &config)...)
}
