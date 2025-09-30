// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package platform

import (
	"context"
	//"fmt"

	"github.com/PaloAltoNetworks/cortex-cloud-go/platform"
	//models "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/platform"
	providerModels "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/provider"
	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/util"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ datasource.DataSource = &GroupDataSource{}
)

// NewGroupDataSource is a helper function to simplify the provider implementation.
func NewGroupDataSource() datasource.DataSource {
	return &GroupDataSource{}
}

// GroupDataSource is the data source implementation.
type GroupDataSource struct {
	client *platform.Client
}

// Metadata returns the data source type name.
func (r *GroupDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_group"
}

// Schema defines the schema for the data source.
func (r *GroupDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Provides visibility into a specific user group on the Cortex Cloud platform.",
		Attributes: map[string]schema.Attribute{
			"name": schema.StringAttribute{
				Description: "The name of the user group.",
				Required:    true,
			},
			"description": schema.StringAttribute{
				Description: "The description of the user group.",
				Computed:    true,
			},
			"user_count": schema.Int64Attribute{
				Description: "The number of users in the group.",
				Computed:    true,
			},
			"is_default": schema.BoolAttribute{
				Description: "Indicates if the group is a default group.",
				Computed:    true,
			},
			"creation_time": schema.Int64Attribute{
				Description: "The creation time of the group.",
				Computed:    true,
			},
			"last_modified": schema.Int64Attribute{
				Description: "The last modified time of the group.",
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

	client, ok := req.ProviderData.(*providerModels.CortexCloudSDKClients)

	if !ok {
		util.AddUnexpectedResourceConfigureTypeError(&resp.Diagnostics, "*http.Client", req.ProviderData)
		return
	}

	r.client = client.Platform
}

// Read refreshes the Terraform state with the latest data.
func (r *GroupDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	//var config models.GroupModel
	//resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	//if resp.Diagnostics.HasError() {
	//	return
	//}

	//request := config.ToGetRequest(ctx, &resp.Diagnostics)
	//if resp.Diagnostics.HasError() {
	//	return
	//}

	//groups, err := r.client.ListGroups(ctx)
	//if err != nil {
	//	resp.Diagnostics.AddError(
	//		"Group Data Source Read Error",
	//		err.Error(),
	//	)
	//	return
	//}

	//var foundGroup *platform.Group
	//for i := range groups {
	//	if groups[i].Name == request.Name {
	//		foundGroup = &groups[i]
	//		break
	//	}
	//}

	//if foundGroup == nil {
	//	resp.Diagnostics.AddError(
	//		"Group Not Found",
	//		fmt.Sprintf("No group found with name: %s", request.Name),
	//	)
	//	return
	//}

	//config.RefreshPropertyValues(ctx, &resp.Diagnostics, foundGroup)
	//if resp.Diagnostics.HasError() {
	//	return
	//}

	//resp.Diagnostics.Append(resp.State.Set(ctx, &config)...)
}
