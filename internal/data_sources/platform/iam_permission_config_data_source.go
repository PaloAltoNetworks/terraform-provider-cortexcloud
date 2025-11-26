// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package platform

import (
	"context"

	models "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/platform"
	providerModels "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/provider"
	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/util"

	"github.com/PaloAltoNetworks/cortex-cloud-go/platform"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ datasource.DataSource = &iamPermissionConfigDataSource{}
)

// NewIamPermissionConfigDataSource is a helper function to simplify the provider implementation.
func NewIamPermissionConfigDataSource() datasource.DataSource {
	return &iamPermissionConfigDataSource{}
}

// iamPermissionConfigDataSource is the data source implementation.
type iamPermissionConfigDataSource struct {
	client *platform.Client
}

// Metadata returns the data source type name.
func (d *iamPermissionConfigDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_iam_permission_config"
}

// Schema defines the schema for the data source.
func (d *iamPermissionConfigDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Provides visibility into the available IAM permission configurations.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true,
			},
			"rbac_permissions": schema.ListNestedAttribute{
				Computed: true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"category_name": schema.StringAttribute{
							Computed: true,
						},
						"sub_categories": schema.ListNestedAttribute{
							Computed: true,
							NestedObject: schema.NestedAttributeObject{
								Attributes: map[string]schema.Attribute{
									"sub_category_name": schema.StringAttribute{
										Computed: true,
									},
									"permissions": schema.ListNestedAttribute{
										Computed: true,
										NestedObject: schema.NestedAttributeObject{
											Attributes: map[string]schema.Attribute{
												"name": schema.StringAttribute{
													Computed: true,
												},
												"view_name": schema.StringAttribute{
													Computed: true,
												},
												"action_name": schema.StringAttribute{
													Computed: true,
												},
												"sub_permissions": schema.ListNestedAttribute{
													Computed: true,
													NestedObject: schema.NestedAttributeObject{
														Attributes: map[string]schema.Attribute{
															"action_name": schema.StringAttribute{
																Computed: true,
															},
															"name": schema.StringAttribute{
																Computed: true,
															},
														},
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			"dataset_groups": schema.ListNestedAttribute{
				Computed: true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"datasets": schema.ListAttribute{
							Computed:    true,
							ElementType: types.StringType,
						},
						"dataset_category": schema.StringAttribute{
							Computed: true,
						},
					},
				},
			},
		},
	}
}

// Configure adds the provider-configured client to the data source.
func (d *iamPermissionConfigDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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
func (d *iamPermissionConfigDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	var state models.IamPermissionConfigModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	listResp, err := d.client.ListPermissionConfigs(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Error Reading IAM Permission Config", err.Error())
		return
	}

	state.ID = types.StringValue("permission-config")

	var rbacPermissions []models.RbacPermissionModel
	for _, rbacPerm := range listResp.Data.RbacPermissions {
		var subCategories []models.SubCategoryModel
		for _, subCat := range rbacPerm.SubCategories {
			var permissions []models.PermissionConfigModel
			for _, perm := range subCat.Permissions {
				var subPermissions []models.SubPermissionModel
				for _, subPerm := range perm.SubPermissions {
					subPermissions = append(subPermissions, models.SubPermissionModel{
						ActionName: subPerm.ActionName,
						Name:       subPerm.Name,
					})
				}
				permissions = append(permissions, models.PermissionConfigModel{
					Name:           perm.Name,
					ViewName:       perm.ViewName,
					ActionName:     perm.ActionName,
					SubPermissions: subPermissions,
				})
			}
			subCategories = append(subCategories, models.SubCategoryModel{
				SubCategoryName: subCat.SubCategoryName,
				Permissions:     permissions,
			})
		}
		rbacPermissions = append(rbacPermissions, models.RbacPermissionModel{
			CategoryName:  rbacPerm.CategoryName,
			SubCategories: subCategories,
		})
	}

	var datasetGroups []models.DatasetGroupModel
	for _, dsGroup := range listResp.Data.DatasetGroups {
		datasetGroups = append(datasetGroups, models.DatasetGroupModel{
			Datasets:        dsGroup.Datasets,
			DatasetCategory: dsGroup.DatasetCategory,
		})
	}

	state.DatasetGroups = datasetGroups
	state.RbacPermissions = rbacPermissions

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
