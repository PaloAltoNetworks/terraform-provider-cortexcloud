// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package appsec

import (
	"context"

	"github.com/PaloAltoNetworks/cortex-cloud-go/appsec"
	appsecModels "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/appsec"
	providerModels "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/provider"
	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/util"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ datasource.DataSource              = &policiesDataSource{}
	_ datasource.DataSourceWithConfigure = &policiesDataSource{}
)

func NewPoliciesDataSource() datasource.DataSource {
	return &policiesDataSource{}
}

type policiesDataSource struct {
	client *appsec.Client
}

func (d *policiesDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_appsec_policies"
}

func (d *policiesDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Provides a filtered list of Application Security policies.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{Computed: true},
			"is_custom": schema.BoolAttribute{
				Description: "Indicates if the policy is a custom policy or a system-provided policy.",
				Optional:    true,
			},
			"status": schema.StringAttribute{
				Description: "Indicates whether the policy is currently enabled or disabled.",
				Optional:    true,
			},
			"policies": schema.ListNestedAttribute{
				Computed: true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Description: "Unique identifier for the policy.",
							Computed:    true,
						},
						"name": schema.StringAttribute{
							Description: "Name of the AppSec policy.",
							Computed:    true,
						},
						"description": schema.StringAttribute{
							Description: "Description of the policy.",
							Computed:    true,
						},
						"status": schema.StringAttribute{
							Description: "Indicates whether the policy is currently enabled or disabled.",
							Computed:    true,
						},
						"is_custom": schema.BoolAttribute{
							Description: "Indicates if the policy is a custom policy or a system-provided policy.",
							Computed:    true,
						},
						"conditions": schema.StringAttribute{
							Description: "Policy conditions as a JSON-encoded string with nested AND/OR logic.",
							Computed:    true,
						},
						"scope": schema.StringAttribute{
							Description: "Asset targeting scope as a JSON-encoded string with nested AND/OR logic.",
							Computed:    true,
						},
						"asset_group_ids": schema.ListAttribute{
							Description: "List of asset groups to which the policy applies. If the array is empty, the policy applies to all asset groups.",
							Computed:    true,
							ElementType: types.Int64Type,
						},
						"periodic_trigger":              periodicTriggerDataSourceAttribute(),
						"pr_trigger":                    prTriggerDataSourceAttribute(),
						"cicd_trigger":                  cicdTriggerDataSourceAttribute(),
						"ci_image_trigger":              ciImageTriggerDataSourceAttribute(),
						"image_registry_trigger":        imageRegistryTriggerDataSourceAttribute(),
						"developer_suppression_affects": schema.BoolAttribute{Computed: true},
						"override_issue_severity":       schema.StringAttribute{Computed: true},
						"created_by": schema.StringAttribute{
							Description: "The user or system that created the policy.",
							Computed:    true,
						},
						"date_created": schema.StringAttribute{
							Description: "The date and time when the policy was created.",
							Computed:    true,
						},
						"modified_by": schema.StringAttribute{
							Description: "The user or system that last modified the policy.",
							Computed:    true,
						},
						"date_modified": schema.StringAttribute{
							Description: "The date and time when the policy was last modified.",
							Computed:    true,
						},
						"version": schema.Float64Attribute{
							Description: "The version of the policy - goes up by one every policy update.",
							Computed:    true,
						},
					},
				},
			},
		},
	}
}

func (d *policiesDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(*providerModels.CortexCloudSDKClients)
	if !ok {
		util.AddUnexpectedDataSourceConfigurationTypeError(&resp.Diagnostics, "*providerModels.CortexCloudSDKClients", req.ProviderData)
		return
	}

	d.client = client.AppSec
}

func (d *policiesDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	var config appsecModels.PoliciesDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	listReq := config.ToListRequest(ctx, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	result, err := d.client.ListPolicies(ctx, listReq)
	if err != nil {
		resp.Diagnostics.AddError("Error Listing AppSec Policies", util.FormatAPIError(err))
		return
	}

	config.RefreshFromRemote(ctx, &resp.Diagnostics, result)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &config)...)
}
