// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package compliance

import (
	"context"

	"github.com/PaloAltoNetworks/cortex-cloud-go/compliance"
	complianceModels "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/compliance"
	providerModels "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/provider"
	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/util"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ datasource.DataSource              = &assessmentProfilesDataSource{}
	_ datasource.DataSourceWithConfigure = &assessmentProfilesDataSource{}
)

func NewAssessmentProfilesDataSource() datasource.DataSource {
	return &assessmentProfilesDataSource{}
}

type assessmentProfilesDataSource struct {
	client *compliance.Client
}

func (d *assessmentProfilesDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_compliance_assessment_profiles"
}

func (d *assessmentProfilesDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Provides a filtered list of Compliance Assessment Profiles.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "Static identifier for the data source.",
				Computed:    true,
			},
			"search_from": schema.Int64Attribute{
				Description: "The starting index for pagination.",
				Optional:    true,
			},
			"search_to": schema.Int64Attribute{
				Description: "The ending index for pagination.",
				Optional:    true,
			},
			"assessment_profiles": schema.ListNestedAttribute{
				Description: "The list of compliance assessment profiles.",
				Computed:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Description: "The ID of the assessment profile.",
							Computed:    true,
						},
						"name": schema.StringAttribute{
							Description: "The name of the assessment profile.",
							Computed:    true,
						},
						"standard_id": schema.StringAttribute{
							Description: "The ID of the compliance standard to assess against.",
							Computed:    true,
						},
						"standard_name": schema.StringAttribute{
							Description: "The name of the compliance standard.",
							Computed:    true,
						},
						"asset_group_id": schema.Int64Attribute{
							Description: "The ID of the asset group to assess.",
							Computed:    true,
						},
						"asset_group_name": schema.StringAttribute{
							Description: "The name of the asset group.",
							Computed:    true,
						},
						"description": schema.StringAttribute{
							Description: "The description of the assessment profile.",
							Computed:    true,
						},
						"report_frequency": schema.StringAttribute{
							Description: "The frequency for generating reports (cron format).",
							Computed:    true,
						},
						"report_targets": schema.ListAttribute{
							Description: "The list of email addresses to send reports to.",
							Computed:    true,
							ElementType: types.StringType,
						},
						"report_type": schema.StringAttribute{
							Description: "The type of report to generate (e.g., 'PDF', 'CSV', 'NONE').",
							Computed:    true,
						},
						"enabled": schema.BoolAttribute{
							Description: "Whether the assessment profile is enabled.",
							Computed:    true,
						},
						"insert_ts": schema.Int64Attribute{
							Description: "The insertion timestamp.",
							Computed:    true,
						},
						"modify_ts": schema.Int64Attribute{
							Description: "The modification timestamp.",
							Computed:    true,
						},
						"created_by": schema.StringAttribute{
							Description: "The user who created the assessment profile.",
							Computed:    true,
						},
						"modified_by": schema.StringAttribute{
							Description: "The user who last modified the assessment profile.",
							Computed:    true,
						},
					},
				},
			},
		},
		Blocks: map[string]schema.Block{
			"filter": schema.SingleNestedBlock{
				Description: "Filter criteria for the assessment profiles. \n\nNote: for the 'is_custom' field, use operator 'in' (the API does not support 'eq'; if 'eq' is specified it will be automatically converted to 'in').",
				Attributes: map[string]schema.Attribute{
					"field": schema.StringAttribute{
						Description: "The field to filter on.",
						Optional:    true,
					},
					"operator": schema.StringAttribute{
						Description: "The filter operator to use (e.g., 'in', 'contains').",
						Optional:    true,
					},
					"value": schema.StringAttribute{
						Description: "The value to filter by.",
						Optional:    true,
					},
				},
			},
		},
	}
}

func (d *assessmentProfilesDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(*providerModels.CortexCloudSDKClients)
	if !ok {
		util.AddUnexpectedDataSourceConfigurationTypeError(&resp.Diagnostics, "*providerModels.CortexCloudSDKClients", req.ProviderData)
		return
	}

	d.client = client.Compliance
}

func (d *assessmentProfilesDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	var config complianceModels.AssessmentProfilesDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	listReq := config.ToListRequest(ctx, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	result, err := d.client.ListAssessmentProfiles(ctx, listReq)
	if err != nil {
		resp.Diagnostics.AddError("Error Listing Compliance Assessment Profiles", err.Error())
		return
	}

	config.RefreshFromRemote(ctx, &resp.Diagnostics, result.AssessmentProfiles)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &config)...)
}
