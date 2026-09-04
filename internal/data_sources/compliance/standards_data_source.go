// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package compliance

import (
	"context"

	complianceModels "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/compliance"
	providerModels "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/provider"
	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/util"
	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/util/pagination"
	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/compliance"
	complianceTypes "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/sdk/types/compliance"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// standardsListPageSize is the per-call page window the get_standards endpoint will honor
const standardsListPageSize = 100

var (
	_ datasource.DataSource              = &standardsDataSource{}
	_ datasource.DataSourceWithConfigure = &standardsDataSource{}
)

func NewStandardsDataSource() datasource.DataSource {
	return &standardsDataSource{}
}

type standardsDataSource struct {
	client *compliance.Client
}

func (d *standardsDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_compliance_standards"
}

func (d *standardsDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Provides a filtered list of Compliance Standards.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "Static identifier for the data source.",
				Computed:    true,
			},
			"search_from": schema.Int64Attribute{
				Description: "The starting index for an explicit pagination window.\n\nWhen both `search_from` and `search_to` are unset, the data source automatically fetches all matching standards up to `max_results`.\n\nWhen either is set, only that single API page is returned and `max_results` is not enforced.",
				Optional:    true,
			},
			"search_to": schema.Int64Attribute{
				Description: "The inclusive ending index for an explicit pagination window.\n\nSee `search_from` for the interaction with auto-pagination.",
				Optional:    true,
			},
			"max_results": schema.Int64Attribute{
				Description: "Maximum number of standards to accumulate when using auto-pagination (when `search_from` and `search_to` are both unconfigured).\n\nIf set to 0, the limit is disabled and all matching standards will be fetched.\n\nDefaults to 1000.",
				Optional:    true,
			},
			"standards": schema.ListNestedAttribute{
				Description: "The list of compliance standards.",
				Computed:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Description: "The ID of the compliance standard.",
							Computed:    true,
						},
						"name": schema.StringAttribute{
							Description: "The name of the compliance standard.",
							Computed:    true,
						},
						"description": schema.StringAttribute{
							Description: "The description of the compliance standard.",
							Computed:    true,
						},
						"version": schema.StringAttribute{
							Description: "The version of the compliance standard.",
							Computed:    true,
						},
						"assessments_profiles_count": schema.Int64Attribute{
							Description: "The number of assessment profiles using this standard.",
							Computed:    true,
						},
						"controls_ids": schema.SetAttribute{
							Description: "The set of control IDs associated with this standard.",
							Computed:    true,
							ElementType: types.StringType,
						},
						"labels": schema.SetAttribute{
							Description: "The set of labels for this standard.",
							Computed:    true,
							ElementType: types.StringType,
						},
						"revision": schema.Int64Attribute{
							Description: "The revision number of the standard. This value increments on every update.",
							Computed:    true,
						},
						"publisher": schema.StringAttribute{
							Description: "The publisher of the standard.",
							Computed:    true,
						},
						"release_date": schema.StringAttribute{
							Description: "The release date of the standard.",
							Computed:    true,
						},
						"created_date": schema.StringAttribute{
							Description: "The creation date of the standard.",
							Computed:    true,
						},
						"created_by": schema.StringAttribute{
							Description: "The user who created the standard.",
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
						"is_custom": schema.BoolAttribute{
							Description: "Whether the standard is custom.",
							Computed:    true,
						},
					},
				},
			},
		},
		Blocks: map[string]schema.Block{
			"filter": schema.SingleNestedBlock{
				Description: "Filter criteria for the standards. \n\nNote: for the 'is_custom' field, use operator 'in' (the API does not support 'eq'; if 'eq' is specified it will be automatically converted to 'in'). For the 'labels' field, use operator 'contains' (if 'eq' is specified it will be automatically converted to 'contains').",
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

func (d *standardsDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

func (d *standardsDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	var config complianceModels.StandardsDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	listReq := config.ToListRequest(ctx, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	var standards []complianceTypes.Standard

	// Honour an explicit search_from/search_to window with a single API call,
	// matching the historical (pre-auto-pagination) behaviour. Auto-pagination
	// activates only when both pagination bounds are unset.
	//
	if listReq.SearchFrom != nil && listReq.SearchTo != nil {
		result, err := d.client.ListStandards(ctx, listReq)
		if err != nil {
			resp.Diagnostics.AddError("Error Listing Compliance Standards", err.Error())
			return
		}
		standards = result.Standards
	} else {
		maxResults := pagination.ResolveMaxResults(config.MaxResults) // unset → 1000; 0 → unlimited
		all, err := pagination.OffsetAccumulateAll(
			ctx,
			standardsListPageSize,
			maxResults,
			"standards",
			func(ctx context.Context, from, to int) ([]complianceTypes.Standard, int, error) {
				pageReq := listReq
				pageReq.SearchFrom = &from
				pageReq.SearchTo = &to
				page, err := d.client.ListStandards(ctx, pageReq)
				if err != nil {
					return nil, 0, err
				}
				return page.Standards, page.TotalCount, nil
			},
		)
		if err != nil {
			resp.Diagnostics.AddError("Error Listing Compliance Standards", err.Error())
			return
		}
		standards = all
	}

	config.RefreshFromRemote(ctx, &resp.Diagnostics, standards)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &config)...)
}
