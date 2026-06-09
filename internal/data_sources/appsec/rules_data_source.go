// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package appsec

import (
	"context"

	"github.com/PaloAltoNetworks/cortex-cloud-go/appsec"
	appsecTypes "github.com/PaloAltoNetworks/cortex-cloud-go/types/appsec"
	appsecModels "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/appsec"
	providerModels "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/provider"
	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/util"
	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/util/pagination"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// rulesListPageSize is the per-call page window sent to the
// list endpoint when auto-paginating.
const rulesListPageSize = 1000

var (
	_ datasource.DataSource              = &rulesDataSource{}
	_ datasource.DataSourceWithConfigure = &rulesDataSource{}
)

func NewRulesDataSource() datasource.DataSource {
	return &rulesDataSource{}
}

type rulesDataSource struct {
	client *appsec.Client
}

func (d *rulesDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_appsec_rules"
}

func (d *rulesDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Provides a filtered list of Application Security rules.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "Static identifier for the data source.",
				Computed:    true,
			},
			"is_custom": schema.BoolAttribute{
				Description: "Indicates whether the rule is custom.",
				Optional:    true,
			},
			"limit": schema.Int64Attribute{
				Description: "Page size for an explicit single-page request.\n\nWhen both `limit` and `offset` are unset, the data source automatically fetches all matching rules up to `max_results`. When either attribute is set, only that single API page is returned and `max_results` is not enforced. When not configured, falls through to the platform default value of 100.",
				Optional:    true,
			},
			"offset": schema.Int64Attribute{
				Description: "Starting index for an explicit single-page request. \n\nSee `limit` attribute's description for the interaction with auto-pagination. When not configured, falls through to the platform default value of 0.",
				Optional:    true,
			},
			"max_results": schema.Int64Attribute{
				Description: "Maximum number of rules to accumulate when using auto-pagination (when `limit` and `offset` are both unconfigured).\n\nIf set to 0, the limit is disabled and all matching rules will be fetched. When not configured, falls through to the platform default value of 1000.",
				Optional:    true,
			},
			"rules": schema.ListNestedAttribute{
				Computed: true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Description: "Unique identifier for the rule.",
							Computed:    true,
						},
						"name": schema.StringAttribute{
							Description: "Name of the rule.",
							Computed:    true,
						},
						"severity": schema.StringAttribute{
							Description: "The severity level of the rule (CRITICAL, HIGH, MEDIUM, LOW).",
							Computed:    true,
						},
						"scanner": schema.StringAttribute{
							Description: "The type of security scanner used to detect findings of this rule.",
							Computed:    true,
						},
						"category": schema.StringAttribute{
							Description: "Custom rule IaC category.",
							Computed:    true,
						},
						"sub_category": schema.StringAttribute{
							Description: "Custom rule subcategory.",
							Computed:    true,
						},
						"description": schema.StringAttribute{
							Description: "The rule description.",
							Computed:    true,
						},
						"frameworks": schema.ListNestedAttribute{
							Description: "The framework or language that the Application Security rule applies to.",
							Computed:    true,
							NestedObject: schema.NestedAttributeObject{
								Attributes: map[string]schema.Attribute{
									"name": schema.StringAttribute{
										Description: "Name of the configured frameworks.",
										Computed:    true,
									},
									"definition": schema.StringAttribute{
										Description: "The rule definition.",
										Computed:    true,
									},
									"definition_link": schema.StringAttribute{
										Description: "HTTP link to the definition documentation.",
										Computed:    true,
									},
									"remediation_description": schema.StringAttribute{
										Description: "The remediation steps that will appear on the rule's findings.",
										Computed:    true,
									},
								},
							},
						},
						"labels": schema.ListAttribute{
							Description: "Labels assigned to the rule.",
							Computed:    true,
							ElementType: types.StringType,
						},
						"is_custom": schema.BoolAttribute{
							Description: "Indicates whether the rule is custom.",
							Computed:    true,
						},
						"is_enabled": schema.BoolAttribute{
							Description: "Indicates whether the rule is enabled.",
							Computed:    true,
						},
						"cloud_provider": schema.StringAttribute{
							Description: "The cloud provider.",
							Computed:    true,
						},
						"domain": schema.StringAttribute{
							Description: "The domain associated with the rule.",
							Computed:    true,
						},
						"finding_category": schema.StringAttribute{
							Description: "The finding category.",
							Computed:    true,
						},
						"created_at": schema.StringAttribute{
							Description: "The timestamp when the rule was created.",
							Computed:    true,
						},
						"updated_at": schema.StringAttribute{
							Description: "The timestamp when the rule was updated.",
							Computed:    true,
						},
					},
				},
			},
		},
	}
}

func (d *rulesDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

func (d *rulesDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	var config appsecModels.RulesDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	listReq := config.ToListRequest(ctx, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	var rules []appsecTypes.Rule

	// Use auto-pagination when limit or offset are configured, otherwise
	// use the default behavior (single-page fetch with an offset of 0 and
	// limit of 100).
	limitSet := !config.Limit.IsNull() && !config.Limit.IsUnknown()
	offsetSet := !config.Offset.IsNull() && !config.Offset.IsUnknown()
	if limitSet || offsetSet {
		// Single-page fetch
		result, err := d.client.List(ctx, listReq)
		if err != nil {
			resp.Diagnostics.AddError("Error Listing AppSec Rules", err.Error())
			return
		}
		rules = result.Rules
	} else {
		// Auto-pagination
		maxResults := pagination.ResolveMaxResults(config.MaxResults)
		nextOffset := 0
		all, err := pagination.AccumulateAll(
			ctx,
			maxResults,
			"rules",
			func(ctx context.Context) ([]appsecTypes.Rule, int, bool, error) {
				pageReq := listReq
				pageReq.Limit = rulesListPageSize
				pageReq.Offset = nextOffset
				page, err := d.client.List(ctx, pageReq)
				if err != nil {
					return nil, 0, false, err
				}
				if page.NextOffset == nil {
					return page.Rules, 0, false, nil
				}
				nextOffset = *page.NextOffset
				return page.Rules, 0, true, nil
			},
		)
		if err != nil {
			resp.Diagnostics.AddError("Error Listing AppSec Rules", err.Error())
			return
		}
		rules = all
	}

	config.RefreshFromRemote(ctx, &resp.Diagnostics, rules)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &config)...)
}
