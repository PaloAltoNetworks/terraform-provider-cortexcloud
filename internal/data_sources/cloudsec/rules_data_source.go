// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package cloudsec

import (
	"context"

	"github.com/PaloAltoNetworks/cortex-cloud-go/cloudsec"
	cloudsecTypes "github.com/PaloAltoNetworks/cortex-cloud-go/types/cloudsec"
	cloudsecModels "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/cloudsec"
	providerModels "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/provider"
	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/util"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ datasource.DataSource              = &CloudSecRulesDataSource{}
	_ datasource.DataSourceWithConfigure = &CloudSecRulesDataSource{}
)

// NewCloudSecRulesDataSource is a helper function to simplify the provider implementation.
func NewCloudSecRulesDataSource() datasource.DataSource {
	return &CloudSecRulesDataSource{}
}

// CloudSecRulesDataSource is the data source implementation for listing CloudSec rules.
type CloudSecRulesDataSource struct {
	client *cloudsec.Client
}

// Metadata returns the data source type name.
func (d *CloudSecRulesDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cloudsec_rules"
}

// Schema defines the schema for the data source.
func (d *CloudSecRulesDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Provides a filtered list of Cloud Security detection rules for Cloud Security Posture Management (CSPM).",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "Static identifier for the data source.",
				Computed:    true,
			},
			"search_from": schema.Int32Attribute{
				Description: "The starting index for pagination (0-based).",
				Optional:    true,
			},
			"search_to": schema.Int32Attribute{
				Description: "The ending index for pagination.",
				Optional:    true,
			},
			"total_count": schema.Int64Attribute{
				Description: "The total number of rules available.",
				Computed:    true,
			},
			"filter_count": schema.Int64Attribute{
				Description: "The number of rules matching the filter criteria.",
				Computed:    true,
			},
			"rules": schema.ListNestedAttribute{
				Description: "The list of CloudSec detection rules.",
				Computed:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Description: "Unique identifier of the rule (UUID format).",
							Computed:    true,
						},
						"name": schema.StringAttribute{
							Description: "Unique rule name.",
							Computed:    true,
						},
						"description": schema.StringAttribute{
							Description: "Detailed rule description.",
							Computed:    true,
						},
						"class": schema.StringAttribute{
							Description: "Rule class (e.g., 'config' for CSPM rules).",
							Computed:    true,
						},
						"type": schema.StringAttribute{
							Description: "Rule type (e.g., 'DETECTION').",
							Computed:    true,
						},
						"asset_types": schema.ListAttribute{
							Description: "Array of asset type identifiers.",
							Computed:    true,
							ElementType: types.StringType,
						},
						"severity": schema.StringAttribute{
							Description: "Rule severity level (low, medium, high, critical, informational).",
							Computed:    true,
						},
						"enabled": schema.BoolAttribute{
							Description: "Whether the rule is enabled.",
							Computed:    true,
						},
						"system_default": schema.BoolAttribute{
							Description: "Indicates if this is a system default rule.",
							Computed:    true,
						},
						"providers": schema.ListAttribute{
							Description: "Cloud providers derived from asset_types.",
							Computed:    true,
							ElementType: types.StringType,
						},
						"compliance_metadata": schema.ListNestedAttribute{
							Description: "List of compliance metadata with control IDs.",
							Computed:    true,
							NestedObject: schema.NestedAttributeObject{
								Attributes: map[string]schema.Attribute{
									"control_id": schema.StringAttribute{
										Description: "Compliance control identifier.",
										Computed:    true,
									},
									"standard_id": schema.StringAttribute{
										Description: "Compliance standard identifier.",
										Computed:    true,
									},
									"standard_name": schema.StringAttribute{
										Description: "Full name of the compliance standard.",
										Computed:    true,
									},
									"control_name": schema.StringAttribute{
										Description: "Full name of the compliance control.",
										Computed:    true,
									},
								},
							},
						},
						"compliance_standards": schema.ListAttribute{
							Description: "List of compliance standard identifiers.",
							Computed:    true,
							ElementType: types.StringType,
						},
						"labels": schema.ListAttribute{
							Description: "Custom labels.",
							Computed:    true,
							ElementType: types.StringType,
						},
						"created_by": schema.StringAttribute{
							Description: "User who created the rule.",
							Computed:    true,
						},
						"created_on": schema.Int64Attribute{
							Description: "Creation timestamp (epoch milliseconds).",
							Computed:    true,
						},
						"last_modified_by": schema.StringAttribute{
							Description: "User who last modified the rule.",
							Computed:    true,
						},
						"last_modified_on": schema.Int64Attribute{
							Description: "Last modification timestamp (epoch milliseconds).",
							Computed:    true,
						},
						"module": schema.StringAttribute{
							Description: "Module the rule belongs to.",
							Computed:    true,
						},
					},
				},
			},
		},
		Blocks: map[string]schema.Block{
			"filter": schema.SingleNestedBlock{
				Description: "Filter criteria for the rules. Use field/type/value for simple filters, or operator with nested criteria for complex AND/OR logic.",
				Attributes: map[string]schema.Attribute{
					"field": schema.StringAttribute{
						Description: "The field to filter on (e.g., 'severity', 'enabled', 'system_default', 'cloudType').",
						Optional:    true,
					},
					"type": schema.StringAttribute{
						Description: "The type of filter (e.g., 'EQ', 'NEQ', 'CONTAINS').",
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

// Configure adds the provider-configured client to the data source.
func (d *CloudSecRulesDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	clients, ok := req.ProviderData.(*providerModels.CortexCloudSDKClients)
	if !ok {
		util.AddUnexpectedDataSourceConfigurationTypeError(&resp.Diagnostics, "*providerModels.CortexCloudSDKClients", req.ProviderData)
		return
	}

	d.client = clients.CloudSec
}

// rulesFilterModel represents a simple filter for the rules data source.
type rulesFilterModel struct {
	Field types.String `tfsdk:"field"`
	Type  types.String `tfsdk:"type"`
	Value types.String `tfsdk:"value"`
}

// CloudSecRulesDataSourceModel represents the Terraform model for the rules data source.
type CloudSecRulesDataSourceModel struct {
	ID          types.String `tfsdk:"id"`
	SearchFrom  types.Int32  `tfsdk:"search_from"`
	SearchTo    types.Int32  `tfsdk:"search_to"`
	TotalCount  types.Int64  `tfsdk:"total_count"`
	FilterCount types.Int64  `tfsdk:"filter_count"`
	Rules       types.List   `tfsdk:"rules"`
	Filter      types.Object `tfsdk:"filter"`
}

// Read refreshes the Terraform state with the latest data.
func (d *CloudSecRulesDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	ctx = tflog.SetField(ctx, "data_source_type", "CloudSecRulesDataSource")

	var config CloudSecRulesDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Build the search request
	searchReq := cloudsecTypes.SearchRulesRequest{}

	// Set pagination
	if !config.SearchFrom.IsNull() && !config.SearchFrom.IsUnknown() {
		searchReq.SearchFrom = config.SearchFrom.ValueInt32()
	}
	if !config.SearchTo.IsNull() && !config.SearchTo.IsUnknown() {
		searchReq.SearchTo = config.SearchTo.ValueInt32()
	}

	// Set filter
	if !config.Filter.IsNull() && !config.Filter.IsUnknown() {
		var filterModel rulesFilterModel
		resp.Diagnostics.Append(config.Filter.As(ctx, &filterModel, basetypes.ObjectAsOptions{})...)
		if resp.Diagnostics.HasError() {
			return
		}

		filter := &cloudsecTypes.FilterCriteria{}
		if !filterModel.Field.IsNull() && !filterModel.Field.IsUnknown() {
			filter.SearchField = filterModel.Field.ValueString()
		}
		if !filterModel.Type.IsNull() && !filterModel.Type.IsUnknown() {
			filter.SearchType = filterModel.Type.ValueString()
		}
		if !filterModel.Value.IsNull() && !filterModel.Value.IsUnknown() {
			filter.SearchValue = filterModel.Value.ValueString()
		}
		searchReq.Filter = filter
	}

	tflog.Debug(ctx, "Searching CloudSec rules")

	// Call SDK Search method
	searchResp, err := d.client.Search(ctx, searchReq)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Searching CloudSec Rules",
			"Could not search rules: "+err.Error(),
		)
		return
	}

	tflog.Debug(ctx, "CloudSec rules search completed",
		map[string]interface{}{
			"total_count":  searchResp.Metadata.TotalCount,
			"filter_count": searchResp.Metadata.FilterCount,
			"rules_count":  len(searchResp.Data),
		},
	)

	// Set static ID
	config.ID = types.StringValue("cloudsec_rules")

	// Set metadata
	config.TotalCount = types.Int64Value(searchResp.Metadata.TotalCount)
	config.FilterCount = types.Int64Value(searchResp.Metadata.FilterCount)

	// Convert rules to Terraform models
	ruleModels := make([]cloudsecModels.CloudSecRuleDataSourceModel, 0, len(searchResp.Data))
	for i := range searchResp.Data {
		var ruleModel cloudsecModels.CloudSecRuleDataSourceModel
		ruleModel.FromSDKRuleData(ctx, &resp.Diagnostics, &searchResp.Data[i])
		if resp.Diagnostics.HasError() {
			return
		}
		ruleModels = append(ruleModels, ruleModel)
	}

	// Convert to types.List
	rulesList, diags := types.ListValueFrom(ctx, types.ObjectType{
		AttrTypes: cloudsecModels.GetRuleDataSourceAttrTypes(),
	}, ruleModels)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	config.Rules = rulesList

	// Set state
	resp.Diagnostics.Append(resp.State.Set(ctx, &config)...)
}
