// Copyright (c) Palo Alto Networks, Inc.
// SPDX-License-Identifier: MPL-2.0

package platform

import (
	"context"
	"fmt"
	"strconv"

	"github.com/PaloAltoNetworks/cortex-cloud-go/platform"
	platformTypes "github.com/PaloAltoNetworks/cortex-cloud-go/types/platform"
	platformModels "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/platform"
	providerModels "github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/models/provider"
	"github.com/PaloAltoNetworks/terraform-provider-cortexcloud/internal/util"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ datasource.DataSource = &IndicatorsDataSource{}
)

// NewIndicatorsDataSource is a helper function to simplify the provider implementation.
func NewIndicatorsDataSource() datasource.DataSource {
	return &IndicatorsDataSource{}
}

// IndicatorsDataSource returns a filtered list of IOCs. Filters mirror the
// indicators/get filter shape; pass an empty filters list to return all
// indicators (subject to the server's response cap).
type IndicatorsDataSource struct {
	client *platform.Client
}

// IndicatorsDataSourceModel is the on-the-wire schema of the list data
// source: a flat input filter list plus a `indicators` output list.
type IndicatorsDataSourceModel struct {
	ID         types.String                          `tfsdk:"id"`
	Filters    []IndicatorsDataSourceFilterModel     `tfsdk:"filters"`
	Indicators []platformModels.IndicatorModel       `tfsdk:"indicators"`
}

// IndicatorsDataSourceFilterModel mirrors a single API filter clause.
// `value` is a string here for schema simplicity; the SDK forwards it as
// the JSON `value` field regardless of operator.
type IndicatorsDataSourceFilterModel struct {
	Field    types.String `tfsdk:"field"`
	Operator types.String `tfsdk:"operator"`
	Value    types.String `tfsdk:"value"`
}

func (d *IndicatorsDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_indicators"
}

func (d *IndicatorsDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	indicatorBlock := schema.NestedAttributeObject{
		Attributes: map[string]schema.Attribute{
			"id":                         schema.StringAttribute{Computed: true},
			"indicator":                  schema.StringAttribute{Computed: true},
			"type":                       schema.StringAttribute{Computed: true},
			"severity":                   schema.StringAttribute{Computed: true},
			"expiration_date":            schema.Int64Attribute{Computed: true},
			"default_expiration_enabled": schema.BoolAttribute{Computed: true},
			"comment":                    schema.StringAttribute{Computed: true},
			"reputation":                 schema.StringAttribute{Computed: true},
			"reliability":                schema.StringAttribute{Computed: true},
			"rule_id":                    schema.Int64Attribute{Computed: true},
			"creation_time":              schema.Int64Attribute{Computed: true},
			"modification_time":          schema.Int64Attribute{Computed: true},
			"status":                     schema.StringAttribute{Computed: true},
			"source":                     schema.StringAttribute{Computed: true},
			"number_of_issues":           schema.Int64Attribute{Computed: true},
		},
	}

	resp.Schema = schema.Schema{
		Description: "Lists Indicators of Compromise (IOCs) matching an optional filter set.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "Synthetic identifier (constant `indicators`).",
				Computed:    true,
			},
			"filters": schema.ListNestedAttribute{
				Description: "Optional filter clauses. Omit for an unfiltered listing.",
				Optional:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"field": schema.StringAttribute{
							Required:    true,
							Description: "Filter field (e.g. `indicator`, `type`, `severity`).",
							Validators:  []validator.String{stringvalidator.LengthAtLeast(1)},
						},
						"operator": schema.StringAttribute{
							Required:    true,
							Description: "Filter operator (`EQ`, `NEQ`, `IN`, `GTE`, `LTE`).",
							Validators: []validator.String{
								stringvalidator.OneOf("EQ", "NEQ", "IN", "GTE", "LTE"),
							},
						},
						"value": schema.StringAttribute{
							Required:    true,
							Description: "Filter value, serialized as the API `value` field.",
						},
					},
				},
			},
			"indicators": schema.ListNestedAttribute{
				Description:  "The IOCs returned by the API.",
				Computed:     true,
				NestedObject: indicatorBlock,
			},
		},
	}
}

func (d *IndicatorsDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	clients, ok := req.ProviderData.(*providerModels.CortexCloudSDKClients)
	if !ok {
		util.AddUnexpectedDataSourceConfigurationTypeError(&resp.Diagnostics, "*providerModels.CortexCloudSDKClients", req.ProviderData)
		return
	}
	d.client = clients.Platform
}

func (d *IndicatorsDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	defer util.PanicHandler(&resp.Diagnostics)

	var config IndicatorsDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	filters := make([]platformTypes.IndicatorFilter, 0, len(config.Filters))
	for i, f := range config.Filters {
		field := f.Field.ValueString()
		raw := f.Value.ValueString()
		// Coerce the Terraform string into the JSON type the API expects
		// per field. Verified live: sending a string for the boolean field
		// returns HTTP 500 ("The value type of the field
		// 'default_expiration_enabled' have to be boolean. Got: 'true'").
		// rule_id is undocumented in the field enum but live API accepts
		// it on EQ — surface a clean error if the value isn't numeric.
		var value any = raw
		switch field {
		case "expiration_date", "rule_id":
			n, parseErr := strconv.ParseInt(raw, 10, 64)
			if parseErr != nil {
				resp.Diagnostics.AddAttributeError(
					path.Root("filters").AtListIndex(i).AtName("value"),
					"Invalid Numeric Filter Value",
					fmt.Sprintf("filter[%d].value=%q is not a valid integer; required for field %q", i, raw, field),
				)
				return
			}
			value = n
		case "default_expiration_enabled":
			b, parseErr := strconv.ParseBool(raw)
			if parseErr != nil {
				resp.Diagnostics.AddAttributeError(
					path.Root("filters").AtListIndex(i).AtName("value"),
					"Invalid Boolean Filter Value",
					fmt.Sprintf("filter[%d].value=%q is not a valid boolean; required for field %q", i, raw, field),
				)
				return
			}
			value = b
		}
		filters = append(filters, platformTypes.IndicatorFilter{
			Field:    field,
			Operator: f.Operator.ValueString(),
			Value:    value,
		})
	}

	listResp, err := d.client.ListIndicators(ctx, platformTypes.ListIndicatorsRequest{
		Filters:      filters,
		ExtendedView: true,
	})
	if err != nil {
		resp.Diagnostics.AddError("Error Listing Indicators", err.Error())
		return
	}

	result := make([]platformModels.IndicatorModel, 0, len(listResp.Objects))
	for i := range listResp.Objects {
		var m platformModels.IndicatorModel
		m.RefreshFromRemote(ctx, &resp.Diagnostics, &listResp.Objects[i])
		if resp.Diagnostics.HasError() {
			return
		}
		result = append(result, m)
	}

	config.ID = types.StringValue("indicators")
	config.Indicators = result

	resp.Diagnostics.Append(resp.State.Set(ctx, &config)...)
}
